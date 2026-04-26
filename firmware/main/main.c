/*
 * GuardNet — ESP32-S3 TinyML Network IDS
 * Main entry point: initializes WiFi AP+STA, NAT, packet inspection,
 * ML-based IDS, firewall, and web dashboard.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "mdns.h"

#include "wifi_manager.h"
#include "ids_engine.h"
#include "firewall.h"
#include "web_server.h"

#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "lwip/pbuf.h"
#include "lwip/err.h"
#include "nvs.h"

static const char *TAG = "guardnet";

static bool s_ids_enabled = true;
static bool s_block_enabled = false;  // default: monitor-only (log but don't block)

bool guardnet_ids_enabled(void) { return s_ids_enabled; }
void guardnet_ids_set_enabled(bool en) { s_ids_enabled = en; ESP_LOGI(TAG, "IDS %s", en ? "ENABLED" : "DISABLED"); }
bool guardnet_block_enabled(void) { return s_block_enabled; }
void guardnet_block_set_enabled(bool en) { s_block_enabled = en; ESP_LOGI(TAG, "Blocking %s", en ? "ENABLED" : "DISABLED (monitor-only)"); }

// ─── Runtime confidence threshold ────────────────────────────
#define CONF_NVS_NS   "guardnet"
#define CONF_NVS_KEY  "conf_thresh"
#define CONF_DEFAULT  0.80f  // calibrated: clean at 0.80, false positives appear at 0.70
#define CONF_MIN      0.50f
#define CONF_MAX      0.95f

static float s_conf_threshold = CONF_DEFAULT;

float guardnet_conf_threshold_get(void) { return s_conf_threshold; }

void guardnet_conf_threshold_set(float v)
{
    if (v < CONF_MIN) v = CONF_MIN;
    if (v > CONF_MAX) v = CONF_MAX;
    s_conf_threshold = v;

    nvs_handle_t h;
    if (nvs_open(CONF_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_blob(h, CONF_NVS_KEY, &v, sizeof(v));
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGI(TAG, "Confidence threshold=%.2f", v);
}

static void conf_threshold_load(void)
{
    nvs_handle_t h;
    if (nvs_open(CONF_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        float v = CONF_DEFAULT;
        size_t sz = sizeof(v);
        if (nvs_get_blob(h, CONF_NVS_KEY, &v, &sz) == ESP_OK
            && sz == sizeof(v) && v >= CONF_MIN && v <= CONF_MAX) {
            s_conf_threshold = v;
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "Confidence threshold loaded: %.2f", s_conf_threshold);
}

// AP subnet: 192.168.4.0/24
#define AP_SUBNET     0x0004A8C0  // 192.168.4.0 in little-endian
#define AP_SUBNET_MASK 0x00FFFFFF

static bool is_ap_client(uint32_t ip)
{
    return (ip & AP_SUBNET_MASK) == AP_SUBNET;
}

// ─── Seen AP clients (discovered via packet inspection) ──────
#define MAX_SEEN_CLIENTS 16
#define SEEN_TIMEOUT_US (300 * 1000000LL)  // 5 min expiry

typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
    int64_t  last_seen;
} seen_client_t;

static seen_client_t s_seen_clients[MAX_SEEN_CLIENTS];

static void record_seen_client(uint32_t ip, const uint8_t *mac)
{
    if (!is_ap_client(ip) || ip == AP_SUBNET + 1) return;  // skip gateway

    int64_t now = esp_timer_get_time();
    int free_idx = -1;
    int oldest_idx = 0;
    int64_t oldest = INT64_MAX;

    for (int i = 0; i < MAX_SEEN_CLIENTS; i++) {
        if (s_seen_clients[i].ip == ip) {
            s_seen_clients[i].last_seen = now;
            if (mac) memcpy(s_seen_clients[i].mac, mac, 6);
            return;
        }
        if (s_seen_clients[i].ip == 0 && free_idx < 0) free_idx = i;
        if (s_seen_clients[i].last_seen < oldest) {
            oldest = s_seen_clients[i].last_seen;
            oldest_idx = i;
        }
    }

    int idx = (free_idx >= 0) ? free_idx : oldest_idx;
    s_seen_clients[idx].ip = ip;
    if (mac) memcpy(s_seen_clients[idx].mac, mac, 6);
    s_seen_clients[idx].last_seen = now;
}

static void deauth_by_ip(uint32_t ip)
{
    for (int i = 0; i < MAX_SEEN_CLIENTS; i++) {
        if (s_seen_clients[i].ip == ip) {
            uint8_t *mac = s_seen_clients[i].mac;
            if (mac[0] || mac[1] || mac[2]) {  // non-zero MAC
                esp_err_t ret = firewall_disconnect_client(mac);
                if (ret == ESP_OK)
                    ESP_LOGW(TAG, "DEAUTHED " MACSTR, MAC2STR(mac));
                else
                    ESP_LOGW(TAG, "Deauth failed for " MACSTR " err=%d", MAC2STR(mac), ret);
            }
            return;
        }
    }
}

// Exported for web_server.c
int guardnet_get_seen_clients(uint32_t *ips, int max)
{
    int64_t now = esp_timer_get_time();
    int count = 0;
    for (int i = 0; i < MAX_SEEN_CLIENTS && count < max; i++) {
        if (s_seen_clients[i].ip != 0 &&
            (now - s_seen_clients[i].last_seen) < SEEN_TIMEOUT_US) {
            ips[count++] = s_seen_clients[i].ip;
        }
    }
    return count;
}

// ─── Flow tracking ────────────────────────────────────────────
// Simplified flow table for tracking active connections

#define MAX_FLOWS 128
#define FLOW_TIMEOUT_US (120 * 1000000LL)  // 120 seconds
#define INSPECT_EVERY_N_PKTS 5
#define CLASSIFY_MIN_PKTS 3            // min packets to classify on eviction
#define CONFIDENCE_THRESHOLD (s_conf_threshold)

// ─── Port scan / SYN flood heuristic detector ──────────────
#define MAX_IP_TRACKERS 32
#define TRACKER_WINDOW_US (10 * 1000000LL)  // 10-second sliding window
#define PORTSCAN_THRESHOLD 120             // 120+ new flows in 10s = scan (laptop browsing hits ~80)
#define SYNFLOOD_THRESHOLD 200             // 200+ SYNs in 10s = flood (laptop TCP hits ~100)

#define CONNECT_GRACE_US (30 * 1000000LL)  // 30s grace on first appearance — suppresses reconnect burst

typedef struct {
    uint32_t ip;
    uint32_t last_dst_ip;   // most recent destination (for alert target field)
    int64_t  window_start;
    int64_t  grace_until;   // heuristics suppressed until this time
    uint16_t new_flows;
    uint16_t syn_count;
    bool     scan_alerted;
    bool     flood_alerted;
} ip_tracker_t;

static ip_tracker_t s_ip_trackers[MAX_IP_TRACKERS];

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    bool     active;

    // Accumulated features
    int64_t  start_time;
    int64_t  last_time;
    uint32_t fwd_packets;
    uint32_t bwd_packets;
    uint32_t fwd_bytes;
    uint32_t bwd_bytes;
    float    fwd_pkt_len_max;
    float    fwd_pkt_len_sum;
    float    fwd_pkt_len_sq_sum;
    float    bwd_pkt_len_max;
    float    bwd_pkt_len_sum;
    float    bwd_pkt_len_sq_sum;
    int64_t  last_fwd_time;
    int64_t  last_bwd_time;
    float    fwd_iat_sum;
    float    bwd_iat_sum;
    float    flow_iat_sum;
    float    flow_iat_sq_sum;
    float    flow_iat_max;
    float    flow_iat_min;
    int64_t  prev_pkt_time;
    uint32_t fwd_iat_count;
    uint32_t bwd_iat_count;
    uint32_t flow_iat_count;
    uint16_t syn_count;
    uint16_t rst_count;
    uint16_t ack_count;
    uint16_t psh_count;
    uint16_t init_win_fwd;
    uint16_t init_win_bwd;
    bool     init_win_fwd_set;
    bool     init_win_bwd_set;
    uint32_t total_pkts;
} flow_entry_t;

static flow_entry_t s_flows[MAX_FLOWS];

static void classify_and_evict(flow_entry_t *f);  // forward decl

static flow_entry_t *find_or_create_flow(uint32_t src_ip, uint32_t dst_ip,
                                         uint16_t src_port, uint16_t dst_port,
                                         uint8_t proto)
{
    int64_t now = esp_timer_get_time();
    int free_idx = -1;
    int oldest_idx = 0;
    int64_t oldest_time = INT64_MAX;

    for (int i = 0; i < MAX_FLOWS; i++) {
        flow_entry_t *f = &s_flows[i];

        // Match existing flow (bidirectional)
        if (f->active) {
            if ((f->src_ip == src_ip && f->dst_ip == dst_ip &&
                 f->src_port == src_port && f->dst_port == dst_port &&
                 f->protocol == proto) ||
                (f->src_ip == dst_ip && f->dst_ip == src_ip &&
                 f->src_port == dst_port && f->dst_port == src_port &&
                 f->protocol == proto)) {
                return f;
            }
            // Check timeout — just mark inactive, don't run inference here.
            // classify_and_evict runs in the 30s main-loop sweep (app_main task)
            // so we never block the lwIP task with NN inference during eviction.
            if (now - f->last_time > FLOW_TIMEOUT_US) {
                f->active = false;
                if (free_idx < 0) free_idx = i;
            } else if (f->last_time < oldest_time) {
                oldest_time = f->last_time;
                oldest_idx = i;
            }
        } else {
            if (free_idx < 0) free_idx = i;
        }
    }

    // Create new flow
    int idx = (free_idx >= 0) ? free_idx : oldest_idx;
    flow_entry_t *f = &s_flows[idx];
    // Don't classify oldest active flow here — would run inference in lwIP task
    if (f->active) f->active = false;
    memset(f, 0, sizeof(*f));
    f->active = true;
    f->src_ip = src_ip;
    f->dst_ip = dst_ip;
    f->src_port = src_port;
    f->dst_port = dst_port;
    f->protocol = proto;
    f->start_time = now;
    f->last_time = now;
    f->prev_pkt_time = now;
    f->flow_iat_min = 1e12f;
    return f;
}

static void build_features(flow_entry_t *f, flow_features_t *feat)
{
    int64_t duration = f->last_time - f->start_time;
    float dur_sec = duration / 1e6f;
    if (dur_sec < 1e-6f) dur_sec = 1e-6f;

    uint32_t total_pkts = f->fwd_packets + f->bwd_packets;
    uint32_t total_bytes = f->fwd_bytes + f->bwd_bytes;

    feat->dest_port = (float)f->dst_port;
    feat->flow_duration = (float)duration;
    feat->total_fwd_packets = (float)f->fwd_packets;
    feat->total_bwd_packets = (float)f->bwd_packets;
    feat->total_len_fwd = (float)f->fwd_bytes;
    feat->total_len_bwd = (float)f->bwd_bytes;
    feat->fwd_pkt_len_max = f->fwd_pkt_len_max;

    float fwd_mean = f->fwd_packets > 0 ? f->fwd_pkt_len_sum / f->fwd_packets : 0;
    feat->fwd_pkt_len_mean = fwd_mean;
    feat->fwd_pkt_len_std = f->fwd_packets > 1
        ? sqrtf(fmaxf(0.0f, (f->fwd_pkt_len_sq_sum / f->fwd_packets) - fwd_mean * fwd_mean)) : 0;

    feat->bwd_pkt_len_max = f->bwd_pkt_len_max;
    float bwd_mean = f->bwd_packets > 0 ? f->bwd_pkt_len_sum / f->bwd_packets : 0;
    feat->bwd_pkt_len_mean = bwd_mean;
    feat->bwd_pkt_len_std = f->bwd_packets > 1
        ? sqrtf(fmaxf(0.0f, (f->bwd_pkt_len_sq_sum / f->bwd_packets) - bwd_mean * bwd_mean)) : 0;

    feat->flow_bytes_per_s = total_bytes / dur_sec;
    feat->flow_pkts_per_s = total_pkts / dur_sec;

    feat->flow_iat_mean = f->flow_iat_count > 0 ? f->flow_iat_sum / f->flow_iat_count : 0;
    float iat_mean = feat->flow_iat_mean;
    feat->flow_iat_std = f->flow_iat_count > 1
        ? sqrtf(fmaxf(0.0f, (f->flow_iat_sq_sum / f->flow_iat_count) - iat_mean * iat_mean)) : 0;
    feat->flow_iat_max = f->flow_iat_max;
    feat->flow_iat_min = f->flow_iat_min < 1e11f ? f->flow_iat_min : 0;

    feat->fwd_iat_mean = f->fwd_iat_count > 0 ? f->fwd_iat_sum / f->fwd_iat_count : 0;
    feat->bwd_iat_mean = f->bwd_iat_count > 0 ? f->bwd_iat_sum / f->bwd_iat_count : 0;

    feat->fwd_psh_flags = (float)f->psh_count;
    feat->syn_flag_count = (float)f->syn_count;
    feat->rst_flag_count = (float)f->rst_count;
    feat->ack_flag_count = (float)f->ack_count;

    feat->down_up_ratio = f->fwd_packets > 0
        ? (float)f->bwd_packets / (float)f->fwd_packets : 0;
    feat->avg_pkt_size = total_pkts > 0 ? (float)total_bytes / total_pkts : 0;
    feat->avg_fwd_seg_size = fwd_mean;
    feat->avg_bwd_seg_size = bwd_mean;
    feat->init_win_fwd = (float)f->init_win_fwd;
    feat->init_win_bwd = (float)f->init_win_bwd;
}

// ─── Classify flow before eviction (catches short-lived attacks) ──

static void classify_and_evict(flow_entry_t *f)
{
    if (!s_ids_enabled || f->total_pkts < CLASSIFY_MIN_PKTS) return;
    if (is_ap_client(f->src_ip) && !is_ap_client(f->dst_ip)) return;  // skip internal→external

    flow_features_t features;
    build_features(f, &features);
    ids_result_t result = ids_classify(&features);

    bool internal = is_ap_client(f->src_ip);
    if (result.category != CAT_NORMAL && result.confidence > CONFIDENCE_THRESHOLD) {
        ESP_LOGW(TAG, "EVICT-DETECT: %s (%.0f%%) %u.%u.%u.%u",
                 result.label, result.confidence * 100,
                 (unsigned)(f->src_ip & 0xFF), (unsigned)((f->src_ip >> 8) & 0xFF),
                 (unsigned)((f->src_ip >> 16) & 0xFF), (unsigned)((f->src_ip >> 24) & 0xFF));
        firewall_log_alert(f->src_ip, f->dst_ip, result.category,
                          result.confidence, internal, (const float *)&features);
        if (s_block_enabled) {
            if (firewall_block_ip(f->src_ip, result.category))
                deauth_by_ip(f->src_ip);
        }
    }
}

// ─── IP behavior tracking (heuristic detectors) ────────────

static ip_tracker_t *get_ip_tracker(uint32_t ip)
{
    int64_t now = esp_timer_get_time();
    int free_idx = -1;
    int oldest_idx = 0;
    int64_t oldest = INT64_MAX;

    for (int i = 0; i < MAX_IP_TRACKERS; i++) {
        if (s_ip_trackers[i].ip == ip) {
            if (now - s_ip_trackers[i].window_start > TRACKER_WINDOW_US) {
                s_ip_trackers[i].window_start = now;
                s_ip_trackers[i].new_flows = 0;
                s_ip_trackers[i].syn_count = 0;
                s_ip_trackers[i].scan_alerted = false;
                s_ip_trackers[i].flood_alerted = false;
            }
            return &s_ip_trackers[i];
        }
        if (s_ip_trackers[i].ip == 0 && free_idx < 0) free_idx = i;
        if (s_ip_trackers[i].window_start < oldest) {
            oldest = s_ip_trackers[i].window_start;
            oldest_idx = i;
        }
    }

    int idx = (free_idx >= 0) ? free_idx : oldest_idx;
    memset(&s_ip_trackers[idx], 0, sizeof(ip_tracker_t));
    s_ip_trackers[idx].ip = ip;
    s_ip_trackers[idx].window_start = now;
    s_ip_trackers[idx].grace_until = now + CONNECT_GRACE_US;  // suppress burst on first appearance
    return &s_ip_trackers[idx];
}

static void check_heuristics(ip_tracker_t *t, uint32_t src_ip)
{
    if (esp_timer_get_time() < t->grace_until) return;  // suppress heuristics during connect burst

    if (!t->scan_alerted && t->new_flows >= PORTSCAN_THRESHOLD) {
        t->scan_alerted = true;
        bool internal = is_ap_client(src_ip);
        ESP_LOGW(TAG, "PORTSCAN: %u new flows/10s from %u.%u.%u.%u%s",
                 t->new_flows,
                 (unsigned)(src_ip & 0xFF), (unsigned)((src_ip >> 8) & 0xFF),
                 (unsigned)((src_ip >> 16) & 0xFF), (unsigned)((src_ip >> 24) & 0xFF),
                 internal ? " [internal, not blocking]" : "");
        firewall_log_alert(src_ip, t->last_dst_ip, CAT_PORTSCAN, 0.95f, internal, NULL);
        if (s_block_enabled && firewall_block_ip(src_ip, CAT_PORTSCAN))
            deauth_by_ip(src_ip);
    }
    if (!t->flood_alerted && t->syn_count >= SYNFLOOD_THRESHOLD) {
        t->flood_alerted = true;
        bool internal = is_ap_client(src_ip);
        ESP_LOGW(TAG, "SYN FLOOD: %u SYNs/10s from %u.%u.%u.%u%s",
                 t->syn_count,
                 (unsigned)(src_ip & 0xFF), (unsigned)((src_ip >> 8) & 0xFF),
                 (unsigned)((src_ip >> 16) & 0xFF), (unsigned)((src_ip >> 24) & 0xFF),
                 internal ? " [internal]" : " [external]");
        firewall_log_alert(src_ip, t->last_dst_ip, CAT_DOS, 0.95f, internal, NULL);
        if (s_block_enabled && firewall_block_ip(src_ip, CAT_DOS))
            deauth_by_ip(src_ip);
    }
}

// ─── Packet inspection hook ─────────────────────────────────

// Self AP gateway IP in host byte order (192.168.4.1 LE = 0x0104A8C0)
#define AP_GW_IP 0x0104A8C0

static void inspect_packet(const struct ip_hdr *iphdr, uint16_t total_len, bool is_input, const uint8_t *src_mac)
{
    uint32_t src_ip = iphdr->src.addr;
    uint32_t dst_ip = iphdr->dest.addr;

    // Drop loopback, self, and unroutable sources immediately — these are
    // ESP32-internal packets leaking into the AP netif hook and would cause
    // false PORTSCAN / SYN-FLOOD heuristic alerts.
    if ((src_ip & 0xFF) == 0x7F ||    // 127.x.x.x loopback
        src_ip == AP_GW_IP    ||       // 192.168.4.1 (self)
        src_ip == 0           ||       // 0.0.0.0
        src_ip == 0xFFFFFFFF)          // 255.255.255.255 broadcast
        return;

    uint8_t proto = IPH_PROTO(iphdr);
    uint16_t src_port = 0, dst_port = 0;
    uint8_t tcp_flags = 0;
    uint16_t win_size = 0;

    uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;
    const uint8_t *transport = ((const uint8_t *)iphdr) + ip_hdr_len;
    uint16_t payload_len = total_len - ip_hdr_len;

    if (proto == IP_PROTO_TCP && payload_len >= 20) {
        const struct tcp_hdr *tcphdr = (const struct tcp_hdr *)transport;
        src_port = ntohs(tcphdr->src);
        dst_port = ntohs(tcphdr->dest);
        tcp_flags = TCPH_FLAGS(tcphdr);
        win_size = ntohs(tcphdr->wnd);
    } else if (proto == IP_PROTO_UDP && payload_len >= 8) {
        const struct udp_hdr *udphdr = (const struct udp_hdr *)transport;
        src_port = ntohs(udphdr->src);
        dst_port = ntohs(udphdr->dest);
    }

    // Track seen AP clients (for dashboard — catches bridged VMs)
    record_seen_client(src_ip, src_mac);

    // Quick check: blocked?
    if (firewall_is_blocked(src_ip)) return;

    // Find/create flow
    flow_entry_t *flow = find_or_create_flow(src_ip, dst_ip, src_port, dst_port, proto);
    int64_t now = esp_timer_get_time();

    // Track per-IP behavior for heuristic detection
    // Skip non-routable/broadcast IPs — DHCP, ARP, multicast cause false positives
    bool skip_heuristic = (src_ip == 0 ||
                           src_ip == 0xFFFFFFFF ||
                           (src_ip & 0xFF) == 0x7F  ||       // 127.x.x.x (belt-and-suspenders)
                           (src_ip & 0xFFFF) == 0xFEA9 ||   // 169.254.x.x link-local
                           (src_ip & 0xF0) == 0xE0);         // 224.x.x.x multicast
    if (!skip_heuristic) {
        bool is_new_flow = (flow->total_pkts == 0);
        ip_tracker_t *tracker = get_ip_tracker(src_ip);
        tracker->last_dst_ip = dst_ip;
        // Only count scanner flows that START with a pure SYN — RST/ACK first packets
        // are responses to evicted flows, not new attack connections, and would falsely
        // flag the victim as a port scanner when the flow table overflows.
        bool is_syn_initiated = (proto == IP_PROTO_TCP && (tcp_flags & 0x02) && !(tcp_flags & 0x10));
        bool is_udp_new = (proto == IP_PROTO_UDP);
        if (is_new_flow && (is_syn_initiated || is_udp_new)) tracker->new_flows++;
        if (proto == IP_PROTO_TCP && (tcp_flags & 0x02) && !(tcp_flags & 0x10)) tracker->syn_count++;
        check_heuristics(tracker, src_ip);
    }

    // Determine direction (forward = same as flow originator)
    bool is_forward = (flow->src_ip == src_ip);

    // Update flow stats
    if (is_forward) {
        flow->fwd_packets++;
        flow->fwd_bytes += total_len;
        float plen = (float)total_len;
        if (plen > flow->fwd_pkt_len_max) flow->fwd_pkt_len_max = plen;
        flow->fwd_pkt_len_sum += plen;
        flow->fwd_pkt_len_sq_sum += plen * plen;

        if (flow->last_fwd_time > 0) {
            float iat = (float)(now - flow->last_fwd_time);
            flow->fwd_iat_sum += iat;
            flow->fwd_iat_count++;
        }
        flow->last_fwd_time = now;

        if (!flow->init_win_fwd_set && proto == IP_PROTO_TCP) {
            flow->init_win_fwd = win_size;
            flow->init_win_fwd_set = true;
        }
    } else {
        flow->bwd_packets++;
        flow->bwd_bytes += total_len;
        float plen = (float)total_len;
        if (plen > flow->bwd_pkt_len_max) flow->bwd_pkt_len_max = plen;
        flow->bwd_pkt_len_sum += plen;
        flow->bwd_pkt_len_sq_sum += plen * plen;

        if (flow->last_bwd_time > 0) {
            float iat = (float)(now - flow->last_bwd_time);
            flow->bwd_iat_sum += iat;
            flow->bwd_iat_count++;
        }
        flow->last_bwd_time = now;

        if (!flow->init_win_bwd_set && proto == IP_PROTO_TCP) {
            flow->init_win_bwd = win_size;
            flow->init_win_bwd_set = true;
        }
    }

    // TCP flags
    if (proto == IP_PROTO_TCP) {
        if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) flow->syn_count++;  // pure SYN only, not SYN-ACK
        if (tcp_flags & 0x04) flow->rst_count++;
        if (tcp_flags & 0x10) flow->ack_count++;
        if (tcp_flags & 0x08) flow->psh_count++;
    }

    // Flow IAT
    if (flow->prev_pkt_time > 0 && flow->prev_pkt_time != now) {
        float iat = (float)(now - flow->prev_pkt_time);
        flow->flow_iat_sum += iat;
        flow->flow_iat_sq_sum += iat * iat;
        if (iat > flow->flow_iat_max) flow->flow_iat_max = iat;
        if (iat < flow->flow_iat_min) flow->flow_iat_min = iat;
        flow->flow_iat_count++;
    }
    flow->prev_pkt_time = now;
    flow->last_time = now;
    flow->total_pkts++;

    // Run IDS every N packets (if enabled)
    // Skip ML only for internal→external traffic: normal laptop/phone browsing produces
    // DDoS-like features in the training dataset. Internal→internal (e.g. Kali→Win7)
    // and external→internal flows both get ML inspection.
    // Always attribute attack to flow->src_ip (initiator), never to the responder.
    bool skip_ml = is_ap_client(flow->src_ip) && !is_ap_client(flow->dst_ip);
    if (s_ids_enabled && !skip_ml &&
        flow->total_pkts % INSPECT_EVERY_N_PKTS == 0 &&
        flow->total_pkts >= INSPECT_EVERY_N_PKTS) {
        flow_features_t features;
        build_features(flow, &features);
        ids_result_t result = ids_classify(&features);

        if (result.category != CAT_NORMAL && result.confidence > CONFIDENCE_THRESHOLD) {
            bool attacker_internal = is_ap_client(flow->src_ip);

            ESP_LOGW(TAG, "ATTACK: %s (%.0f%%) from %u.%u.%u.%u %s",
                     result.label, result.confidence * 100,
                     (unsigned)(flow->src_ip & 0xFF), (unsigned)((flow->src_ip >> 8) & 0xFF),
                     (unsigned)((flow->src_ip >> 16) & 0xFF), (unsigned)((flow->src_ip >> 24) & 0xFF),
                     attacker_internal ? "[INTERNAL]" : "[EXTERNAL]");

            firewall_log_alert(flow->src_ip, flow->dst_ip, result.category,
                             result.confidence, attacker_internal, (const float *)&features);

            if (s_block_enabled) {
                if (firewall_block_ip(flow->src_ip, result.category)) {
                    ESP_LOGW(TAG, "%s attacker %u.%u.%u.%u blocked + deauthed",
                             attacker_internal ? "Internal" : "External",
                             (unsigned)(flow->src_ip & 0xFF), (unsigned)((flow->src_ip >> 8) & 0xFF),
                             (unsigned)((flow->src_ip >> 16) & 0xFF), (unsigned)((flow->src_ip >> 24) & 0xFF));
                    deauth_by_ip(flow->src_ip);
                }
            }

            // Reset flow after enforcement
            flow->active = false;
        }
    }
}

// ─── Network interface hooks ─────────────────────────────────
// We hook into the netif input to inspect packets

static netif_input_fn s_original_ap_input = NULL;
static struct netif *s_ap_lwip_netif = NULL;

// Shared inspection logic for both AP and STA hooks
#define ETH_HDR_LEN 14
#define ETH_TYPE_IP 0x0800

static bool inspect_frame(struct pbuf *p)
{
    if (p->len < ETH_HDR_LEN + sizeof(struct ip_hdr)) return false;

    const uint8_t *frame = (const uint8_t *)p->payload;
    uint16_t eth_type = (frame[12] << 8) | frame[13];
    if (eth_type != ETH_TYPE_IP) return false;

    const struct ip_hdr *iphdr = (const struct ip_hdr *)(frame + ETH_HDR_LEN);
    if (IPH_V(iphdr) != 4) return false;

    const uint8_t *src_mac = frame + 6;  // Ethernet source MAC
    inspect_packet(iphdr, ntohs(IPH_LEN(iphdr)), true, src_mac);

    // Drop if blocked — but never drop DHCP (clients need it to connect)
    if (firewall_is_blocked(iphdr->src.addr)) {
        bool is_dhcp = false;
        if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
            uint16_t ihl = IPH_HL(iphdr) * 4;
            const struct udp_hdr *uh = (const struct udp_hdr *)((const uint8_t *)iphdr + ihl);
            uint16_t dp = ntohs(uh->dest);
            if (dp == 67 || dp == 68) is_dhcp = true;
        }
        if (!is_dhcp) return true;  // signal caller to drop
    }
    return false;
}

static err_t guardnet_ap_hook(struct pbuf *p, struct netif *inp)
{
    if (inspect_frame(p)) {
        pbuf_free(p);
        return ERR_OK;
    }
    return s_original_ap_input(p, inp);
}


static void install_packet_hook(void)
{
    struct netif *nif;

    NETIF_FOREACH(nif) {
        if (nif->name[0] == 'a' && nif->name[1] == 'p') {
            s_ap_lwip_netif = nif;
            s_original_ap_input = nif->input;
            nif->input = guardnet_ap_hook;
            ESP_LOGI(TAG, "Packet hook on AP netif");
            return;
        }
    }

    // Fallback: hook first netif that isn't loopback
    NETIF_FOREACH(nif) {
        if (!(nif->name[0] == 'l' && nif->name[1] == 'o')) {
            s_ap_lwip_netif = nif;
            s_original_ap_input = nif->input;
            nif->input = guardnet_ap_hook;
            ESP_LOGI(TAG, "Packet hook on netif '%c%c'",
                     nif->name[0], nif->name[1]);
            return;
        }
    }
    ESP_LOGW(TAG, "Could not find netif for packet hook!");
}

// ─── mDNS setup ──────────────────────────────────────────────

static void mdns_setup(void)
{
    mdns_init();
    mdns_hostname_set("esp-firewall");
    mdns_instance_name_set("GuardNet IDS");
    mdns_service_add("GuardNet Web", "_http", "_tcp", 80, NULL, 0);
    ESP_LOGI(TAG, "mDNS: http://esp-firewall.local/");
}

// ─── Main ────────────────────────────────────────────────────

void app_main(void)
{
    ESP_LOGI(TAG, "=================================");
    ESP_LOGI(TAG, "  GuardNet — TinyML Network IDS");
    ESP_LOGI(TAG, "  ESP32-S3 | AP+STA+NAT+IDS");
    ESP_LOGI(TAG, "=================================");

    // Init subsystems
    ESP_ERROR_CHECK(wifi_manager_init());
    ESP_ERROR_CHECK(ids_engine_init());
    ESP_ERROR_CHECK(firewall_init());
    conf_threshold_load();

    // Install packet inspection hook
    install_packet_hook();

    // Start services
    mdns_setup();
    ESP_ERROR_CHECK(web_server_start());

    ESP_LOGI(TAG, "GuardNet running! Dashboard: http://esp-firewall.local/");
    ESP_LOGI(TAG, "AP SSID: %s | Password: %s", GUARDNET_AP_SSID, GUARDNET_AP_PASS);

    // Main loop: periodic stats + flow cleanup
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(30000));

        // Auto-unblock expired IPs
        int auto_unblocked = firewall_check_auto_unblock();

        // Classify and evict stale flows (catches attacks that stopped mid-flow)
        int64_t now = esp_timer_get_time();
        int evicted = 0;
        for (int i = 0; i < MAX_FLOWS; i++) {
            if (s_flows[i].active && (now - s_flows[i].last_time > FLOW_TIMEOUT_US)) {
                classify_and_evict(&s_flows[i]);
                s_flows[i].active = false;
                evicted++;
            }
        }

        if (auto_unblocked > 0)
            ESP_LOGI(TAG, "Auto-unblocked %d IP(s)", auto_unblocked);

        ESP_LOGI(TAG, "Status: %d clients | %d blocked | %d attacks | %d flows evicted",
                 wifi_manager_get_client_count(),
                 firewall_get_blocked_count(),
                 firewall_get_total_attacks(),
                 evicted);
    }
}
