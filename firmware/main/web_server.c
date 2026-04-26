#include "web_server.h"
#include "firewall.h"
#include "ids_engine.h"
#include "wifi_manager.h"
#include "model_data.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "nvs.h"
#include "mbedtls/base64.h"
#include <stdio.h>
#include <string.h>

// From main.c
extern bool guardnet_ids_enabled(void);
extern void guardnet_ids_set_enabled(bool en);
extern bool guardnet_block_enabled(void);
extern void guardnet_block_set_enabled(bool en);
extern int guardnet_get_seen_clients(uint32_t *ips, int max);
extern float guardnet_conf_threshold_get(void);
extern void guardnet_conf_threshold_set(float v);

static const char *TAG = "web_srv";

// ─── Embedded frontend files ────────────────────────────────
extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
extern const uint8_t style_css_start[]  asm("_binary_style_css_start");
extern const uint8_t style_css_end[]    asm("_binary_style_css_end");
extern const uint8_t app_js_start[]     asm("_binary_app_js_start");
extern const uint8_t app_js_end[]       asm("_binary_app_js_end");

// ─── Dashboard Authentication ───────────────────────────────
#define NVS_AUTH_NAMESPACE "guardnet"
#define NVS_AUTH_KEY       "dash_pass"
#define DEFAULT_PASS       "admin"
#define MAX_PASS_LEN       32

static char s_dash_pass[MAX_PASS_LEN + 1] = DEFAULT_PASS;

static void load_dashboard_pass(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_AUTH_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(s_dash_pass);
        if (nvs_get_str(h, NVS_AUTH_KEY, s_dash_pass, &len) != ESP_OK) {
            strncpy(s_dash_pass, DEFAULT_PASS, MAX_PASS_LEN);
        }
        nvs_close(h);
    }
}

static esp_err_t save_dashboard_pass(const char *pass)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_AUTH_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    nvs_set_str(h, NVS_AUTH_KEY, pass);
    nvs_commit(h);
    nvs_close(h);
    strncpy(s_dash_pass, pass, MAX_PASS_LEN);
    s_dash_pass[MAX_PASS_LEN] = 0;
    return ESP_OK;
}

static bool check_auth(httpd_req_t *req)
{
    char auth_buf[128];
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_buf, sizeof(auth_buf)) != ESP_OK) {
        return false;
    }
    if (strncmp(auth_buf, "Basic ", 6) != 0) return false;

    unsigned char decoded[80];
    size_t decoded_len = 0;
    if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decoded_len,
                               (const unsigned char *)auth_buf + 6,
                               strlen(auth_buf + 6)) != 0) {
        return false;
    }
    decoded[decoded_len] = 0;

    char *colon = strchr((char *)decoded, ':');
    if (!colon) return false;
    if (colon - (char *)decoded != 5 || strncmp((char *)decoded, "admin", 5) != 0) return false;

    return strcmp(colon + 1, s_dash_pass) == 0;
}

static esp_err_t send_auth_required(httpd_req_t *req)
{
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"error\":\"unauthorized\"}");
    return ESP_OK;
}

// ─── Helpers ────────────────────────────────────────────────

// Escape " and \ in a string for JSON embedding. out must be 2× len of src.
static void json_escape(const char *src, char *out, int out_len)
{
    int j = 0;
    for (int i = 0; src[i] && j < out_len - 2; i++) {
        if (src[i] == '"' || src[i] == '\\') {
            if (j < out_len - 3) out[j++] = '\\';
            else break;
        }
        out[j++] = src[i];
    }
    out[j] = 0;
}

static void ip_to_str(uint32_t ip, char *buf, int len)
{
    snprintf(buf, len, "%u.%u.%u.%u",
             (unsigned)(ip & 0xFF), (unsigned)((ip >> 8) & 0xFF),
             (unsigned)((ip >> 16) & 0xFF), (unsigned)((ip >> 24) & 0xFF));
}

static bool get_ip_for_mac(const uint8_t *mac, char *ip_buf, int buf_len)
{
    esp_netif_pair_mac_ip_t pair;
    memcpy(pair.mac, mac, 6);
    pair.ip.addr = 0;
    if (esp_netif_dhcps_get_clients_by_mac(wifi_manager_get_ap_netif(), 1, &pair) == ESP_OK
        && pair.ip.addr != 0) {
        ip_to_str(pair.ip.addr, ip_buf, buf_len);
        return true;
    }
    return false;
}

// ─── Static file handlers (no auth — needed to serve login page) ─

static esp_err_t handler_index(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)index_html_start,
                    index_html_end - index_html_start);
    return ESP_OK;
}

static esp_err_t handler_css(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/css");
    httpd_resp_send(req, (const char *)style_css_start,
                    style_css_end - style_css_start);
    return ESP_OK;
}

static esp_err_t handler_js(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/javascript");
    httpd_resp_send(req, (const char *)app_js_start,
                    app_js_end - app_js_start);
    return ESP_OK;
}

// ─── Auth API ───────────────────────────────────────────────

static esp_err_t handler_auth_check(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t handler_auth_change(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) goto bad;
    buf[len] = 0;

    char *p;

    p = strstr(buf, "\"old\"");
    if (!p) goto bad;
    p = strchr(p + 5, '"');
    if (!p) goto bad;
    char *old_start = ++p;
    char *old_end = strchr(old_start, '"');
    if (!old_end) goto bad;
    *old_end = 0;

    p = strstr(old_end + 1, "\"new\"");
    if (!p) goto bad;
    p = strchr(p + 5, '"');
    if (!p) goto bad;
    char *new_start = ++p;
    char *new_end = strchr(new_start, '"');
    if (!new_end) goto bad;
    *new_end = 0;

    if (strcmp(old_start, s_dash_pass) != 0) {
        httpd_resp_set_status(req, "403 Forbidden");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Wrong current password\"}");
        return ESP_OK;
    }

    {
        size_t new_len = strlen(new_start);
        if (new_len < 4 || new_len > MAX_PASS_LEN) {
            httpd_resp_set_status(req, "400 Bad Request");
            httpd_resp_set_type(req, "application/json");
            httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Password must be 4-32 characters\"}");
            return ESP_OK;
        }
    }

    save_dashboard_pass(new_start);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;

bad:
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Invalid request\"}");
    return ESP_OK;
}

// ─── API handlers (all require auth) ────────────────────────

static esp_err_t handler_status(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[384];
    long long uptime = (long long)(esp_timer_get_time() / 1000000);

    // Count clients: WiFi associations + any seen-only IPs from packet inspection
    uint32_t seen[16];
    int seen_count = guardnet_get_seen_clients(seen, 16);
    int total_clients = seen_count > wifi_manager_get_client_count()
                        ? seen_count : wifi_manager_get_client_count();

    snprintf(buf, sizeof(buf),
        "{\"uptime\":%lld,\"clients\":%d,\"blocked\":%d,"
        "\"total_attacks\":%d,\"sta_connected\":%s,"
        "\"ids_enabled\":%s,\"block_enabled\":%s,"
        "\"conf_threshold\":%.2f,"
        "\"avg_inference_us\":%.1f,\"quantized\":true,"
        "\"block_timeout\":%d}",
        uptime,
        total_clients,
        firewall_get_blocked_count(),
        firewall_get_total_attacks(),
        wifi_manager_sta_connected() ? "true" : "false",
        guardnet_ids_enabled() ? "true" : "false",
        guardnet_block_enabled() ? "true" : "false",
        guardnet_conf_threshold_get(),
        ids_get_avg_inference_us(),
        firewall_get_block_timeout());

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, strlen(buf));
    return ESP_OK;
}

static esp_err_t handler_alerts(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    const alert_entry_t *alerts = firewall_get_alert_log();
    int count = firewall_get_alert_count();
    int head  = firewall_get_alert_head();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "[");

    char src[20], dst[20];
    for (int i = 0; i < count; i++) {
        // Iterate oldest→newest so JS .reverse() gives newest-first display
        int idx = (head - count + i + MAX_ALERT_LOG) % MAX_ALERT_LOG;
        ip_to_str(alerts[idx].src_ip, src, sizeof(src));
        ip_to_str(alerts[idx].dst_ip, dst, sizeof(dst));

        // Header chunk
        char hdr[192];
        snprintf(hdr, sizeof(hdr),
            "%s{\"src\":\"%s\",\"dst\":\"%s\",\"cat\":\"%s\","
            "\"conf\":%.2f,\"time\":%lld,\"internal\":%s,\"features\":[",
            i > 0 ? "," : "", src, dst,
            CATEGORY_NAMES[alerts[idx].category],
            alerts[idx].confidence,
            (long long)alerts[idx].timestamp,
            alerts[idx].from_internal ? "true" : "false");
        httpd_resp_sendstr_chunk(req, hdr);

        // Features chunk (30 floats × up to 20 chars each)
        char feat_buf[720]; int fp = 0;
        for (int fi = 0; fi < ALERT_NUM_FEATURES; fi++) {
            fp += snprintf(feat_buf + fp, sizeof(feat_buf) - fp,
                           "%s%.6f", fi > 0 ? "," : "", alerts[idx].features[fi]);
        }
        feat_buf[fp] = 0;
        httpd_resp_sendstr_chunk(req, feat_buf);
        httpd_resp_sendstr_chunk(req, "]}");
    }

    httpd_resp_sendstr_chunk(req, "]");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t handler_blocked(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    const blocked_entry_t *list = firewall_get_blocked_list();
    int count = firewall_get_blocked_count();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "[");

    char buf[160];
    char ip_str[20];
    int64_t now_us = esp_timer_get_time();
    for (int i = 0; i < count; i++) {
        ip_to_str(list[i].ip, ip_str, sizeof(ip_str));
        int remaining = -1;  // -1 = permanent
        if (list[i].unblock_at > 0) {
            int64_t rem_us = list[i].unblock_at - now_us;
            remaining = rem_us > 0 ? (int)(rem_us / 1000000) : 0;
        }
        snprintf(buf, sizeof(buf),
                 "%s{\"ip\":\"%s\",\"reason\":\"%s\",\"time\":%lld,\"remaining\":%d}",
                 i > 0 ? "," : "",
                 ip_str, CATEGORY_NAMES[list[i].reason],
                 (long long)list[i].timestamp, remaining);
        httpd_resp_sendstr_chunk(req, buf);
    }

    httpd_resp_sendstr_chunk(req, "]");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t handler_clients(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    wifi_sta_list_t sta_list;
    esp_wifi_ap_get_sta_list(&sta_list);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "[");

    int entry_idx = 0;
    char buf[192];

    // 1) WiFi-associated clients (have RSSI)
    for (int i = 0; i < sta_list.num; i++) {
        char ip_str[20];
        if (!get_ip_for_mac(sta_list.sta[i].mac, ip_str, sizeof(ip_str))) {
            uint32_t ip_val;
            if (wifi_manager_get_client_ip(sta_list.sta[i].mac, &ip_val)) {
                ip_to_str(ip_val, ip_str, sizeof(ip_str));
            } else {
                strncpy(ip_str, "pending", sizeof(ip_str));
            }
        }
        snprintf(buf, sizeof(buf),
                 "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ip\":\"%s\",\"rssi\":%d}",
                 entry_idx > 0 ? "," : "",
                 sta_list.sta[i].mac[0], sta_list.sta[i].mac[1],
                 sta_list.sta[i].mac[2], sta_list.sta[i].mac[3],
                 sta_list.sta[i].mac[4], sta_list.sta[i].mac[5],
                 ip_str,
                 sta_list.sta[i].rssi);
        httpd_resp_sendstr_chunk(req, buf);
        entry_idx++;
    }

    // 2) DHCP-only clients (VMs with bridged adapters — no own WiFi association)
    uint8_t dhcp_macs[8][6];
    uint32_t dhcp_ips[8];
    int dhcp_count = wifi_manager_get_dhcp_clients(dhcp_macs, dhcp_ips, 8);

    for (int d = 0; d < dhcp_count; d++) {
        // Skip if already listed as WiFi client
        bool already_listed = false;
        for (int w = 0; w < sta_list.num; w++) {
            if (memcmp(sta_list.sta[w].mac, dhcp_macs[d], 6) == 0) {
                already_listed = true;
                break;
            }
        }
        if (already_listed) continue;

        char ip_str[20];
        ip_to_str(dhcp_ips[d], ip_str, sizeof(ip_str));
        snprintf(buf, sizeof(buf),
                 "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ip\":\"%s\",\"rssi\":0,\"bridged\":true}",
                 entry_idx > 0 ? "," : "",
                 dhcp_macs[d][0], dhcp_macs[d][1], dhcp_macs[d][2],
                 dhcp_macs[d][3], dhcp_macs[d][4], dhcp_macs[d][5],
                 ip_str);
        httpd_resp_sendstr_chunk(req, buf);
        entry_idx++;
    }

    // 3) Seen-only clients (discovered via packet inspection — bridged VMs)
    uint32_t seen_ips[16];
    int seen_count = guardnet_get_seen_clients(seen_ips, 16);

    for (int s = 0; s < seen_count; s++) {
        // Skip if already listed by WiFi or DHCP
        bool already = false;
        // Check against WiFi clients' IPs (via DHCP lookup only — skip "pending")
        for (int w = 0; w < sta_list.num && !already; w++) {
            uint32_t wip_val = 0;
            if (wifi_manager_get_client_ip(sta_list.sta[w].mac, &wip_val)) {
                if (wip_val == seen_ips[s]) already = true;
            }
        }
        // Check against DHCP clients
        for (int d = 0; d < dhcp_count && !already; d++) {
            if (dhcp_ips[d] == seen_ips[s]) already = true;
        }
        if (already) continue;

        char ip_str[20];
        ip_to_str(seen_ips[s], ip_str, sizeof(ip_str));
        snprintf(buf, sizeof(buf),
                 "%s{\"mac\":\"--:--:--:--:--:--\",\"ip\":\"%s\",\"rssi\":0,\"bridged\":true}",
                 entry_idx > 0 ? "," : "", ip_str);
        httpd_resp_sendstr_chunk(req, buf);
        entry_idx++;
    }

    httpd_resp_sendstr_chunk(req, "]");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t handler_block_ip(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) goto bad;
    buf[len] = 0;

    {
        char *start = strchr(buf, ':');
        if (!start) goto bad;
        start = strchr(start, '"');
        if (!start) goto bad;
        start++;
        char *end = strchr(start, '"');
        if (!end) goto bad;
        *end = 0;

        uint8_t a, b, c, d;
        if (sscanf(start, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) goto bad;
        uint32_t ip = a | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24);
        firewall_block_ip(ip, CAT_NORMAL);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":true}");
        return ESP_OK;
    }
bad:
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Invalid request\"}");
    return ESP_OK;
}

static esp_err_t handler_unblock_ip(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) goto bad;
    buf[len] = 0;

    {
        char *start = strchr(buf, ':');
        if (!start) goto bad;
        start = strchr(start, '"');
        if (!start) goto bad;
        start++;
        char *end = strchr(start, '"');
        if (!end) goto bad;
        *end = 0;

        uint8_t a, b, c, d;
        if (sscanf(start, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) goto bad;
        uint32_t ip = a | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24);
        firewall_unblock_ip(ip);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":true}");
        return ESP_OK;
    }
bad:
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Invalid request\"}");
    return ESP_OK;
}

static esp_err_t handler_disconnect(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) goto bad;
    buf[len] = 0;

    {
        char *start = strchr(buf, ':');
        if (!start) goto bad;
        start = strchr(start, '"');
        if (!start) goto bad;
        start++;
        char *end = strchr(start, '"');
        if (!end) goto bad;
        *end = 0;

        uint8_t mac[6];
        if (sscanf(start, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) goto bad;
        firewall_disconnect_client(mac);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":true}");
        return ESP_OK;
    }
bad:
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Invalid request\"}");
    return ESP_OK;
}

static esp_err_t handler_wifi_status(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    const char *ssid = wifi_manager_get_sta_ssid();
    char ssid_esc[70];
    json_escape(ssid, ssid_esc, sizeof(ssid_esc));

    char buf[160];
    snprintf(buf, sizeof(buf),
        "{\"configured\":%s,\"ssid\":\"%s\",\"connected\":%s}",
        strlen(ssid) > 0 ? "true" : "false",
        ssid_esc,
        wifi_manager_sta_connected() ? "true" : "false");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, strlen(buf));
    return ESP_OK;
}

static esp_err_t handler_wifi_scan(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    scan_ap_t results[MAX_SCAN_APS];
    int count = wifi_manager_scan(results, MAX_SCAN_APS);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "[");

    char buf[160];
    for (int i = 0; i < count; i++) {
        char ssid_esc[70];
        json_escape(results[i].ssid, ssid_esc, sizeof(ssid_esc));
        snprintf(buf, sizeof(buf), "%s{\"ssid\":\"%s\",\"rssi\":%d,\"secure\":%s}",
                 i > 0 ? "," : "",
                 ssid_esc, results[i].rssi,
                 results[i].secure ? "true" : "false");
        httpd_resp_sendstr_chunk(req, buf);
    }

    httpd_resp_sendstr_chunk(req, "]");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t handler_wifi_connect(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[160];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return ESP_FAIL;
    buf[len] = 0;

    char *ssid_key = strstr(buf, "\"ssid\"");
    if (!ssid_key) return ESP_FAIL;
    char *ssid_start = strchr(ssid_key + 6, '"');
    if (!ssid_start) return ESP_FAIL;
    ssid_start++;
    char *ssid_end = strchr(ssid_start, '"');
    if (!ssid_end) return ESP_FAIL;
    *ssid_end = 0;

    char *pass_val = "";
    char *pass_key = strstr(ssid_end + 1, "\"pass\"");
    if (pass_key) {
        char *pass_start = strchr(pass_key + 6, '"');
        if (pass_start) {
            pass_start++;
            char *pass_end = strchr(pass_start, '"');
            if (pass_end) {
                *pass_end = 0;
                pass_val = pass_start;
            }
        }
    }

    esp_err_t err = wifi_manager_set_sta(ssid_start, pass_val);
    if (err == ESP_OK) {
        httpd_resp_sendstr(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false}");
    }
    return ESP_OK;
}

static esp_err_t handler_wifi_retry(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);
    esp_err_t err = wifi_manager_retry_sta();
    if (err == ESP_ERR_INVALID_STATE) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"No credentials saved\"}");
    } else {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":true}");
    }
    return ESP_OK;
}

static esp_err_t handler_wifi_forget(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    wifi_manager_forget_sta();
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

// ─── IDS toggle ────────────────────────────────────────────

static esp_err_t handler_ids_toggle(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[64];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
        return ESP_OK;
    }
    buf[ret] = 0;

    bool enable = (strstr(buf, "true") != NULL);
    guardnet_ids_set_enabled(enable);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, enable ? "{\"ids_enabled\":true}" : "{\"ids_enabled\":false}");
    return ESP_OK;
}

// ─── Block toggle ──────────────────────────────────────────

static esp_err_t handler_block_toggle(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[64];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
        return ESP_OK;
    }
    buf[ret] = 0;

    bool enable = (strstr(buf, "true") != NULL);
    guardnet_block_set_enabled(enable);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, enable ? "{\"block_enabled\":true}" : "{\"block_enabled\":false}");
    return ESP_OK;
}

// ─── Timeline ──────────────────────────────────────────────

static esp_err_t handler_timeline(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);
    int32_t counts[TIMELINE_BUCKETS];
    firewall_get_timeline(counts);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "[");
    char buf[16];
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        snprintf(buf, sizeof(buf), "%s%ld", i > 0 ? "," : "", (long)counts[i]);
        httpd_resp_sendstr_chunk(req, buf);
    }
    httpd_resp_sendstr_chunk(req, "]");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

// ─── Block timeout ─────────────────────────────────────────

static esp_err_t handler_block_timeout(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);
    char buf[64];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body"); return ESP_OK; }
    buf[ret] = 0;
    char *p = strstr(buf, "\"minutes\"");
    if (!p) { httpd_resp_sendstr(req, "{\"ok\":false}"); return ESP_OK; }
    p = strchr(p + 9, ':');
    if (!p) { httpd_resp_sendstr(req, "{\"ok\":false}"); return ESP_OK; }
    int minutes = atoi(p + 1);
    if (minutes < 0) minutes = 0;
    firewall_set_block_timeout(minutes * 60);
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"block_timeout\":%d}", minutes * 60);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    return ESP_OK;
}

// ─── Clear alerts ──────────────────────────────────────────

static esp_err_t handler_clear_alerts(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);
    firewall_clear_alerts();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

// ─── Confidence threshold ──────────────────────────────────

static esp_err_t handler_conf_threshold_set(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[64];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
        return ESP_OK;
    }
    buf[ret] = 0;

    char *p = strstr(buf, "\"threshold\"");
    if (!p) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"missing threshold\"}");
        return ESP_OK;
    }
    p = strchr(p + 11, ':');
    if (!p) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"bad json\"}");
        return ESP_OK;
    }
    float v = strtof(p + 1, NULL);
    if (v < 0.50f || v > 0.95f) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"threshold must be 0.50-0.95\"}");
        return ESP_OK;
    }

    guardnet_conf_threshold_set(v);

    char resp[64];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"conf_threshold\":%.2f}", guardnet_conf_threshold_get());
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    return ESP_OK;
}

// ─── Assign static IP to client ───────────────────────────

static esp_err_t handler_setip(httpd_req_t *req)
{
    if (!check_auth(req)) return send_auth_required(req);

    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body"); return ESP_OK; }
    buf[len] = 0;

    // Parse {"mac":"xx:xx:xx:xx:xx:xx","ip":"192.168.4.x"}
    uint8_t mac[6];
    char *mac_key = strstr(buf, "\"mac\"");
    if (!mac_key) goto bad;
    char *mac_start = strchr(mac_key + 5, '"');
    if (!mac_start) goto bad;
    mac_start++;
    char *mac_end = strchr(mac_start, '"');
    if (!mac_end) goto bad;
    *mac_end = 0;
    if (sscanf(mac_start, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) goto bad;

    char *ip_key = strstr(mac_end + 1, "\"ip\"");
    if (!ip_key) goto bad;
    char *ip_start = strchr(ip_key + 4, '"');
    if (!ip_start) goto bad;
    ip_start++;
    char *ip_end = strchr(ip_start, '"');
    if (!ip_end) goto bad;
    *ip_end = 0;

    uint8_t a, b, c, d;
    if (sscanf(ip_start, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) goto bad;

    // Validate: must be in AP subnet 192.168.4.2–254 (not gateway .1)
    if (a != 192 || b != 168 || c != 4 || d < 2 || d > 254) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"IP must be 192.168.4.2-254\"}");
        return ESP_OK;
    }

    uint32_t ip = a | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24);
    esp_err_t err = wifi_manager_set_client_ip(mac, ip);

    if (err == ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Failed\"}");
    }
    return ESP_OK;

bad:
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Invalid request\"}");
    return ESP_OK;
}

// ─── Server init ────────────────────────────────────────────

esp_err_t web_server_start(void)
{
    load_dashboard_pass();

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 27;
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.stack_size = 8192;
    config.max_open_sockets = 7;        // handle more concurrent connections
    config.lru_purge_enable = true;      // drop oldest connection when full (survives scans)
    config.recv_wait_timeout = 5;        // don't hold sockets forever
    config.send_wait_timeout = 5;

    httpd_handle_t server = NULL;
    ESP_ERROR_CHECK(httpd_start(&server, &config));

    // Static files (no auth — login page needs these)
    httpd_uri_t uri_index = { .uri = "/", .method = HTTP_GET, .handler = handler_index };
    httpd_uri_t uri_css   = { .uri = "/style.css", .method = HTTP_GET, .handler = handler_css };
    httpd_uri_t uri_js    = { .uri = "/app.js", .method = HTTP_GET, .handler = handler_js };

    // Auth API
    httpd_uri_t uri_auth_check  = { .uri = "/api/auth/check",  .method = HTTP_GET,  .handler = handler_auth_check };
    httpd_uri_t uri_auth_change = { .uri = "/api/auth/change", .method = HTTP_POST, .handler = handler_auth_change };

    // Data API
    httpd_uri_t uri_status  = { .uri = "/api/status",  .method = HTTP_GET,  .handler = handler_status };
    httpd_uri_t uri_alerts  = { .uri = "/api/alerts",  .method = HTTP_GET,  .handler = handler_alerts };
    httpd_uri_t uri_blocked = { .uri = "/api/blocked",  .method = HTTP_GET, .handler = handler_blocked };
    httpd_uri_t uri_clients = { .uri = "/api/clients",  .method = HTTP_GET, .handler = handler_clients };
    httpd_uri_t uri_block   = { .uri = "/api/block",    .method = HTTP_POST, .handler = handler_block_ip };
    httpd_uri_t uri_unblock     = { .uri = "/api/unblock",     .method = HTTP_POST, .handler = handler_unblock_ip };
    httpd_uri_t uri_disconnect  = { .uri = "/api/disconnect",  .method = HTTP_POST, .handler = handler_disconnect };
    httpd_uri_t uri_setip       = { .uri = "/api/clients/setip", .method = HTTP_POST, .handler = handler_setip };

    // WiFi config API
    httpd_uri_t uri_wifi_status  = { .uri = "/api/wifi/status",  .method = HTTP_GET,  .handler = handler_wifi_status };
    httpd_uri_t uri_wifi_scan    = { .uri = "/api/wifi/scan",    .method = HTTP_GET,  .handler = handler_wifi_scan };
    httpd_uri_t uri_wifi_connect = { .uri = "/api/wifi/connect", .method = HTTP_POST, .handler = handler_wifi_connect };
    httpd_uri_t uri_wifi_forget  = { .uri = "/api/wifi/forget",  .method = HTTP_POST, .handler = handler_wifi_forget };
    httpd_uri_t uri_wifi_retry   = { .uri = "/api/wifi/retry",   .method = HTTP_POST, .handler = handler_wifi_retry };

    // IDS toggle
    httpd_uri_t uri_ids_toggle = { .uri = "/api/ids/toggle", .method = HTTP_POST, .handler = handler_ids_toggle };

    // Block toggle
    httpd_uri_t uri_block_toggle = { .uri = "/api/block/toggle", .method = HTTP_POST, .handler = handler_block_toggle };

    // Confidence threshold (paranoia slider)
    httpd_uri_t uri_conf_set = { .uri = "/api/confidence", .method = HTTP_POST, .handler = handler_conf_threshold_set };

    // Clear alert log
    httpd_uri_t uri_clear = { .uri = "/api/alerts/clear", .method = HTTP_POST, .handler = handler_clear_alerts };

    // Timeline (attacks/minute over last 10 min)
    httpd_uri_t uri_timeline = { .uri = "/api/timeline", .method = HTTP_GET, .handler = handler_timeline };

    // Block timeout
    httpd_uri_t uri_block_timeout = { .uri = "/api/block/timeout", .method = HTTP_POST, .handler = handler_block_timeout };

    httpd_register_uri_handler(server, &uri_index);
    httpd_register_uri_handler(server, &uri_css);
    httpd_register_uri_handler(server, &uri_js);
    httpd_register_uri_handler(server, &uri_auth_check);
    httpd_register_uri_handler(server, &uri_auth_change);
    httpd_register_uri_handler(server, &uri_status);
    httpd_register_uri_handler(server, &uri_alerts);
    httpd_register_uri_handler(server, &uri_blocked);
    httpd_register_uri_handler(server, &uri_clients);
    httpd_register_uri_handler(server, &uri_block);
    httpd_register_uri_handler(server, &uri_unblock);
    httpd_register_uri_handler(server, &uri_disconnect);
    httpd_register_uri_handler(server, &uri_setip);
    httpd_register_uri_handler(server, &uri_wifi_status);
    httpd_register_uri_handler(server, &uri_wifi_scan);
    httpd_register_uri_handler(server, &uri_wifi_connect);
    httpd_register_uri_handler(server, &uri_wifi_forget);
    httpd_register_uri_handler(server, &uri_wifi_retry);
    httpd_register_uri_handler(server, &uri_ids_toggle);
    httpd_register_uri_handler(server, &uri_block_toggle);
    httpd_register_uri_handler(server, &uri_conf_set);
    httpd_register_uri_handler(server, &uri_clear);
    httpd_register_uri_handler(server, &uri_timeline);
    httpd_register_uri_handler(server, &uri_block_timeout);

    ESP_LOGI(TAG, "Web server started on port %d", config.server_port);
    ESP_LOGI(TAG, "Dashboard: http://esp-firewall.local/");
    return ESP_OK;
}
