#include "wifi_manager.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "lwip/lwip_napt.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "dhcpserver/dhcpserver.h"

static const char *TAG = "wifi_mgr";

#define NVS_NAMESPACE "wifi_cfg"
#define NVS_KEY_SSID  "sta_ssid"
#define NVS_KEY_PASS  "sta_pass"

static esp_netif_t *s_ap_netif = NULL;
static esp_netif_t *s_sta_netif = NULL;
static EventGroupHandle_t s_wifi_events;
static bool s_sta_connected = false;
static bool s_manual_connect = false;  // only retry when user triggered connect
static char s_sta_ssid[33] = {0};
static char s_sta_pass[65] = {0};
static int s_retry_count = 0;
static esp_timer_handle_t s_reconnect_timer = NULL;
static bool s_dhcp_pool_restricted = false;  // true while pool is locked to one IP

// ─── Static IP assignment table ──────────────────────────────
#define MAX_STATIC_IPS 8
static static_ip_entry_t s_static_ips[MAX_STATIC_IPS];

// Full DHCP pool: 192.168.4.2 – 192.168.4.254
#define AP_POOL_START_IP  0x0204A8C0U  // 192.168.4.2  LE
#define AP_POOL_END_IP    0xFE04A8C0U  // 192.168.4.254 LE

static void restore_dhcp_pool(void)
{
    dhcps_lease_t full = {
        .enable   = true,
        .start_ip = { .addr = AP_POOL_START_IP },
        .end_ip   = { .addr = AP_POOL_END_IP   },
    };
    esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET,
                           ESP_NETIF_REQUESTED_IP_ADDRESS, &full, sizeof(full));
    s_dhcp_pool_restricted = false;
    ESP_LOGI(TAG, "DHCP pool restored to full range");
}

#define STA_CONNECTED_BIT BIT0
#define MAX_RETRIES 5

// ─── AP client MAC→IP table (populated from DHCP assignment events) ──
#define MAX_AP_CLIENT_ENTRIES 8

typedef struct {
    uint8_t  mac[6];
    uint32_t ip;
} ap_client_entry_t;

static ap_client_entry_t s_ap_clients[MAX_AP_CLIENT_ENTRIES];

static void s_reconnect_timer_cb(void *arg) { esp_wifi_connect(); }

static bool load_sta_creds(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;

    size_t len = sizeof(s_sta_ssid);
    bool ok = (nvs_get_str(h, NVS_KEY_SSID, s_sta_ssid, &len) == ESP_OK);
    if (ok) {
        len = sizeof(s_sta_pass);
        nvs_get_str(h, NVS_KEY_PASS, s_sta_pass, &len);
    }
    nvs_close(h);
    return ok && strlen(s_sta_ssid) > 0;
}

static esp_err_t save_sta_creds(const char *ssid, const char *pass)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    nvs_set_str(h, NVS_KEY_SSID, ssid);
    nvs_set_str(h, NVS_KEY_PASS, pass ? pass : "");
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
}

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    if (base == WIFI_EVENT) {
        switch (id) {
        case WIFI_EVENT_STA_START:
            // Don't auto-connect — wait for manual trigger from dashboard
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            s_sta_connected = false;
            if (s_manual_connect && s_retry_count < MAX_RETRIES) {
                s_retry_count++;
                ESP_LOGW(TAG, "STA disconnected, retry %d/%d", s_retry_count, MAX_RETRIES);
                // Use timer instead of vTaskDelay — never block the WiFi event task
                if (s_reconnect_timer)
                    esp_timer_start_once(s_reconnect_timer, 3000000);
            } else if (s_retry_count >= MAX_RETRIES) {
                s_manual_connect = false;
                ESP_LOGE(TAG, "STA failed after %d retries — check credentials via dashboard", MAX_RETRIES);
            }
            break;
        case WIFI_EVENT_AP_STACONNECTED: {
            wifi_event_ap_staconnected_t *e = data;
            ESP_LOGI(TAG, "Client connected: " MACSTR, MAC2STR(e->mac));
            break;
        }
        case WIFI_EVENT_AP_STADISCONNECTED: {
            wifi_event_ap_stadisconnected_t *e = data;
            ESP_LOGI(TAG, "Client disconnected: " MACSTR, MAC2STR(e->mac));
            break;
        }
        }
    } else if (base == IP_EVENT && id == IP_EVENT_AP_STAIPASSIGNED) {
        ip_event_ap_staipassigned_t *e = data;
        // Record MAC→IP assignment for AP client
        int free_idx = -1;
        for (int i = 0; i < MAX_AP_CLIENT_ENTRIES; i++) {
            if (memcmp(s_ap_clients[i].mac, e->mac, 6) == 0) {
                s_ap_clients[i].ip = e->ip.addr;
                ESP_LOGI(TAG, "AP client IP updated: " MACSTR " -> " IPSTR,
                         MAC2STR(e->mac), IP2STR(&e->ip));
                free_idx = -2; // mark found
                break;
            }
            if (s_ap_clients[i].ip == 0 && free_idx < 0) free_idx = i;
        }
        if (free_idx >= 0) {
            memcpy(s_ap_clients[free_idx].mac, e->mac, 6);
            s_ap_clients[free_idx].ip = e->ip.addr;
            ESP_LOGI(TAG, "AP client IP assigned: " MACSTR " -> " IPSTR,
                     MAC2STR(e->mac), IP2STR(&e->ip));
        }
        // If pool was restricted for a static IP assignment, restore it now
        if (s_dhcp_pool_restricted) restore_dhcp_pool();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        ESP_LOGI(TAG, "STA got IP: " IPSTR, IP2STR(&e->ip_info.ip));
        s_sta_connected = true;
        s_retry_count = 0;
        xEventGroupSetBits(s_wifi_events, STA_CONNECTED_BIT);

        // Forward upstream DNS to AP clients
        esp_netif_dns_info_t dns;
        if (esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
            esp_netif_dhcps_stop(s_ap_netif);
            esp_netif_set_dns_info(s_ap_netif, ESP_NETIF_DNS_MAIN, &dns);

            dhcps_offer_t offer = OFFER_DNS;
            esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET,
                                   ESP_NETIF_DOMAIN_NAME_SERVER, &offer, sizeof(offer));

            // If pool was restricted for IP assignment, the restart cleared it — cancel
            s_dhcp_pool_restricted = false;

            esp_netif_dhcps_start(s_ap_netif);
            ESP_LOGI(TAG, "DNS forwarded: " IPSTR, IP2STR(&dns.ip.u_addr.ip4));
        }

        // Enable NAPT on AP interface (packets entering AP get source-NATted out STA)
        esp_netif_ip_info_t ap_ip;
        if (esp_netif_get_ip_info(s_ap_netif, &ap_ip) == ESP_OK) {
            ip_napt_enable(ap_ip.ip.addr, 1);
            ESP_LOGI(TAG, "NAPT enabled on AP (" IPSTR ") — clients can access internet",
                     IP2STR(&ap_ip.ip));
        }
    }
}

esp_err_t wifi_manager_init(void)
{
    // Init NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    s_wifi_events = xEventGroupCreate();

    // Create reconnect timer — fires from timer task, not the WiFi event task
    esp_timer_create_args_t reconnect_args = {
        .callback = s_reconnect_timer_cb,
        .name = "sta_reconnect",
    };
    esp_timer_create(&reconnect_args, &s_reconnect_timer);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_ap_netif = esp_netif_create_default_wifi_ap();
    s_sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED,
                                               wifi_event_handler, NULL));

    // Load saved STA creds — auto-connect if available
    bool has_sta_creds = load_sta_creds();

    if (has_sta_creds) {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    } else {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    }

    // Configure AP
    wifi_config_t ap_cfg = {0};
    memcpy(ap_cfg.ap.ssid, GUARDNET_AP_SSID, strlen(GUARDNET_AP_SSID));
    ap_cfg.ap.ssid_len = strlen(GUARDNET_AP_SSID);
    memcpy(ap_cfg.ap.password, GUARDNET_AP_PASS, strlen(GUARDNET_AP_PASS));
    ap_cfg.ap.channel = GUARDNET_AP_CHANNEL;
    ap_cfg.ap.max_connection = GUARDNET_AP_MAX_CONN;
    ap_cfg.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;  // WPA1+WPA2 mixed — disables PMF/WPA3 negotiation
    ap_cfg.ap.beacon_interval = 100;
    ap_cfg.ap.pmf_cfg.required = false;
    ap_cfg.ap.pmf_cfg.capable  = false;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));

    // Configure STA before start if creds exist
    if (has_sta_creds) {
        wifi_config_t sta_cfg = {0};
        strncpy((char *)sta_cfg.sta.ssid, s_sta_ssid, sizeof(sta_cfg.sta.ssid) - 1);
        strncpy((char *)sta_cfg.sta.password, s_sta_pass, sizeof(sta_cfg.sta.password) - 1);
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
    }

    ESP_ERROR_CHECK(esp_wifi_start());

    // ~15 dBm TX power (60 quarter-dBm) — safer for USB power supply
    esp_wifi_set_max_tx_power(60);

    // Keep clients associated for 30s of inactivity (default 5s is too aggressive)
    esp_wifi_set_inactive_time(WIFI_IF_AP, 30);

    // Auto-connect STA if saved creds exist (smooth reboot reconnection)
    if (has_sta_creds) {
        s_manual_connect = true;
        esp_wifi_connect();
        ESP_LOGI(TAG, "Auto-connecting STA to: %s", s_sta_ssid);
    }

    ESP_LOGI(TAG, "AP started: %s | Dashboard: http://192.168.4.1/", GUARDNET_AP_SSID);

    return ESP_OK;
}

esp_err_t wifi_manager_set_sta(const char *ssid, const char *pass)
{
    if (!ssid || strlen(ssid) == 0) return ESP_ERR_INVALID_ARG;

    esp_err_t err = save_sta_creds(ssid, pass);
    if (err != ESP_OK) return err;

    strncpy(s_sta_ssid, ssid, sizeof(s_sta_ssid) - 1);
    s_sta_ssid[sizeof(s_sta_ssid) - 1] = 0;
    strncpy(s_sta_pass, pass ? pass : "", sizeof(s_sta_pass) - 1);
    s_sta_pass[sizeof(s_sta_pass) - 1] = 0;

    // Ensure APSTA mode
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    // Set connection state BEFORE disconnect so event handler knows
    // we intend to reconnect (prevents stale-state race condition)
    s_sta_connected = false;
    s_manual_connect = false;  // suppress retries during reconfiguration
    s_retry_count = 0;

    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(300));

    wifi_config_t sta_cfg = {0};
    strncpy((char *)sta_cfg.sta.ssid, s_sta_ssid, sizeof(sta_cfg.sta.ssid) - 1);
    strncpy((char *)sta_cfg.sta.password, s_sta_pass, sizeof(sta_cfg.sta.password) - 1);
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));

    // Now enable retries and connect
    s_manual_connect = true;
    esp_wifi_connect();

    ESP_LOGI(TAG, "STA connecting to: %s", s_sta_ssid);
    return ESP_OK;
}

esp_err_t wifi_manager_retry_sta(void)
{
    if (strlen(s_sta_ssid) == 0) return ESP_ERR_INVALID_STATE;
    if (s_sta_connected) return ESP_OK;
    s_manual_connect = true;
    s_retry_count = 0;
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_wifi_connect();
    ESP_LOGI(TAG, "STA retry connect to: %s", s_sta_ssid);
    return ESP_OK;
}

esp_err_t wifi_manager_forget_sta(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_key(h, NVS_KEY_SSID);
        nvs_erase_key(h, NVS_KEY_PASS);
        nvs_commit(h);
        nvs_close(h);
    }

    s_sta_ssid[0] = 0;
    s_sta_pass[0] = 0;
    s_sta_connected = false;
    s_manual_connect = false;
    s_retry_count = 0;

    esp_wifi_disconnect();

    // Stay in current mode — switching to AP-only then back to APSTA
    // causes initialization issues on reconnect

    ESP_LOGI(TAG, "STA credentials forgotten");
    return ESP_OK;
}

const char *wifi_manager_get_sta_ssid(void)
{
    return s_sta_ssid;
}

int wifi_manager_scan(scan_ap_t *results, int max)
{
    // Switch to APSTA mode for scanning
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_AP) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    wifi_scan_config_t scan_cfg = {
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100,
        .scan_time.active.max = 200,
    };

    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Scan failed: %s", esp_err_to_name(err));
        return 0;
    }

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);

    int to_get = (ap_count < (uint16_t)max) ? ap_count : max;
    wifi_ap_record_t *records = calloc(to_get, sizeof(wifi_ap_record_t));
    if (!records) return 0;

    uint16_t got = to_get;
    esp_wifi_scan_get_ap_records(&got, records);

    for (int i = 0; i < got; i++) {
        strncpy(results[i].ssid, (const char *)records[i].ssid, 32);
        results[i].ssid[32] = 0;
        results[i].rssi = records[i].rssi;
        results[i].secure = (records[i].authmode != WIFI_AUTH_OPEN);
    }

    free(records);
    return got;
}

esp_netif_t *wifi_manager_get_ap_netif(void)  { return s_ap_netif; }
esp_netif_t *wifi_manager_get_sta_netif(void) { return s_sta_netif; }
bool wifi_manager_sta_connected(void)         { return s_sta_connected; }

int wifi_manager_get_client_count(void)
{
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
        return sta_list.num;
    }
    return 0;
}

bool wifi_manager_get_client_ip(const uint8_t *mac, uint32_t *ip_out)
{
    for (int i = 0; i < MAX_AP_CLIENT_ENTRIES; i++) {
        if (s_ap_clients[i].ip != 0 &&
            memcmp(s_ap_clients[i].mac, mac, 6) == 0) {
            *ip_out = s_ap_clients[i].ip;
            return true;
        }
    }
    return false;
}

int wifi_manager_get_dhcp_clients(uint8_t macs[][6], uint32_t *ips, int max)
{
    int count = 0;
    for (int i = 0; i < MAX_AP_CLIENT_ENTRIES && count < max; i++) {
        if (s_ap_clients[i].ip != 0) {
            memcpy(macs[count], s_ap_clients[i].mac, 6);
            ips[count] = s_ap_clients[i].ip;
            count++;
        }
    }
    return count;
}

// ─── Static IP assignment ─────────────────────────────────────

esp_err_t wifi_manager_set_client_ip(const uint8_t mac[6], uint32_t desired_ip)
{
    // Store in static IP table
    int free_idx = -1;
    for (int i = 0; i < MAX_STATIC_IPS; i++) {
        bool zero = true;
        for (int b = 0; b < 6; b++) if (s_static_ips[i].mac[b]) { zero = false; break; }
        if (!zero && memcmp(s_static_ips[i].mac, mac, 6) == 0) {
            s_static_ips[i].ip = desired_ip;
            free_idx = -2;  // found+updated
            break;
        }
        if (zero && free_idx < 0) free_idx = i;
    }
    if (free_idx >= 0) {
        memcpy(s_static_ips[free_idx].mac, mac, 6);
        s_static_ips[free_idx].ip = desired_ip;
    }

    // Temporarily restrict DHCP pool to only the desired IP, then reset on assignment
    esp_netif_dhcps_stop(s_ap_netif);

    dhcps_lease_t lease = {
        .enable   = true,
        .start_ip = { .addr = desired_ip },
        .end_ip   = { .addr = desired_ip },
    };
    esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET,
                           ESP_NETIF_REQUESTED_IP_ADDRESS, &lease, sizeof(lease));
    s_dhcp_pool_restricted = true;  // restore_dhcp_pool() called on next IP_EVENT_AP_STAIPASSIGNED

    esp_netif_dhcps_start(s_ap_netif);

    // Deauth target client — forces reconnect and fresh DHCP request
    uint16_t aid = 0;
    if (esp_wifi_ap_get_sta_aid(mac, &aid) == ESP_OK && aid > 0) {
        esp_wifi_deauth_sta(aid);
        ESP_LOGI(TAG, "Deauthed client for IP reassignment: %u.%u.%u.%u",
                 (unsigned)(desired_ip & 0xFF), (unsigned)((desired_ip >> 8) & 0xFF),
                 (unsigned)((desired_ip >> 16) & 0xFF), (unsigned)((desired_ip >> 24) & 0xFF));
    }

    return ESP_OK;
}

void wifi_manager_clear_client_ip(const uint8_t mac[6])
{
    for (int i = 0; i < MAX_STATIC_IPS; i++) {
        if (memcmp(s_static_ips[i].mac, mac, 6) == 0) {
            memset(&s_static_ips[i], 0, sizeof(static_ip_entry_t));
            return;
        }
    }
}

int wifi_manager_get_static_ips(static_ip_entry_t *out, int max)
{
    int count = 0;
    for (int i = 0; i < MAX_STATIC_IPS && count < max; i++) {
        bool zero = true;
        for (int b = 0; b < 6; b++) if (s_static_ips[i].mac[b]) { zero = false; break; }
        if (!zero) {
            out[count++] = s_static_ips[i];
        }
    }
    return count;
}
