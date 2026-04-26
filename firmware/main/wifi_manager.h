#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "esp_err.h"
#include "esp_netif.h"
#include <stdbool.h>

#define GUARDNET_AP_SSID     "GuardNet"
#define GUARDNET_AP_PASS     "guardnet123"
#define GUARDNET_AP_CHANNEL  1
#define GUARDNET_AP_MAX_CONN 8

#define MAX_SCAN_APS 20

typedef struct {
    char ssid[33];
    int8_t rssi;
    bool secure;
} scan_ap_t;

// Init WiFi — loads STA credentials from NVS if saved
esp_err_t wifi_manager_init(void);

// Save new STA credentials to NVS and reconnect
esp_err_t wifi_manager_set_sta(const char *ssid, const char *pass);

// Retry connecting to saved STA credentials (no-op if already connected or no creds)
esp_err_t wifi_manager_retry_sta(void);

// Forget saved STA credentials, revert to AP-only
esp_err_t wifi_manager_forget_sta(void);

// Get currently configured STA SSID (empty string if none)
const char *wifi_manager_get_sta_ssid(void);

// Scan for nearby networks. Returns count of results filled.
int wifi_manager_scan(scan_ap_t *results, int max);

// Get AP and STA netif handles
esp_netif_t *wifi_manager_get_ap_netif(void);
esp_netif_t *wifi_manager_get_sta_netif(void);

// Check if STA is connected to upstream
bool wifi_manager_sta_connected(void);

// Get number of connected AP clients
int wifi_manager_get_client_count(void);

// Look up IP for an AP client by MAC (from DHCP assignment events)
// Returns true and sets *ip_out if found
bool wifi_manager_get_client_ip(const uint8_t *mac, uint32_t *ip_out);

// Get all DHCP-assigned clients (MAC+IP pairs). Returns count filled.
int wifi_manager_get_dhcp_clients(uint8_t macs[][6], uint32_t *ips, int max);

// Assign a static IP to a client by MAC. Stores mapping, resets DHCP, deauths client.
// Client must reconnect to receive the new IP. Returns ESP_OK on success.
esp_err_t wifi_manager_set_client_ip(const uint8_t mac[6], uint32_t desired_ip);

// Remove a static IP assignment for a MAC.
void wifi_manager_clear_client_ip(const uint8_t mac[6]);

// Get all static IP assignments. Returns count.
typedef struct {
    uint8_t  mac[6];
    uint32_t ip;
} static_ip_entry_t;

int wifi_manager_get_static_ips(static_ip_entry_t *out, int max);

#endif
