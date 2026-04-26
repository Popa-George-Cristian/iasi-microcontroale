#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "ids_engine.h"

#define MAX_BLOCKED_IPS    64
#define MAX_ALERT_LOG      50
#define TIMELINE_BUCKETS   10   // 10 × 60s = 10-minute window

typedef struct {
    uint32_t ip;
    attack_category_t reason;
    int64_t timestamp;          // seconds since boot when blocked
    int64_t unblock_at;         // esp_timer microseconds; 0 = permanent
} blocked_entry_t;

#define ALERT_NUM_FEATURES 30  // must match NUM_FEATURES in ids_engine.h

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    attack_category_t category;
    float confidence;
    int64_t timestamp;
    bool from_internal;
    float features[ALERT_NUM_FEATURES];
} alert_entry_t;

esp_err_t firewall_init(void);

// Block/unblock IPs
bool firewall_block_ip(uint32_t ip, attack_category_t reason);
bool firewall_unblock_ip(uint32_t ip);
bool firewall_is_blocked(uint32_t ip);
int  firewall_check_auto_unblock(void);  // call from main loop; returns # unblocked

// Block timeout (seconds; 0 = permanent)
void firewall_set_block_timeout(int seconds);
int  firewall_get_block_timeout(void);

// Disconnect AP client by MAC
esp_err_t firewall_disconnect_client(const uint8_t mac[6]);

// Alert log
void firewall_log_alert(uint32_t src_ip, uint32_t dst_ip,
                        attack_category_t cat, float confidence, bool internal,
                        const float *features);

// Getters for dashboard
int firewall_get_blocked_count(void);
int firewall_get_alert_count(void);
int firewall_get_alert_head(void);   // ring-buffer write head; use with get_alert_log
const blocked_entry_t *firewall_get_blocked_list(void);
const alert_entry_t   *firewall_get_alert_log(void);
int firewall_get_total_attacks(void);
void firewall_clear_alerts(void);

// Timeline: 10 buckets × 60s, index 0 = oldest, index (head) = current
void firewall_get_timeline(int32_t counts[TIMELINE_BUCKETS]);

#endif
