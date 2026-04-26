#include "firewall.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "firewall";

#define BLOCK_TIMEOUT_DEFAULT_SEC  300   // 5 minutes; 0 = permanent
#define TIMELINE_BUCKET_SEC        60

static blocked_entry_t s_blocked[MAX_BLOCKED_IPS];
static int             s_blocked_count = 0;
static alert_entry_t   s_alerts[MAX_ALERT_LOG];
static int             s_alert_head  = 0;
static int             s_alert_count = 0;
static int             s_total_attacks = 0;
static int             s_block_timeout_sec = BLOCK_TIMEOUT_DEFAULT_SEC;
static SemaphoreHandle_t s_mutex;

// ─── Timeline ────────────────────────────────────────────────
static int32_t  s_timeline[TIMELINE_BUCKETS];
static int      s_tl_head = 0;           // index of the current (most recent) bucket
static int64_t  s_tl_bucket_start_us = 0;

static void timeline_advance(int64_t now_us)
{
    if (s_tl_bucket_start_us == 0) {
        s_tl_bucket_start_us = now_us;
        return;
    }
    int64_t bucket_us = (int64_t)TIMELINE_BUCKET_SEC * 1000000LL;
    int64_t elapsed   = now_us - s_tl_bucket_start_us;
    if (elapsed < bucket_us) return;

    int advance = (int)(elapsed / bucket_us);
    if (advance >= TIMELINE_BUCKETS) {
        memset(s_timeline, 0, sizeof(s_timeline));
        s_tl_head = 0;
    } else {
        for (int i = 0; i < advance; i++) {
            s_tl_head = (s_tl_head + 1) % TIMELINE_BUCKETS;
            s_timeline[s_tl_head] = 0;
        }
    }
    s_tl_bucket_start_us += (int64_t)advance * bucket_us;
}

static void timeline_record(void)
{
    int64_t now = esp_timer_get_time();
    timeline_advance(now);
    s_timeline[s_tl_head]++;
}

void firewall_get_timeline(int32_t counts[TIMELINE_BUCKETS])
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    timeline_advance(esp_timer_get_time());
    // Return oldest→newest: start from (head+1) mod BUCKETS
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        counts[i] = s_timeline[(s_tl_head + 1 + i) % TIMELINE_BUCKETS];
    }
    xSemaphoreGive(s_mutex);
}

// ─── Init ────────────────────────────────────────────────────

esp_err_t firewall_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    s_tl_bucket_start_us = esp_timer_get_time();
    ESP_LOGI(TAG, "Firewall init — max %d IPs, %d alerts, timeout=%ds",
             MAX_BLOCKED_IPS, MAX_ALERT_LOG, s_block_timeout_sec);
    return ESP_OK;
}

// ─── Block timeout ───────────────────────────────────────────

void firewall_set_block_timeout(int seconds)
{
    s_block_timeout_sec = seconds;
    ESP_LOGI(TAG, "Block timeout set to %ds (%s)", seconds,
             seconds == 0 ? "permanent" : "auto-unblock");
}

int firewall_get_block_timeout(void) { return s_block_timeout_sec; }

// ─── Block / unblock ─────────────────────────────────────────

bool firewall_block_ip(uint32_t ip, attack_category_t reason)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    for (int i = 0; i < s_blocked_count; i++) {
        if (s_blocked[i].ip == ip) {
            xSemaphoreGive(s_mutex);
            return false;
        }
    }

    if (s_blocked_count >= MAX_BLOCKED_IPS) {
        memmove(&s_blocked[0], &s_blocked[1],
                (MAX_BLOCKED_IPS - 1) * sizeof(blocked_entry_t));
        s_blocked_count--;
    }

    int64_t now_us = esp_timer_get_time();
    s_blocked[s_blocked_count].ip        = ip;
    s_blocked[s_blocked_count].reason    = reason;
    s_blocked[s_blocked_count].timestamp = now_us / 1000000;
    s_blocked[s_blocked_count].unblock_at =
        (s_block_timeout_sec > 0)
            ? now_us + (int64_t)s_block_timeout_sec * 1000000LL
            : 0;
    s_blocked_count++;

    ESP_LOGW(TAG, "BLOCKED %u.%u.%u.%u reason=%d timeout=%ds",
             (unsigned)(ip & 0xFF), (unsigned)((ip >> 8) & 0xFF),
             (unsigned)((ip >> 16) & 0xFF), (unsigned)((ip >> 24) & 0xFF),
             reason, s_block_timeout_sec);

    xSemaphoreGive(s_mutex);
    return true;
}

bool firewall_unblock_ip(uint32_t ip)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < s_blocked_count; i++) {
        if (s_blocked[i].ip == ip) {
            memmove(&s_blocked[i], &s_blocked[i + 1],
                    (s_blocked_count - i - 1) * sizeof(blocked_entry_t));
            s_blocked_count--;
            xSemaphoreGive(s_mutex);
            ESP_LOGI(TAG, "Unblocked %u.%u.%u.%u",
                     (unsigned)(ip & 0xFF), (unsigned)((ip >> 8) & 0xFF),
                     (unsigned)((ip >> 16) & 0xFF), (unsigned)((ip >> 24) & 0xFF));
            return true;
        }
    }
    xSemaphoreGive(s_mutex);
    return false;
}

bool firewall_is_blocked(uint32_t ip)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < s_blocked_count; i++) {
        if (s_blocked[i].ip == ip) {
            xSemaphoreGive(s_mutex);
            return true;
        }
    }
    xSemaphoreGive(s_mutex);
    return false;
}

int firewall_check_auto_unblock(void)
{
    int64_t now_us = esp_timer_get_time();
    int unblocked = 0;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < s_blocked_count; ) {
        if (s_blocked[i].unblock_at > 0 && now_us >= s_blocked[i].unblock_at) {
            uint32_t ip = s_blocked[i].ip;
            memmove(&s_blocked[i], &s_blocked[i + 1],
                    (s_blocked_count - i - 1) * sizeof(blocked_entry_t));
            s_blocked_count--;
            unblocked++;
            ESP_LOGI(TAG, "Auto-unblocked %u.%u.%u.%u",
                     (unsigned)(ip & 0xFF), (unsigned)((ip >> 8) & 0xFF),
                     (unsigned)((ip >> 16) & 0xFF), (unsigned)((ip >> 24) & 0xFF));
        } else {
            i++;
        }
    }
    xSemaphoreGive(s_mutex);
    return unblocked;
}

// ─── Disconnect by MAC ───────────────────────────────────────

esp_err_t firewall_disconnect_client(const uint8_t mac[6])
{
    ESP_LOGW(TAG, "Deauthing client: " MACSTR, MAC2STR(mac));
    uint16_t aid = 0;
    if (esp_wifi_ap_get_sta_aid(mac, &aid) != ESP_OK || aid == 0)
        return ESP_ERR_NOT_FOUND;
    return esp_wifi_deauth_sta(aid);
}

// ─── Alert log ───────────────────────────────────────────────

void firewall_log_alert(uint32_t src_ip, uint32_t dst_ip,
                        attack_category_t cat, float confidence, bool internal,
                        const float *features)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    alert_entry_t *e = &s_alerts[s_alert_head];
    e->src_ip       = src_ip;
    e->dst_ip       = dst_ip;
    e->category     = cat;
    e->confidence   = confidence;
    e->timestamp    = esp_timer_get_time() / 1000000;
    e->from_internal = internal;
    if (features)
        memcpy(e->features, features, ALERT_NUM_FEATURES * sizeof(float));
    else
        memset(e->features, 0, ALERT_NUM_FEATURES * sizeof(float));

    s_alert_head = (s_alert_head + 1) % MAX_ALERT_LOG;
    if (s_alert_count < MAX_ALERT_LOG) s_alert_count++;
    s_total_attacks++;
    timeline_record();

    xSemaphoreGive(s_mutex);
}

// ─── Getters ─────────────────────────────────────────────────

int firewall_get_blocked_count(void)                    { return s_blocked_count; }
int firewall_get_alert_count(void)                      { return s_alert_count; }
int firewall_get_alert_head(void)                       { return s_alert_head; }
const blocked_entry_t *firewall_get_blocked_list(void)  { return s_blocked; }
const alert_entry_t   *firewall_get_alert_log(void)     { return s_alerts; }
int firewall_get_total_attacks(void)                    { return s_total_attacks; }

void firewall_clear_alerts(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    memset(s_alerts, 0, sizeof(s_alerts));
    s_alert_head  = 0;
    s_alert_count = 0;
    s_total_attacks = 0;
    xSemaphoreGive(s_mutex);
}
