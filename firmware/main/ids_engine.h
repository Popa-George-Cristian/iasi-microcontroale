#ifndef IDS_ENGINE_H
#define IDS_ENGINE_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

// Attack categories (match training)
typedef enum {
    CAT_NORMAL = 0,
    CAT_DOS,
    CAT_DDOS,
    CAT_PORTSCAN,
    CAT_BRUTEFORCE,
    CAT_WEBATTACK,
    CAT_INFILTRATION,
    CAT_BOTNET,
    CAT_COUNT
} attack_category_t;

// Flow features (30 features matching training)
typedef struct {
    float dest_port;
    float flow_duration;
    float total_fwd_packets;
    float total_bwd_packets;
    float total_len_fwd;
    float total_len_bwd;
    float fwd_pkt_len_max;
    float fwd_pkt_len_mean;
    float fwd_pkt_len_std;
    float bwd_pkt_len_max;
    float bwd_pkt_len_mean;
    float bwd_pkt_len_std;
    float flow_bytes_per_s;
    float flow_pkts_per_s;
    float flow_iat_mean;
    float flow_iat_std;
    float flow_iat_max;
    float flow_iat_min;
    float fwd_iat_mean;
    float bwd_iat_mean;
    float fwd_psh_flags;
    float syn_flag_count;
    float rst_flag_count;
    float ack_flag_count;
    float down_up_ratio;
    float avg_pkt_size;
    float avg_fwd_seg_size;
    float avg_bwd_seg_size;
    float init_win_fwd;
    float init_win_bwd;
} flow_features_t;

// Classification result
typedef struct {
    attack_category_t category;
    float confidence;
    const char *label;
    float inference_time_us;
} ids_result_t;

// Init the inference engine
esp_err_t ids_engine_init(void);

// Classify a flow
ids_result_t ids_classify(const flow_features_t *features);

// Average inference time in microseconds
float ids_get_avg_inference_us(void);

#endif
