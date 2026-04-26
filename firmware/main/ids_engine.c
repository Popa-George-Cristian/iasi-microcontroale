#include "ids_engine.h"
#include "model_data.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <math.h>

static const char *TAG = "ids";

// INT8 intermediate buffers
static int8_t input_q[NUM_FEATURES];
static int8_t layer1_out[LAYER1_SIZE];
static int8_t layer2_out[LAYER2_SIZE];
static float  output_f[NUM_CLASSES];

// Inference timing (running average)
static float s_avg_inference_us = 0;
static uint32_t s_inference_count = 0;

// Softmax on float output
static void softmax(float *x, int n)
{
    float max_val = x[0];
    for (int i = 1; i < n; i++)
        if (x[i] > max_val) max_val = x[i];

    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    for (int i = 0; i < n; i++)
        x[i] /= sum;
}

/**
 * INT8 dense layer with ReLU + per-channel requantization to int8.
 *
 * Inner loop: int8 x int8 → int32 accumulator (ESP32-S3 SIMD friendly).
 * Outer loop: per-channel rescale (negligible overhead vs inner loop).
 * ReLU on int32 accumulator (sign preserved since all scales positive).
 */
static void dense_relu_q8(const int8_t *input, const int8_t *weights,
                          const int32_t *bias, int8_t *out,
                          int in_size, int out_size,
                          const float *rescale)
{
    for (int o = 0; o < out_size; o++) {
        int32_t acc = bias[o];
        const int8_t *w_row = &weights[o * in_size];
        for (int i = 0; i < in_size; i++) {
            acc += (int32_t)w_row[i] * (int32_t)input[i];
        }
        // ReLU: negative accumulator → 0
        if (acc <= 0) {
            out[o] = 0;
        } else {
            int32_t q = (int32_t)roundf((float)acc * rescale[o]);
            out[o] = (int8_t)(q > 127 ? 127 : q);
        }
    }
}

/**
 * INT8 dense layer → float output (final layer before softmax).
 * Per-channel dequantization to float. No activation applied.
 */
static void dense_linear_q8_float(const int8_t *input, const int8_t *weights,
                                  const int32_t *bias, float *out,
                                  int in_size, int out_size,
                                  const float *dequant)
{
    for (int o = 0; o < out_size; o++) {
        int32_t acc = bias[o];
        const int8_t *w_row = &weights[o * in_size];
        for (int i = 0; i < in_size; i++) {
            acc += (int32_t)w_row[i] * (int32_t)input[i];
        }
        out[o] = (float)acc * dequant[o];
    }
}

esp_err_t ids_engine_init(void)
{
    ESP_LOGI(TAG, "IDS engine initialized — per-channel INT8 quantized");
    ESP_LOGI(TAG, "  %d features, %d classes", NUM_FEATURES, NUM_CLASSES);
    ESP_LOGI(TAG, "  Model: %d->%d->%d->%d (INT8 weights, INT32 accum)",
             NUM_FEATURES, LAYER1_SIZE, LAYER2_SIZE, NUM_CLASSES);
    return ESP_OK;
}

ids_result_t ids_classify(const flow_features_t *features)
{
    int64_t t_start = esp_timer_get_time();

    // Step 1: MinMax normalize + quantize input to INT8
    const float *raw = (const float *)features;
    for (int i = 0; i < NUM_FEATURES; i++) {
        float range = scaler_max[i] - scaler_min[i];
        float scaled;
        if (range > 1e-8f) {
            scaled = (raw[i] - scaler_min[i]) / range;
        } else {
            scaled = 0.0f;
        }
        if (scaled < 0.0f) scaled = 0.0f;
        if (scaled > 1.0f) scaled = 1.0f;
        int32_t q = (int32_t)roundf(scaled / q_input_scale);
        input_q[i] = (int8_t)(q > 127 ? 127 : (q < -128 ? -128 : q));
    }

    // Step 2: INT8 forward pass (per-channel rescale)
    dense_relu_q8(input_q, w1_q, b1_q, layer1_out,
                  NUM_FEATURES, LAYER1_SIZE, q_l1_rescale);
    dense_relu_q8(layer1_out, w2_q, b2_q, layer2_out,
                  LAYER1_SIZE, LAYER2_SIZE, q_l2_rescale);
    dense_linear_q8_float(layer2_out, w3_q, b3_q, output_f,
                          LAYER2_SIZE, NUM_CLASSES, q_l3_dequant);

    // Step 3: Softmax (float)
    softmax(output_f, NUM_CLASSES);

    // Find argmax
    ids_result_t result;
    result.category = CAT_NORMAL;
    result.confidence = output_f[0];
    for (int i = 1; i < NUM_CLASSES; i++) {
        if (output_f[i] > result.confidence) {
            result.confidence = output_f[i];
            result.category = (attack_category_t)i;
        }
    }
    result.label = CATEGORY_NAMES[result.category];

    // Record timing
    int64_t elapsed = esp_timer_get_time() - t_start;
    result.inference_time_us = (float)elapsed;
    s_inference_count++;
    s_avg_inference_us += ((float)elapsed - s_avg_inference_us) / s_inference_count;

    return result;
}

float ids_get_avg_inference_us(void)
{
    return s_avg_inference_us;
}
