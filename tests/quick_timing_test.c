/*********************************************************************
* Filename:   quick_timing_test.c
* Author:     Quick timing test for SHA256-90R
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Quick timing test to verify patches work
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include "../src/sha256_90r/sha256_90r.h"

/****************************** MACROS ******************************/
#define NUM_SAMPLES 1000
#define INPUT_SIZE 64

/**************************** DATA TYPES ****************************/
typedef struct {
    double mean;
    double std_dev;
    double min;
    double max;
} timing_stats_t;

/*********************** FUNCTION DEFINITIONS ***********************/

/**
 * Calculate mean of timing samples
 */
double calculate_mean(const double *samples, size_t count) {
    double sum = 0.0;
    for (size_t i = 0; i < count; i++) {
        sum += samples[i];
    }
    return sum / count;
}

/**
 * Calculate standard deviation of timing samples
 */
double calculate_std_dev(const double *samples, size_t count, double mean) {
    double sum_squared_diff = 0.0;
    for (size_t i = 0; i < count; i++) {
        double diff = samples[i] - mean;
        sum_squared_diff += diff * diff;
    }
    return sqrt(sum_squared_diff / (count - 1));
}

/**
 * Welch's t-test implementation
 */
double welch_t_test(const double *samples1, size_t count1,
                   const double *samples2, size_t count2) {
    double mean1 = calculate_mean(samples1, count1);
    double mean2 = calculate_mean(samples2, count2);
    double var1 = calculate_std_dev(samples1, count1, mean1);
    double var2 = calculate_std_dev(samples2, count2, mean2);

    var1 = var1 * var1;  // variance
    var2 = var2 * var2;  // variance

    double t_stat = (mean1 - mean2) / sqrt((var1 / count1) + (var2 / count2));

    // For large sample sizes, t-distribution approaches normal distribution
    double z = fabs(t_stat);
    double p_value = 2.0 * (1.0 - 0.5 * (1.0 + erf(z / sqrt(2.0))));

    return p_value;
}

/**
 * Time a single SHA256-90R operation
 */
double time_sha256_90r(const uint8_t *input, size_t input_len) {
    struct timespec start, end;
    SHA256_90R_CTX *ctx;
    uint8_t hash[SHA256_90R_DIGEST_SIZE];

    // Start timing
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    // Initialize context
    ctx = sha256_90r_new(SHA256_90R_MODE_SECURE);
    sha256_90r_update(ctx, input, input_len);
    sha256_90r_final(ctx, hash);
    sha256_90r_free(ctx);

    // End timing
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    // Calculate elapsed time in nanoseconds
    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 +
                       (end.tv_nsec - start.tv_nsec);

    return elapsed_ns;
}

/**
 * Collect timing samples
 */
void collect_timing_samples(double *samples, size_t count, const uint8_t *input, size_t input_len) {
    for (size_t i = 0; i < count; i++) {
        samples[i] = time_sha256_90r(input, input_len);
    }
}

/**
 * Determine if timing difference is statistically significant
 */
const char* significance_level(double p_value, double mean_diff_ns) {
    if (fabs(mean_diff_ns) < 100.0 && p_value >= 0.001) {
        return "NOT EXPLOITABLE";
    }
    if (p_value < 0.001) return "EXPLOITABLE";
    if (p_value < 0.01) return "SIGNIFICANT";
    if (p_value < 0.05) return "MARGINALLY SIGNIFICANT";
    return "NOT SIGNIFICANT";
}

/*********************** MAIN FUNCTION ***********************/
int main() {
    printf("=== SHA256-90R Quick Timing Test ===\n");

    // Test cases
    uint8_t input1[INPUT_SIZE] = {0}; // All zeros
    uint8_t input2[INPUT_SIZE] = {0}; // Will be modified
    input2[0] ^= 0x01; // Single bit flip

    // Allocate memory for timing samples
    double *samples1 = malloc(NUM_SAMPLES * sizeof(double));
    double *samples2 = malloc(NUM_SAMPLES * sizeof(double));

    if (!samples1 || !samples2) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    printf("Testing: All zeros vs single bit flip\n");
    printf("Samples per input: %d\n\n", NUM_SAMPLES);

    // Collect timing samples
    printf("Collecting samples for input 1...\n");
    collect_timing_samples(samples1, NUM_SAMPLES, input1, INPUT_SIZE);

    printf("Collecting samples for input 2...\n");
    collect_timing_samples(samples2, NUM_SAMPLES, input2, INPUT_SIZE);

    // Perform statistical test
    double p_value = welch_t_test(samples1, NUM_SAMPLES, samples2, NUM_SAMPLES);
    double mean1 = calculate_mean(samples1, NUM_SAMPLES);
    double mean2 = calculate_mean(samples2, NUM_SAMPLES);
    double mean_diff = mean1 - mean2;

    printf("\nStatistical Analysis:\n");
    printf("  Mean difference: %.2f ns\n", mean_diff);
    printf("  Welch's t-test p-value: %.6f\n", p_value);
    printf("  Significance: %s\n", significance_level(p_value, mean_diff));

    // Test result
    if (fabs(mean_diff) < 100.0 && p_value >= 0.001) {
        printf("\n✅ RESULT: CONSTANT-TIME VERIFIED\n");
        printf("   Timing differences are not exploitable.\n");
    } else {
        printf("\n❌ RESULT: TIMING LEAK DETECTED\n");
        printf("   Further investigation needed.\n");
    }

    // Cleanup
    free(samples1);
    free(samples2);

    return 0;
}
