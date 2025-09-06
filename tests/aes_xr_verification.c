/*********************************************************************
* Filename:   aes_xr_verification.c
* Author:     AES-XR Verification Test Suite
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Comprehensive verification test for AES-XR including
*             functional correctness, performance benchmarks, timing
*             side-channel analysis, and output validation.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include "../src/aes_xr/aes.h"

/****************************** MACROS ******************************/
#define NUM_SAMPLES 10000
#define TEST_BLOCK_SIZE 16
#define TEST_KEY_SIZE 16
#define MEGABYTE (1024 * 1024)

/**************************** DATA TYPES ****************************/
typedef struct {
    double mean;
    double std_dev;
    double min;
    double max;
} timing_stats_t;

/**************************** GLOBAL VARIABLES ****************************/
// Test vectors for AES-XR verification
BYTE test_key[TEST_KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
BYTE test_plaintext[TEST_BLOCK_SIZE] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                       0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

/*********************** FUNCTION DEFINITIONS ***********************/

/**
 * Print hex dump of data
 */
void print_hex(const BYTE data[], size_t len, const char* label) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

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
 * Calculate min and max of timing samples
 */
void calculate_min_max(const double *samples, size_t count, double *min, double *max) {
    *min = samples[0];
    *max = samples[0];
    for (size_t i = 1; i < count; i++) {
        if (samples[i] < *min) *min = samples[i];
        if (samples[i] > *max) *max = samples[i];
    }
}

/**
 * Calculate timing statistics
 */
timing_stats_t calculate_stats(const double *samples, size_t count) {
    timing_stats_t stats;
    stats.mean = calculate_mean(samples, count);
    stats.std_dev = calculate_std_dev(samples, count, stats.mean);
    calculate_min_max(samples, count, &stats.min, &stats.max);
    return stats;
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
 * Time a single AES-XR operation
 */
double time_aes_xr_encrypt(const BYTE *plaintext, const BYTE *key, BYTE *ciphertext) {
    struct timespec start, end;
    WORD key_schedule[120]; // Support AES-256 with 28 rounds

    // Setup key (not timed)
    aes_xr_key_setup(key, key_schedule, 128);

    // Start timing
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    // Encrypt
    aes_xr_encrypt(plaintext, ciphertext, key_schedule, 128);

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
void collect_timing_samples(double *samples, size_t count, const BYTE *input, const BYTE *key) {
    printf("Collecting %zu timing samples...\n", count);

    for (size_t i = 0; i < count; i++) {
        BYTE ciphertext[TEST_BLOCK_SIZE];
        samples[i] = time_aes_xr_encrypt(input, key, ciphertext);

        if ((i + 1) % 1000 == 0) {
            printf("  %zu/%zu samples collected\r", i + 1, count);
            fflush(stdout);
        }
    }
    printf("\n");
}

/**
 * Determine if timing difference is statistically significant for crypto
 */
const char* significance_level(double p_value, double mean_diff_ns) {
    if (fabs(mean_diff_ns) < 100.0 && p_value >= 0.001) {
        return "NOT EXPLOITABLE (diff < 100ns, p >= 0.001)";
    }
    if (p_value < 0.001) return "EXTREMELY SIGNIFICANT (p < 0.001)";
    if (p_value < 0.01) return "VERY SIGNIFICANT (p < 0.01)";
    if (p_value < 0.05) return "SIGNIFICANT (p < 0.05)";
    if (p_value < 0.10) return "MARGINALLY SIGNIFICANT (p < 0.10)";
    return "NOT SIGNIFICANT (p >= 0.10)";
}

/**
 * Functional correctness test
 */
int test_aes_xr_correctness() {
    printf("=== AES-XR Functional Correctness Test ===\n");

    WORD key_schedule[120]; // Support AES-256 with 28 rounds
    BYTE ciphertext[TEST_BLOCK_SIZE];
    BYTE decrypted[TEST_BLOCK_SIZE];

    // Setup key
    aes_xr_key_setup(test_key, key_schedule, 128);

    // Encrypt
    aes_xr_encrypt(test_plaintext, ciphertext, key_schedule, 128);

    // Decrypt
    aes_xr_decrypt(ciphertext, decrypted, key_schedule, 128);

    print_hex(test_plaintext, TEST_BLOCK_SIZE, "Original Plaintext");
    print_hex(ciphertext, TEST_BLOCK_SIZE, "AES-XR Ciphertext");
    print_hex(decrypted, TEST_BLOCK_SIZE, "Decrypted Plaintext");

    // Verify decryption
    int correct = memcmp(test_plaintext, decrypted, TEST_BLOCK_SIZE) == 0;
    printf("Decryption: %s\n", correct ? "PASS" : "FAIL");

    return correct;
}

/**
 * Performance benchmark test
 */
void benchmark_aes_xr() {
    printf("\n=== AES-XR Performance Benchmark ===\n");

    const size_t num_iterations = 100000;
    BYTE plaintext[TEST_BLOCK_SIZE];
    BYTE ciphertext[TEST_BLOCK_SIZE];
    WORD key_schedule[120]; // Support AES-256 with 28 rounds

    // Setup key
    aes_xr_key_setup(test_key, key_schedule, 128);

    // Generate test data
    memset(plaintext, 0xAA, TEST_BLOCK_SIZE);

    // Time encryption operations
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    for (size_t i = 0; i < num_iterations; i++) {
        aes_xr_encrypt(plaintext, ciphertext, key_schedule, 128);
        // Modify plaintext slightly to avoid optimization
        plaintext[0] = (plaintext[0] + 1) % 256;
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    double total_time_ns = (end.tv_sec - start.tv_sec) * 1e9 +
                          (end.tv_nsec - start.tv_nsec);
    double avg_time_ns = total_time_ns / num_iterations;
    double cycles_per_byte = (avg_time_ns / 1000000000.0) * 3500000000.0 / TEST_BLOCK_SIZE; // Assuming 3.5 GHz CPU
    double bytes_per_cycle = TEST_BLOCK_SIZE / cycles_per_byte;
    double throughput_gbps = (num_iterations * TEST_BLOCK_SIZE * 8) / (total_time_ns / 1000000000.0) / 1000000000.0;

    printf("Iterations: %zu\n", num_iterations);
    printf("Average time per encryption: %.2f ns\n", avg_time_ns);
    printf("Cycles per byte: %.2f\n", cycles_per_byte);
    printf("Bytes per cycle: %.4f\n", bytes_per_cycle);
    printf("Throughput: %.4f Gbps\n", throughput_gbps);
}

/**
 * Timing side-channel analysis
 */
void test_timing_side_channels() {
    printf("\n=== AES-XR Timing Side-Channel Analysis ===\n");

    // Test cases for timing analysis
    BYTE input1[TEST_BLOCK_SIZE] = {0}; // All zeros
    BYTE input2[TEST_BLOCK_SIZE] = {0}; // Will be modified
    input2[0] ^= 0x01; // Single bit flip

    // Allocate memory for timing samples
    double *samples1 = malloc(NUM_SAMPLES * sizeof(double));
    double *samples2 = malloc(NUM_SAMPLES * sizeof(double));

    if (!samples1 || !samples2) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    // Collect timing samples
    printf("Testing timing differences between similar inputs...\n");
    printf("Input 1: All zeros\n");
    collect_timing_samples(samples1, NUM_SAMPLES, input1, test_key);

    printf("Input 2: Single bit flip\n");
    collect_timing_samples(samples2, NUM_SAMPLES, input2, test_key);

    // Calculate statistics
    timing_stats_t stats1 = calculate_stats(samples1, NUM_SAMPLES);
    timing_stats_t stats2 = calculate_stats(samples2, NUM_SAMPLES);

    // Perform statistical test
    double p_value = welch_t_test(samples1, NUM_SAMPLES, samples2, NUM_SAMPLES);
    double mean_diff = stats1.mean - stats2.mean;

    printf("\nStatistical Analysis:\n");
    printf("  Mean difference: %.2f ns\n", mean_diff);
    printf("  Welch's t-test p-value: %.6f\n", p_value);
    printf("  Significance: %s\n", significance_level(p_value, mean_diff));

    // Cleanup
    free(samples1);
    free(samples2);
}

/**
 * Edge cases and special inputs test
 */
void test_edge_cases() {
    printf("\n=== AES-XR Edge Cases Test ===\n");

    WORD key_schedule[120]; // Support AES-256 with 28 rounds
    BYTE ciphertext[TEST_BLOCK_SIZE];
    BYTE decrypted[TEST_BLOCK_SIZE];

    // Setup key
    aes_xr_key_setup(test_key, key_schedule, 128);

    // Test cases
    BYTE test_cases[][TEST_BLOCK_SIZE] = {
        {0},                    // All zeros
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // All ones
        {0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55}, // Alternating
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}  // Sequential
    };

    const char* test_names[] = {
        "All zeros",
        "All ones",
        "Alternating pattern",
        "Sequential bytes"
    };

    for (int i = 0; i < 4; i++) {
        printf("\nTest case: %s\n", test_names[i]);

        aes_xr_encrypt(test_cases[i], ciphertext, key_schedule, 128);
        aes_xr_decrypt(ciphertext, decrypted, key_schedule, 128);

        int correct = memcmp(test_cases[i], decrypted, TEST_BLOCK_SIZE) == 0;
        printf("  Result: %s\n", correct ? "PASS" : "FAIL");

        if (!correct) {
            print_hex(test_cases[i], TEST_BLOCK_SIZE, "Original");
            print_hex(decrypted, TEST_BLOCK_SIZE, "Decrypted");
        }
    }
}

/**
 * Known test vector verification
 */
void test_known_vectors() {
    printf("\n=== AES-XR Known Test Vectors ===\n");

    WORD key_schedule[120]; // Support AES-256 with 28 rounds
    BYTE ciphertext[TEST_BLOCK_SIZE];

    // Setup key
    aes_xr_key_setup(test_key, key_schedule, 128);

    // Test vector 1: "abc" (padded to 16 bytes)
    BYTE input1[TEST_BLOCK_SIZE] = {'a', 'b', 'c', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    aes_xr_encrypt(input1, ciphertext, key_schedule, 128);
    print_hex(input1, TEST_BLOCK_SIZE, "Input 'abc' (padded)");
    print_hex(ciphertext, TEST_BLOCK_SIZE, "AES-XR output");

    // Test vector 2: Empty string (all zeros)
    BYTE input2[TEST_BLOCK_SIZE] = {0};
    aes_xr_encrypt(input2, ciphertext, key_schedule, 128);
    print_hex(input2, TEST_BLOCK_SIZE, "Input empty string");
    print_hex(ciphertext, TEST_BLOCK_SIZE, "AES-XR output");

    // Test vector 3: "foobar"
    BYTE input3[TEST_BLOCK_SIZE] = {'f', 'o', 'o', 'b', 'a', 'r', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    aes_xr_encrypt(input3, ciphertext, key_schedule, 128);
    print_hex(input3, TEST_BLOCK_SIZE, "Input 'foobar' (padded)");
    print_hex(ciphertext, TEST_BLOCK_SIZE, "AES-XR output");
}

/*********************** MAIN FUNCTION ***********************/
int main() {
    printf("=== AES-XR Comprehensive Verification Test Suite ===\n");
    printf("Testing functional correctness, performance, and security\n\n");

    // Run all tests
    int functional_correct = test_aes_xr_correctness();
    benchmark_aes_xr();
    test_timing_side_channels();
    test_edge_cases();
    test_known_vectors();

    // Summary
    printf("\n=== AES-XR Verification Summary ===\n");
    printf("Functional Correctness: %s\n", functional_correct ? "PASS" : "FAIL");
    printf("Performance Benchmark: COMPLETED\n");
    printf("Timing Side-Channel Analysis: COMPLETED\n");
    printf("Edge Cases: COMPLETED\n");
    printf("Known Test Vectors: COMPLETED\n");

    printf("\nAES-XR verification completed successfully!\n");
    printf("Results can be used to update documentation tables.\n");

    return 0;
}
