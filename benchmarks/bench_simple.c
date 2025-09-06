#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "../src/sha256_90r/sha256_90r.h"

// Define BYTE for compatibility
typedef unsigned char BYTE;

#define TEST_SIZE (100 * 1024 * 1024) // 100 MB
#define BLOCK_SIZE 64

double now_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main() {
    uint8_t *data = (uint8_t *)malloc(TEST_SIZE);
    if (!data) {
        fprintf(stderr, "Failed to allocate %d MB\n", TEST_SIZE / (1024*1024));
        return 1;
    }

    memset(data, 0xAA, TEST_SIZE); // fixed pattern
    uint8_t hash[32];

    printf("SHA256-90R Simple Benchmark\n");
    printf("Input size: %.1f MB\n", TEST_SIZE / (1024.0*1024.0));

    // Use public API with acceleration enabled
    SHA256_90R_CTX *ctx = sha256_90r_new(SHA256_90R_MODE_ACCEL);

    double t0 = now_sec();
    sha256_90r_update(ctx, data, TEST_SIZE);
    sha256_90r_final(ctx, hash);
    double t1 = now_sec();

    sha256_90r_free(ctx);

    double secs = t1 - t0;
    double gbps = (TEST_SIZE * 8.0) / (secs * 1e9);

    printf("Processed %.1f MB in %.3f s = %.3f Gbps\n",
           TEST_SIZE / (1024.0*1024.0), secs, gbps);

    printf("Digest: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    free(data);
    return 0;
}
