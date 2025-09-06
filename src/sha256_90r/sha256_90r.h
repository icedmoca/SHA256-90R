/*********************************************************************
* Filename:   sha256_90r.h
* Author:     SHA256-90R Development Team
* Copyright:  Public Domain
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Public API for SHA256-90R extended round hash function
*********************************************************************/

#ifndef SHA256_90R_PUBLIC_H
#define SHA256_90R_PUBLIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*************************** DEFINES ***************************/
#define SHA256_90R_BLOCK_SIZE 32            // Output size: 256 bits / 8 = 32 bytes
#define SHA256_90R_DIGEST_SIZE 32           // Same as block size for SHA-256
#define SHA256_90R_STATE_SIZE 8             // 8 x 32-bit words

/*************************** TYPES ****************************/
/* Opaque context structure - implementation details hidden */
typedef struct sha256_90r_ctx SHA256_90R_CTX;

/* Operation modes */
typedef enum {
    SHA256_90R_MODE_SECURE = 0,      // Constant-time, side-channel resistant
    SHA256_90R_MODE_ACCEL = 1,       // Hardware accelerated (may leak timing)
    SHA256_90R_MODE_FAST = 2         // Maximum performance (no security guarantees)
} sha256_90r_mode_t;

/* Backend selection */
typedef enum {
    SHA256_90R_BACKEND_AUTO = 0,     // Automatic selection based on CPU
    SHA256_90R_BACKEND_SCALAR = 1,   // Portable C implementation
    SHA256_90R_BACKEND_SIMD = 2,     // SIMD (AVX2/NEON) optimized
    SHA256_90R_BACKEND_SHA_NI = 3,   // Intel SHA extensions
    SHA256_90R_BACKEND_GPU = 4,      // GPU acceleration (if available)
    SHA256_90R_BACKEND_FPGA = 5,     // FPGA acceleration (if available)
    SHA256_90R_BACKEND_JIT = 6       // JIT compiled (if available)
} sha256_90r_backend_t;

/*************************** CORE API ***************************/

/* Initialize library and detect CPU features */
int sha256_90r_init_library(void);

/* Create a new context with specified mode */
SHA256_90R_CTX* sha256_90r_new(sha256_90r_mode_t mode);

/* Create a new context with specific backend */
SHA256_90R_CTX* sha256_90r_new_backend(sha256_90r_backend_t backend);

/* Free a context */
void sha256_90r_free(SHA256_90R_CTX* ctx);

/* Reset context for new hash */
void sha256_90r_reset(SHA256_90R_CTX* ctx);

/* Update hash with data */
void sha256_90r_update(SHA256_90R_CTX* ctx, const uint8_t* data, size_t len);

/* Finalize hash and get result */
void sha256_90r_final(SHA256_90R_CTX* ctx, uint8_t hash[SHA256_90R_DIGEST_SIZE]);

/* One-shot hashing */
void sha256_90r_hash(const uint8_t* data, size_t len, uint8_t hash[SHA256_90R_DIGEST_SIZE]);

/* One-shot hashing with mode selection */
void sha256_90r_hash_mode(const uint8_t* data, size_t len, uint8_t hash[SHA256_90R_DIGEST_SIZE], 
                          sha256_90r_mode_t mode);

/*************************** BATCH API ***************************/

/* Process multiple messages in parallel (for GPU/SIMD backends) */
void sha256_90r_batch(const uint8_t** messages, const size_t* lengths, 
                      uint8_t** hashes, size_t count, sha256_90r_mode_t mode);

/*************************** UTILITY API *************************/

/* Get version string */
const char* sha256_90r_version(void);

/* Get backend name for context */
const char* sha256_90r_backend_name(const SHA256_90R_CTX* ctx);

/* Check if backend is available */
int sha256_90r_backend_available(sha256_90r_backend_t backend);

/* Get performance estimate (Gbps) for backend */
double sha256_90r_backend_performance(sha256_90r_backend_t backend);

/* Run self-test */
int sha256_90r_selftest(void);

/* Run timing test (returns timing variance in nanoseconds) */
double sha256_90r_timing_test(sha256_90r_mode_t mode, int iterations);

#ifdef __cplusplus
}
#endif

#endif /* SHA256_90R_PUBLIC_H */
