/*********************************************************************
* Filename:   sha256_internal.h
* Author:     SHA256-90R Development Team
* Copyright:  Public Domain
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Internal definitions for SHA256-90R implementation.
*             This file is for internal use only - use sha256_90r.h for public API.
*********************************************************************/

#ifndef SHA256_INTERNAL_H
#define SHA256_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/*************************** INTERNAL TYPES ***************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

// Internal context structure for SHA256-90R implementation
// Note: This defines the actual struct, while sha256_90r.h has the forward declaration
struct sha256_90r_internal_ctx {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
};

/*************************** INTERNAL FUNCTIONS ***********************/
// Internal function declarations (implementation details only)
// Note: Public API functions are declared in sha256_90r.h, not here
void sha256_90r_init_internal(struct sha256_90r_internal_ctx *ctx);
void sha256_90r_update_internal(struct sha256_90r_internal_ctx *ctx, const BYTE data[], size_t len);
void sha256_90r_update_fast(struct sha256_90r_internal_ctx *ctx, const BYTE data[], size_t len);
void sha256_90r_final_internal(struct sha256_90r_internal_ctx *ctx, BYTE hash[]);
void sha256_90r_transform(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
void sha256_90r_transform_scalar(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);

#ifdef USE_SIMD
void sha256_90r_transform_simd(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
void sha256_90r_transform_avx2(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
void sha256_90r_transform_avx512(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
void sha256_90r_transform_neon(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
void sha256_90r_transform_avx2_4way(WORD states[4][8], const BYTE data[4][64]);
void sha256_90r_transform_avx2_8way(struct sha256_90r_internal_ctx ctxs[8], const BYTE data[8][64]);
#ifdef __AVX512F__
void sha256_90r_transform_avx512_16way(struct sha256_90r_internal_ctx ctxs[16], const BYTE data[16][64]);
#endif
#endif

#ifdef USE_MULTIBLOCK_SIMD
void sha256_90r_transform_multiblock_simd(struct sha256_90r_internal_ctx ctxs[4], const BYTE data[4][64]);
#endif

#ifdef USE_CUDA
cudaError_t sha256_90r_transform_cuda(struct sha256_90r_internal_ctx *ctx, const BYTE *data, size_t num_blocks);
#else
typedef int cudaError_t;
#define cudaSuccess 0
#endif

void sha256_90r_transform_pipelined(struct sha256_90r_internal_ctx *ctx, const BYTE data[], size_t num_blocks);
void sha256_90r_transform_parallel(struct sha256_90r_internal_ctx *ctx, const BYTE data[], size_t len, int num_threads);
void sha256_90r_update_parallel(struct sha256_90r_internal_ctx *ctx, const BYTE data[], size_t len, int num_threads);

#ifdef USE_TREE_HASHING
typedef struct {
	size_t chunk_size;
	int max_threads;
	struct sha256_90r_internal_ctx **contexts;
	BYTE **intermediate_hashes;
	size_t num_chunks;
	size_t processed_bytes;
} SHA256_90R_TREE_CTX;

void sha256_90r_tree_hash(const BYTE *data, size_t len, BYTE hash[], size_t chunk_size, int max_threads);
void sha256_90r_tree_hash_init(SHA256_90R_TREE_CTX *ctx, size_t chunk_size, int max_threads);
void sha256_90r_tree_hash_update(SHA256_90R_TREE_CTX *ctx, const BYTE *data, size_t len);
void sha256_90r_tree_hash_final(SHA256_90R_TREE_CTX *ctx, BYTE hash[]);
#endif

#ifdef USE_SHA_NI
void sha256_90r_transform_sha_ni(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
#endif

#ifdef USE_ARMV8_CRYPTO
void sha256_90r_transform_armv8_crypto(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
#endif

#ifdef USE_FPGA_PIPELINE
void sha256_90r_transform_fpga(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
void print_fpga_analysis(void);
#endif

#ifdef USE_JIT_CODEGEN
int sha256_90r_jit_init(void);
void sha256_90r_transform_jit(struct sha256_90r_internal_ctx *ctx, const BYTE data[]);
void sha256_90r_jit_cleanup(void);
const char* sha256_90r_jit_status(void);
#endif

#endif /* SHA256_INTERNAL_H */
