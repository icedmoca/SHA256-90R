/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Internal definitions for the legacy SHA-256 implementation.
*             This file is for internal use only - use sha256_90r.h for public API.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

/*********************** SHA-256-90R INTERNAL IMPLEMENTATION **********************/
// Internal context structure for SHA256-90R implementation
typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_90R_CTX;

// Internal function declarations (implementation details only)
void sha256_90r_init(SHA256_90R_CTX *ctx);
void sha256_90r_update(SHA256_90R_CTX *ctx, const BYTE data[], size_t len);
void sha256_90r_update_fast(SHA256_90R_CTX *ctx, const BYTE data[], size_t len);
void sha256_90r_final(SHA256_90R_CTX *ctx, BYTE hash[]);
void sha256_90r_transform(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_transform_scalar(SHA256_90R_CTX *ctx, const BYTE data[]);

#ifdef USE_SIMD
void sha256_90r_transform_simd(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_transform_avx2(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_transform_avx512(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_transform_neon(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_transform_avx2_4way(WORD states[4][8], const BYTE data[4][64]);
void sha256_90r_transform_avx2_8way(SHA256_90R_CTX ctxs[8], const BYTE data[8][64]);
#ifdef __AVX512F__
void sha256_90r_transform_avx512_16way(SHA256_90R_CTX ctxs[16], const BYTE data[16][64]);
#endif
#endif

#ifdef USE_MULTIBLOCK_SIMD
void sha256_90r_transform_multiblock_simd(SHA256_90R_CTX ctxs[4], const BYTE data[4][64]);
#endif

#ifdef USE_CUDA
cudaError_t sha256_90r_transform_cuda(SHA256_90R_CTX *ctx, const BYTE *data, size_t num_blocks);
#else
typedef int cudaError_t;
#define cudaSuccess 0
#endif

void sha256_90r_transform_pipelined(SHA256_90R_CTX *ctx, const BYTE data[], size_t num_blocks);
void sha256_90r_transform_parallel(SHA256_90R_CTX *ctx, const BYTE data[], size_t len, int num_threads);
void sha256_90r_update_parallel(SHA256_90R_CTX *ctx, const BYTE data[], size_t len, int num_threads);

#ifdef USE_TREE_HASHING
typedef struct {
	size_t chunk_size;
	int max_threads;
	SHA256_90R_CTX **contexts;
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
void sha256_90r_transform_sha_ni(SHA256_90R_CTX *ctx, const BYTE data[]);
#endif

#ifdef USE_ARMV8_CRYPTO
void sha256_90r_transform_armv8_crypto(SHA256_90R_CTX *ctx, const BYTE data[]);
#endif

#ifdef USE_FPGA_PIPELINE
void sha256_90r_transform_fpga(SHA256_90R_CTX *ctx, const BYTE data[]);
void print_fpga_analysis(void);
#endif

#ifdef USE_JIT_CODEGEN
int sha256_90r_jit_init(void);
void sha256_90r_transform_jit(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_jit_cleanup(void);
const char* sha256_90r_jit_status(void);
#endif

#endif   // SHA256_H