/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
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

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_90R_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

/*********************** SHA-256-90R FUNCTION DECLARATIONS **********************/
void sha256_90r_init(SHA256_90R_CTX *ctx);
void sha256_90r_update(SHA256_90R_CTX *ctx, const BYTE data[], size_t len);
void sha256_90r_final(SHA256_90R_CTX *ctx, BYTE hash[]);

/*********************** CONSTANT-TIME SCALAR IMPLEMENTATION **********************/
void sha256_90r_transform_scalar(SHA256_90R_CTX *ctx, const BYTE data[]);

/*********************** SIMD-ACCELERATED SHA-256-90R FUNCTIONS **********************/
#ifdef USE_SIMD
void sha256_90r_transform_simd(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_transform_avx2(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_transform_avx512(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_transform_neon(SHA256_90R_CTX *ctx, const BYTE data[]);
#endif

#ifdef USE_MULTIBLOCK_SIMD
void sha256_90r_transform_multiblock_simd(SHA256_90R_CTX ctxs[4], const BYTE data[4][64]);
#endif

/*********************** GPU-ACCELERATED FUNCTIONS **********************/
#ifdef USE_CUDA
cudaError_t sha256_90r_transform_cuda(SHA256_90R_CTX *ctx, const BYTE *data, size_t num_blocks);
#endif

/*********************** MULTI-BLOCK PARALLEL FUNCTIONS **********************/
void sha256_90r_transform_parallel(SHA256_90R_CTX *ctx, const BYTE data[], size_t num_blocks);
void sha256_90r_update_parallel(SHA256_90R_CTX *ctx, const BYTE data[], size_t len, int num_threads);

/*********************** TREE HASHING MODE **********************/
#ifdef USE_TREE_HASHING
// Tree context structure
typedef struct {
	size_t chunk_size;
	int max_threads;
	SHA256_90R_CTX **contexts;
	BYTE **intermediate_hashes;
	size_t num_chunks;
	size_t processed_bytes;
} SHA256_90R_TREE_CTX;

// BLAKE3-style tree hashing for large messages
void sha256_90r_tree_hash(const BYTE *data, size_t len, BYTE hash[], size_t chunk_size, int max_threads);
void sha256_90r_tree_hash_init(SHA256_90R_TREE_CTX *ctx, size_t chunk_size, int max_threads);
void sha256_90r_tree_hash_update(SHA256_90R_TREE_CTX *ctx, const BYTE *data, size_t len);
void sha256_90r_tree_hash_final(SHA256_90R_TREE_CTX *ctx, BYTE hash[]);
#endif

/*********************** SHA-NI HYBRID SUPPORT **********************/
#ifdef USE_SHA_NI
// SHA-NI accelerated transform (hybrid with software rounds)
void sha256_90r_transform_sha_ni(SHA256_90R_CTX *ctx, const BYTE data[]);
#endif

/*********************** FPGA PIPELINE PROTOTYPE **********************/
#ifdef USE_FPGA_PIPELINE
// FPGA pipeline simulation (90-stage hardware pipeline prototype)
void sha256_90r_transform_fpga(SHA256_90R_CTX *ctx, const BYTE data[]);
void print_fpga_analysis(void);
#endif

/*********************** JIT CODE GENERATION **********************/
#ifdef USE_JIT_CODEGEN
// Runtime-optimized JIT compilation for maximum performance
int sha256_90r_jit_init(void);
void sha256_90r_transform_jit(SHA256_90R_CTX *ctx, const BYTE data[]);
void sha256_90r_jit_cleanup(void);
const char* sha256_90r_jit_status(void);
#endif

#endif   // SHA256_H
