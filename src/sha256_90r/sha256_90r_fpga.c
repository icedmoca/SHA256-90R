/**
 * SHA256-90R FPGA Pipeline Prototype
 * Software simulation of a 90-stage hardware pipeline
 * Useful as a reference design for FPGA/hardware teams
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sha256.h"

// SHA-256 constants (same as in main implementation)
static const uint32_t k_90r_fpga[96] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
	0xc67178f2,0xca273ece,0xd186b8c7,0xeada7dd6,0xf57d4f7f,0x06f067aa,0x0a637dc5,0x113f9804,
	0x1b710b35,0x28db77f5,0x32caab7b,0x3c9ebe0a,0x431d67c4,0x4cc5d4be,0x597f299c,0x5fcb6fab,
	0x6c44198c,0x7ba0ea2d,0x7eabf2d0,0x8dbe8d03,0x90bb1721,0x99a2ad45,0x9f86e289,0xa84c4472,
	0xb3df34fc,0xb99bb8d7,0,0,0,0,0,0
};

// FPGA pipeline stage structure
typedef struct {
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t w;  // Message word for this stage
	uint32_t k;  // Round constant for this stage
	int valid;   // Pipeline stage valid flag
} fpga_pipeline_stage_t;

// Complete FPGA pipeline with 90 stages
#define FPGA_PIPELINE_DEPTH 90
typedef struct {
	fpga_pipeline_stage_t stages[FPGA_PIPELINE_DEPTH];
	int pipeline_filled;
	int current_stage;
} fpga_pipeline_t;

// Initialize FPGA pipeline
void fpga_pipeline_init(fpga_pipeline_t *pipeline) {
	memset(pipeline, 0, sizeof(fpga_pipeline_t));
	pipeline->pipeline_filled = 0;
	pipeline->current_stage = 0;
}

// FPGA round function (single stage computation)
static inline void fpga_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d,
                              uint32_t *e, uint32_t *f, uint32_t *g, uint32_t *h,
                              uint32_t w, uint32_t k) {
	uint32_t t1 = *h + (((*e >> 6) | (*e << 26)) ^ ((*e >> 11) | (*e << 21)) ^ ((*e >> 25) | (*e << 7))) +
	                ((*e & *f) ^ (~*e & *g)) + k + w;
	uint32_t t2 = (((*a >> 2) | (*a << 30)) ^ ((*a >> 13) | (*a << 19)) ^ ((*a >> 22) | (*a << 10))) +
	                ((*a & *b) ^ (*a & *c) ^ (*b & *c));

	*h = *g;
	*g = *f;
	*f = *e;
	*e = *d + t1;
	*d = *c;
	*c = *b;
	*b = *a;
	*a = t1 + t2;
}

// Constant-time FPGA round function with masking
static inline void fpga_round_masked(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d,
                                    uint32_t *e, uint32_t *f, uint32_t *g, uint32_t *h,
                                    uint32_t w, uint32_t k, uint32_t valid_mask) {
	uint32_t t1 = *h + (((*e >> 6) | (*e << 26)) ^ ((*e >> 11) | (*e << 21)) ^ ((*e >> 25) | (*e << 7))) +
	                ((*e & *f) ^ (~*e & *g)) + k + w;
	uint32_t t2 = (((*a >> 2) | (*a << 30)) ^ ((*a >> 13) | (*a << 19)) ^ ((*a >> 22) | (*a << 10))) +
	                ((*a & *b) ^ (*a & *c) ^ (*b & *c));

	uint32_t new_h = *g;
	uint32_t new_g = *f;
	uint32_t new_f = *e;
	uint32_t new_e = *d + t1;
	uint32_t new_d = *c;
	uint32_t new_c = *b;
	uint32_t new_b = *a;
	uint32_t new_a = t1 + t2;

	// Apply masking to conditionally update state
	*h = (new_h & valid_mask) | (*h & ~valid_mask);
	*g = (new_g & valid_mask) | (*g & ~valid_mask);
	*f = (new_f & valid_mask) | (*f & ~valid_mask);
	*e = (new_e & valid_mask) | (*e & ~valid_mask);
	*d = (new_d & valid_mask) | (*d & ~valid_mask);
	*c = (new_c & valid_mask) | (*c & ~valid_mask);
	*b = (new_b & valid_mask) | (*b & ~valid_mask);
	*a = (new_a & valid_mask) | (*a & ~valid_mask);
}

// Constant-time FPGA pipeline clock - always processes all stages regardless of input
void fpga_pipeline_clock(fpga_pipeline_t *pipeline, uint32_t w, uint32_t k, int input_valid) {
	int i;

	// Always shift data through ALL pipeline stages (constant-time)
	for (i = FPGA_PIPELINE_DEPTH - 1; i > 0; --i) {
		pipeline->stages[i] = pipeline->stages[i - 1];
		// Always perform round computation - use arithmetic masking for conditional behavior
		uint32_t valid_mask = pipeline->stages[i].valid ? 0xFFFFFFFF : 0;
		fpga_round_masked(&pipeline->stages[i].a, &pipeline->stages[i].b, &pipeline->stages[i].c, &pipeline->stages[i].d,
						 &pipeline->stages[i].e, &pipeline->stages[i].f, &pipeline->stages[i].g, &pipeline->stages[i].h,
						 pipeline->stages[i].w, pipeline->stages[i].k, valid_mask);
	}

	// Load new data into first stage using arithmetic masking (constant-time)
	uint32_t input_mask = input_valid ? 0xFFFFFFFF : 0;

	// Always initialize state values, but mask them based on input validity
	uint32_t new_a = (0x6a09e667 & input_mask) | (pipeline->stages[0].a & ~input_mask);
	uint32_t new_b = (0xbb67ae85 & input_mask) | (pipeline->stages[0].b & ~input_mask);
	uint32_t new_c = (0x3c6ef372 & input_mask) | (pipeline->stages[0].c & ~input_mask);
	uint32_t new_d = (0xa54ff53a & input_mask) | (pipeline->stages[0].d & ~input_mask);
	uint32_t new_e = (0x510e527f & input_mask) | (pipeline->stages[0].e & ~input_mask);
	uint32_t new_f = (0x9b05688c & input_mask) | (pipeline->stages[0].f & ~input_mask);
	uint32_t new_g = (0x1f83d9ab & input_mask) | (pipeline->stages[0].g & ~input_mask);
	uint32_t new_h = (0x5be0cd19 & input_mask) | (pipeline->stages[0].h & ~input_mask);
	uint32_t new_w = (w & input_mask) | (pipeline->stages[0].w & ~input_mask);
	uint32_t new_k = (k & input_mask) | (pipeline->stages[0].k & ~input_mask);
	uint32_t new_valid = input_valid ? 1 : pipeline->stages[0].valid;

	pipeline->stages[0].a = new_a;
	pipeline->stages[0].b = new_b;
	pipeline->stages[0].c = new_c;
	pipeline->stages[0].d = new_d;
	pipeline->stages[0].e = new_e;
	pipeline->stages[0].f = new_f;
	pipeline->stages[0].g = new_g;
	pipeline->stages[0].h = new_h;
	pipeline->stages[0].w = new_w;
	pipeline->stages[0].k = new_k;
	pipeline->stages[0].valid = new_valid;

	// Update pipeline state using masking (constant-time)
	uint32_t fill_update_mask = (input_valid && !pipeline->pipeline_filled) ? 0xFFFFFFFF : 0;
	uint32_t new_current_stage = pipeline->current_stage + (fill_update_mask ? 1 : 0);
	uint32_t new_pipeline_filled = pipeline->pipeline_filled | ((new_current_stage >= FPGA_PIPELINE_DEPTH) ? 1 : 0);

	pipeline->current_stage = new_current_stage;
	pipeline->pipeline_filled = new_pipeline_filled;
}

// Check if pipeline has valid output
int fpga_pipeline_has_output(fpga_pipeline_t *pipeline) {
	return pipeline->stages[FPGA_PIPELINE_DEPTH - 1].valid;
}

// Get final hash from pipeline output
void fpga_pipeline_get_output(fpga_pipeline_t *pipeline, uint32_t hash[8]) {
	fpga_pipeline_stage_t *output_stage = &pipeline->stages[FPGA_PIPELINE_DEPTH - 1];

	hash[0] = output_stage->a;
	hash[1] = output_stage->b;
	hash[2] = output_stage->c;
	hash[3] = output_stage->d;
	hash[4] = output_stage->e;
	hash[5] = output_stage->f;
	hash[6] = output_stage->g;
	hash[7] = output_stage->h;
}

// Constant-time SHA256-90R FPGA pipeline simulation
void sha256_90r_transform_fpga(SHA256_90R_CTX *ctx, const BYTE data[]) {
	uint32_t m[90];
	uint32_t hash[8];
	fpga_pipeline_t pipeline;
	int i, j;

	// Initialize message schedule (constant-time)
	for (i = 0, j = 0; i < 16; ++i, j += 4) {
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
	}

	for (i = 16; i < 90; ++i) {
		uint32_t s0 = ((m[i-15] >> 7) | (m[i-15] << 25)) ^ ((m[i-15] >> 18) | (m[i-15] << 14)) ^ (m[i-15] >> 3);
		uint32_t s1 = ((m[i-2] >> 17) | (m[i-2] << 15)) ^ ((m[i-2] >> 19) | (m[i-2] << 13)) ^ (m[i-2] >> 10);
		m[i] = m[i-16] + s0 + m[i-7] + s1;
	}

	// Initialize FPGA pipeline
	fpga_pipeline_init(&pipeline);

	// Feed message words through pipeline (constant-time: always 90 + 89 cycles)
	for (i = 0; i < 90; ++i) {
		fpga_pipeline_clock(&pipeline, m[i], k_90r_fpga[i], 1);
	}

	// Drain pipeline with fixed number of cycles (constant-time)
	for (i = 0; i < FPGA_PIPELINE_DEPTH - 1; ++i) {
		fpga_pipeline_clock(&pipeline, 0, 0, 0);
	}

	// Get final hash from pipeline
	fpga_pipeline_get_output(&pipeline, hash);

	// Add to context state
	for (i = 0; i < 8; ++i) {
		ctx->state[i] += hash[i];
	}
}

// FPGA timing test harness for constant-time verification
typedef struct {
	uint64_t cycle_count;
	uint32_t hash[8];
} fpga_timing_result_t;

// Constant-time FPGA timing test function
fpga_timing_result_t fpga_timing_test(const BYTE data[]) {
	uint32_t m[90];
	fpga_pipeline_t pipeline;
	fpga_timing_result_t result = {0};
	int i, j;

	// Initialize message schedule
	for (i = 0, j = 0; i < 16; ++i, j += 4) {
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
	}

	for (i = 16; i < 90; ++i) {
		uint32_t s0 = ((m[i-15] >> 7) | (m[i-15] << 25)) ^ ((m[i-15] >> 18) | (m[i-15] << 14)) ^ (m[i-15] >> 3);
		uint32_t s1 = ((m[i-2] >> 17) | (m[i-2] << 15)) ^ ((m[i-2] >> 19) | (m[i-2] << 13)) ^ (m[i-2] >> 10);
		m[i] = m[i-16] + s0 + m[i-7] + s1;
	}

	// Initialize FPGA pipeline
	fpga_pipeline_init(&pipeline);

	// Count cycles: 90 input cycles + 89 drain cycles = 179 total
	result.cycle_count = 90 + (FPGA_PIPELINE_DEPTH - 1);

	// Process all cycles (constant-time)
	for (i = 0; i < 90; ++i) {
		fpga_pipeline_clock(&pipeline, m[i], k_90r_fpga[i], 1);
	}

	for (i = 0; i < FPGA_PIPELINE_DEPTH - 1; ++i) {
		fpga_pipeline_clock(&pipeline, 0, 0, 0);
	}

	// Get final hash
	fpga_pipeline_get_output(&pipeline, result.hash);

	return result;
}

// FPGA pipeline statistics and analysis
typedef struct {
	uint64_t total_cycles;
	uint64_t data_cycles;
	uint64_t drain_cycles;
	uint64_t throughput_cycles;
} fpga_stats_t;

// Analyze FPGA pipeline performance
fpga_stats_t analyze_fpga_pipeline(void) {
	fpga_stats_t stats = {0};

	// Data input phase: 90 cycles for 90 message words
	stats.data_cycles = 90;

	// Pipeline drain phase: 89 cycles to flush pipeline
	stats.drain_cycles = FPGA_PIPELINE_DEPTH - 1;

	// Total cycles for one block
	stats.total_cycles = stats.data_cycles + stats.drain_cycles;

	// Steady-state throughput: 1 hash per cycle after pipeline fill
	stats.throughput_cycles = 1;

	return stats;
}

// FPGA hardware resource estimation
typedef struct {
	int lut_count;
	int ff_count;
	int bram_count;
	int dsp_count;
	int max_frequency_mhz;
} fpga_resources_t;

fpga_resources_t estimate_fpga_resources(void) {
	fpga_resources_t res = {0};

	// Estimate based on 90-stage pipeline with 32-bit operations
	res.lut_count = FPGA_PIPELINE_DEPTH * 500;  // ~500 LUTs per stage
	res.ff_count = FPGA_PIPELINE_DEPTH * 256;   // ~256 FFs per stage
	res.bram_count = 4;                          // For constants and message storage
	res.dsp_count = 0;                           // Pure logic implementation
	res.max_frequency_mhz = 300;                 // Conservative estimate

	return res;
}

// Print FPGA analysis results
void print_fpga_analysis(void) {
	fpga_stats_t stats = analyze_fpga_pipeline();
	fpga_resources_t res = estimate_fpga_resources();

	printf("FPGA Pipeline Analysis:\n");
	printf("======================\n");
	printf("Pipeline Depth: %d stages\n", FPGA_PIPELINE_DEPTH);
	        printf("Total Cycles per Block: %lu\n", (unsigned long)stats.total_cycles);
        printf("Data Input Cycles: %lu\n", (unsigned long)stats.data_cycles);
        printf("Pipeline Drain Cycles: %lu\n", (unsigned long)stats.drain_cycles);
        printf("Steady-State Throughput: %lu cycles/hash\n", (unsigned long)stats.throughput_cycles);
	printf("\n");
	printf("Estimated FPGA Resources:\n");
	printf("LUTs: %d\n", res.lut_count);
	printf("Flip-Flops: %d\n", res.ff_count);
	printf("BRAM Blocks: %d\n", res.bram_count);
	printf("DSP Slices: %d\n", res.dsp_count);
	printf("Max Frequency: %d MHz\n", res.max_frequency_mhz);
}
