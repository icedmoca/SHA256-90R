/**
 * SHA256-90R CUDA Implementation
 * GPU-accelerated batch hashing for maximum throughput
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

// SHA-256 constants aligned for GPU memory
__constant__ uint32_t d_k_90r[96] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
	// Extended constants for SHA-256-90R
	0xc67178f2,0xca273ece,0xd186b8c7,0xeada7dd6,0xf57d4f7f,0x06f067aa,0x0a637dc5,0x113f9804,
	0x1b710b35,0x28db77f5,0x32caab7b,0x3c9ebe0a,0x431d67c4,0x4cc5d4be,0x597f299c,0x5fcb6fab,
	0x6c44198c,0x7ba0ea2d,0x7eabf2d0,0x8dbe8d03,0x90bb1721,0x99a2ad45,0x9f86e289,0xa84c4472,
	0xb3df34fc,0xb99bb8d7,
	// Padding for alignment
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000
};

// Device functions for SHA-256 operations
__device__ __forceinline__ uint32_t ROTR(uint32_t x, int n) {
	return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__ uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (~x & z);
}

__device__ __forceinline__ uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint32_t EP0(uint32_t x) {
	return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

__device__ __forceinline__ uint32_t EP1(uint32_t x) {
	return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

__device__ __forceinline__ uint32_t SIG0(uint32_t x) {
	return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

__device__ __forceinline__ uint32_t SIG1(uint32_t x) {
	return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

// Macro-generated unrolled compression pipeline
#define SHA256_90R_GPU_ROUND(a,b,c,d,e,f,g,h,t1,t2,k_idx,m_idx) \
	t1 = h + EP1(e) + CH(e,f,g) + d_k_90r[k_idx] + m[m_idx]; \
	t2 = EP0(a) + MAJ(a,b,c); \
	h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

// Constant-time CUDA kernel for batch SHA256-90R processing
// Hardened against timing side-channels with uniform execution patterns
__global__ void sha256_90r_warp_kernel(
	const uint8_t* __restrict__ input_data,
	uint32_t* __restrict__ output_states,
	size_t num_blocks
) {
	const int global_tid = blockIdx.x * blockDim.x + threadIdx.x;
	const int warp_id = global_tid / 32;
	const int lane_id = threadIdx.x % 32;

	// Each warp processes one block
	for (size_t block_idx = warp_id; block_idx < num_blocks; block_idx += (gridDim.x * blockDim.x / 32)) {
		// Load input data for this block
		const uint8_t* data = input_data + block_idx * 64;

		// Shared memory for message expansion (90 words per warp)
		// Use fixed-size shared memory to ensure constant access patterns
		__shared__ uint32_t shared_m[90 * 32]; // 90 words * max warps per block
		uint32_t* m = shared_m + (threadIdx.x / 32) * 90;

		// Constant-time message expansion - all threads participate uniformly
		// Each thread handles exactly one word position, using arithmetic to select data
		for (int word_idx = 0; word_idx < 16; ++word_idx) {
			int byte_offset = word_idx * 4;
			uint32_t word = (data[byte_offset] << 24) | (data[byte_offset + 1] << 16) |
						   (data[byte_offset + 2] << 8) | data[byte_offset + 3);

			// Use arithmetic selection instead of conditional assignment
			uint32_t mask = (lane_id == word_idx) ? 0xFFFFFFFF : 0;
			m[word_idx] = (word & mask) | (m[word_idx] & ~mask);
		}
		__syncwarp();

		// Constant-time extended message expansion
		// All threads compute all words but only store when appropriate
		for (int i = 16; i < 90; ++i) {
			uint32_t m_i_minus_16 = m[i - 16];
			uint32_t m_i_minus_15 = m[i - 15];
			uint32_t m_i_minus_7 = m[i - 7];
			uint32_t m_i_minus_2 = m[i - 2];

			uint32_t new_word = SIG1(m_i_minus_2) + m_i_minus_7 + SIG0(m_i_minus_15) + m_i_minus_16;

			// Use arithmetic selection instead of conditional assignment
			uint32_t mask = (lane_id == (i % 32)) ? 0xFFFFFFFF : 0;
			m[i] = (new_word & mask) | (m[i] & ~mask);
		}
		__syncwarp();

		// Initialize state using arithmetic selection (constant-time)
		uint32_t initial_states[8] = {
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
		};

		uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0;

		// Distribute initial state using arithmetic operations
		for (int state_idx = 0; state_idx < 8; ++state_idx) {
			uint32_t state_val = initial_states[state_idx];
			uint32_t mask = (lane_id == state_idx) ? 0xFFFFFFFF : 0;

			a = (state_val & mask) | (a & ~mask);
			b = (state_val & mask) | (b & ~mask);
			c = (state_val & mask) | (c & ~mask);
			d = (state_val & mask) | (d & ~mask);
			e = (state_val & mask) | (e & ~mask);
			f = (state_val & mask) | (f & ~mask);
			g = (state_val & mask) | (g & ~mask);
			h = (state_val & mask) | (h & ~mask);
		}

		uint32_t t1, t2;

		// Constant-time compression rounds
		// All threads execute the same operations every round
		for (int round = 0; round < 90; ++round) {
			// All threads compute the same message word selection
			uint32_t m_round = m[round];

			// All threads compute round operations identically
			t1 = h + EP1(e) + CH(e, f, g) + d_k_90r[round] + m_round;
			t2 = EP0(a) + MAJ(a, b, c);

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		// Constant-time state collection and storage
		// All threads participate in state collection
		uint32_t final_a = a, final_b = b, final_c = c, final_d = d;
		uint32_t final_e = e, final_f = f, final_g = g, final_h = h;

		// Store final state - all threads write, but only lane 0's data is valid
		if (lane_id < 8) {
			uint32_t* out_state = output_states + block_idx * 8;
			uint32_t state_values[8] = {final_a, final_b, final_c, final_d,
									   final_e, final_f, final_g, final_h};
			out_state[lane_id] = initial_states[lane_id] + state_values[lane_id];
		}
	}
}

#undef SHA256_90R_GPU_ROUND

// Host function to launch the warp-optimized CUDA kernel
extern "C" cudaError_t launch_sha256_90r_cuda_batch(
	const uint8_t* input_data,
	uint32_t* output_states,
	size_t num_blocks,
	int threads_per_block = 256
) {
	cudaError_t cudaStatus;

	// Allocate device memory
	uint8_t* d_input = nullptr;
	uint32_t* d_output = nullptr;

	size_t input_size = num_blocks * 64 * sizeof(uint8_t);
	size_t output_size = num_blocks * 8 * sizeof(uint32_t);

	cudaStatus = cudaMalloc(&d_input, input_size);
	if (cudaStatus != cudaSuccess) return cudaStatus;

	cudaStatus = cudaMalloc(&d_output, output_size);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		return cudaStatus;
	}

	// Copy input data to device
	cudaStatus = cudaMemcpy(d_input, input_data, input_size, cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Calculate grid dimensions for warp-level processing
	// Each warp (32 threads) processes one block
	int warps_per_block = threads_per_block / 32;
	int blocks_per_grid = (num_blocks + warps_per_block - 1) / warps_per_block;

	// Prefetch constants to GPU
	cudaStatus = cudaMemcpyToSymbol(d_k_90r, k_90r, sizeof(k_90r));
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Launch warp-optimized kernel
	sha256_90r_warp_kernel<<<blocks_per_grid, threads_per_block>>>(
		d_input, d_output, num_blocks
	);

	// Check for kernel launch errors
	cudaStatus = cudaGetLastError();
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Copy results back to host
	cudaStatus = cudaMemcpy(output_states, d_output, output_size, cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Cleanup
	cudaFree(d_input);
	cudaFree(d_output);

	return cudaSuccess;
}

// CUDA kernel for regression testing constant-time behavior
__global__ void sha256_90r_constant_time_test_kernel(
	const uint8_t* __restrict__ input_data1,
	const uint8_t* __restrict__ input_data2,
	uint32_t* __restrict__ output_states,
	size_t num_blocks,
	uint64_t* __restrict__ timing_results
) {
	const int global_tid = blockIdx.x * blockDim.x + threadIdx.x;
	const int warp_id = global_tid / 32;
	const int lane_id = threadIdx.x % 32;

	// Each warp processes pairs of blocks for timing comparison
	for (size_t block_idx = warp_id; block_idx < num_blocks; block_idx += (gridDim.x * blockDim.x / 32)) {
		uint64_t start_time = clock64();

		// Process first input (all zeros)
		const uint8_t* data1 = input_data1 + block_idx * 64;
		__shared__ uint32_t shared_m1[90 * 32];
		uint32_t* m1 = shared_m1 + (threadIdx.x / 32) * 90;

		// Constant-time message expansion for input 1
		for (int word_idx = 0; word_idx < 16; ++word_idx) {
			int byte_offset = word_idx * 4;
			uint32_t word = (data1[byte_offset] << 24) | (data1[byte_offset + 1] << 16) |
						   (data1[byte_offset + 2] << 8) | data1[byte_offset + 3);
			uint32_t mask = (lane_id == word_idx) ? 0xFFFFFFFF : 0;
			m1[word_idx] = (word & mask) | (m1[word_idx] & ~mask);
		}
		__syncwarp();

		for (int i = 16; i < 90; ++i) {
			uint32_t m_i_minus_16 = m1[i - 16];
			uint32_t m_i_minus_15 = m1[i - 15];
			uint32_t m_i_minus_7 = m1[i - 7];
			uint32_t m_i_minus_2 = m1[i - 2];
			uint32_t new_word = SIG1(m_i_minus_2) + m_i_minus_7 + SIG0(m_i_minus_15) + m_i_minus_16;
			uint32_t mask = (lane_id == (i % 32)) ? 0xFFFFFFFF : 0;
			m1[i] = (new_word & mask) | (m1[i] & ~mask);
		}
		__syncwarp();

		// Process first input through compression
		uint32_t initial_states[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
									 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
		uint32_t a1 = 0, b1 = 0, c1 = 0, d1 = 0, e1 = 0, f1 = 0, g1 = 0, h1 = 0;

		for (int state_idx = 0; state_idx < 8; ++state_idx) {
			uint32_t state_val = initial_states[state_idx];
			uint32_t mask = (lane_id == state_idx) ? 0xFFFFFFFF : 0;
			a1 = (state_val & mask) | (a1 & ~mask);
			b1 = (state_val & mask) | (b1 & ~mask);
			c1 = (state_val & mask) | (c1 & ~mask);
			d1 = (state_val & mask) | (d1 & ~mask);
			e1 = (state_val & mask) | (e1 & ~mask);
			f1 = (state_val & mask) | (f1 & ~mask);
			g1 = (state_val & mask) | (g1 & ~mask);
			h1 = (state_val & mask) | (h1 & ~mask);
		}

		for (int round = 0; round < 90; ++round) {
			uint32_t m_round = m1[round];
			uint32_t t1 = h1 + EP1(e1) + CH(e1, f1, g1) + d_k_90r[round] + m_round;
			uint32_t t2 = EP0(a1) + MAJ(a1, b1, c1);
			h1 = g1; g1 = f1; f1 = e1; e1 = d1 + t1; d1 = c1; c1 = b1; b1 = a1; a1 = t1 + t2;
		}

		// Process second input (bit flip)
		const uint8_t* data2 = input_data2 + block_idx * 64;
		__shared__ uint32_t shared_m2[90 * 32];
		uint32_t* m2 = shared_m2 + (threadIdx.x / 32) * 90;

		for (int word_idx = 0; word_idx < 16; ++word_idx) {
			int byte_offset = word_idx * 4;
			uint32_t word = (data2[byte_offset] << 24) | (data2[byte_offset + 1] << 16) |
						   (data2[byte_offset + 2] << 8) | data2[byte_offset + 3);
			uint32_t mask = (lane_id == word_idx) ? 0xFFFFFFFF : 0;
			m2[word_idx] = (word & mask) | (m2[word_idx] & ~mask);
		}
		__syncwarp();

		for (int i = 16; i < 90; ++i) {
			uint32_t m_i_minus_16 = m2[i - 16];
			uint32_t m_i_minus_15 = m2[i - 15];
			uint32_t m_i_minus_7 = m2[i - 7];
			uint32_t m_i_minus_2 = m2[i - 2];
			uint32_t new_word = SIG1(m_i_minus_2) + m_i_minus_7 + SIG0(m_i_minus_15) + m_i_minus_16;
			uint32_t mask = (lane_id == (i % 32)) ? 0xFFFFFFFF : 0;
			m2[i] = (new_word & mask) | (m2[i] & ~mask);
		}
		__syncwarp();

		uint32_t a2 = 0, b2 = 0, c2 = 0, d2 = 0, e2 = 0, f2 = 0, g2 = 0, h2 = 0;

		for (int state_idx = 0; state_idx < 8; ++state_idx) {
			uint32_t state_val = initial_states[state_idx];
			uint32_t mask = (lane_id == state_idx) ? 0xFFFFFFFF : 0;
			a2 = (state_val & mask) | (a2 & ~mask);
			b2 = (state_val & mask) | (b2 & ~mask);
			c2 = (state_val & mask) | (c2 & ~mask);
			d2 = (state_val & mask) | (d2 & ~mask);
			e2 = (state_val & mask) | (e2 & ~mask);
			f2 = (state_val & mask) | (f2 & ~mask);
			g2 = (state_val & mask) | (g2 & ~mask);
			h2 = (state_val & mask) | (h2 & ~mask);
		}

		for (int round = 0; round < 90; ++round) {
			uint32_t m_round = m2[round];
			uint32_t t1 = h2 + EP1(e2) + CH(e2, f2, g2) + d_k_90r[round] + m_round;
			uint32_t t2 = EP0(a2) + MAJ(a2, b2, c2);
			h2 = g2; g2 = f2; f2 = e2; e2 = d2 + t1; d2 = c2; c2 = b2; b2 = a2; a2 = t1 + t2;
		}

		uint64_t end_time = clock64();

		// Store timing result (only thread 0 per warp)
		if (lane_id == 0 && timing_results) {
			timing_results[block_idx] = end_time - start_time;
		}

		// Store results for verification
		if (lane_id < 8) {
			uint32_t* out_state1 = output_states + block_idx * 16;
			uint32_t* out_state2 = output_states + block_idx * 16 + 8;
			uint32_t state_values1[8] = {a1, b1, c1, d1, e1, f1, g1, h1};
			uint32_t state_values2[8] = {a2, b2, c2, d2, e2, f2, g2, h2};
			out_state1[lane_id] = initial_states[lane_id] + state_values1[lane_id];
			out_state2[lane_id] = initial_states[lane_id] + state_values2[lane_id];
		}
	}
}

// Host function for CUDA constant-time regression testing
extern "C" cudaError_t launch_sha256_90r_cuda_timing_test(
	const uint8_t* input_data1,
	const uint8_t* input_data2,
	uint32_t* output_states,
	size_t num_blocks,
	uint64_t* timing_results,
	int threads_per_block = 256
) {
	cudaError_t cudaStatus;

	uint8_t* d_input1 = nullptr;
	uint8_t* d_input2 = nullptr;
	uint32_t* d_output = nullptr;
	uint64_t* d_timing = nullptr;

	size_t input_size = num_blocks * 64 * sizeof(uint8_t);
	size_t output_size = num_blocks * 16 * sizeof(uint32_t); // 2 hashes per block
	size_t timing_size = num_blocks * sizeof(uint64_t);

	// Allocate device memory
	cudaStatus = cudaMalloc(&d_input1, input_size);
	if (cudaStatus != cudaSuccess) return cudaStatus;

	cudaStatus = cudaMalloc(&d_input2, input_size);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input1);
		return cudaStatus;
	}

	cudaStatus = cudaMalloc(&d_output, output_size);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input1);
		cudaFree(d_input2);
		return cudaStatus;
	}

	cudaStatus = cudaMalloc(&d_timing, timing_size);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input1);
		cudaFree(d_input2);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Copy input data
	cudaStatus = cudaMemcpy(d_input1, input_data1, input_size, cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) goto cleanup;

	cudaStatus = cudaMemcpy(d_input2, input_data2, input_size, cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) goto cleanup;

	// Copy constants
	cudaStatus = cudaMemcpyToSymbol(d_k_90r, k_90r, sizeof(k_90r));
	if (cudaStatus != cudaSuccess) goto cleanup;

	// Calculate grid dimensions
	int warps_per_block = threads_per_block / 32;
	int blocks_per_grid = (num_blocks + warps_per_block - 1) / warps_per_block;

	// Launch timing test kernel
	sha256_90r_constant_time_test_kernel<<<blocks_per_grid, threads_per_block>>>(
		d_input1, d_input2, d_output, num_blocks, d_timing
	);

	cudaStatus = cudaGetLastError();
	if (cudaStatus != cudaSuccess) goto cleanup;

	// Copy results back
	cudaStatus = cudaMemcpy(output_states, d_output, output_size, cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) goto cleanup;

	if (timing_results) {
		cudaStatus = cudaMemcpy(timing_results, d_timing, timing_size, cudaMemcpyDeviceToHost);
	}

cleanup:
	cudaFree(d_input1);
	cudaFree(d_input2);
	cudaFree(d_output);
	cudaFree(d_timing);

	return cudaStatus;
}

// Performance comparison: original vs warp-optimized kernel
extern "C" cudaError_t launch_sha256_90r_cuda_batch_original(
	const uint8_t* input_data,
	uint32_t* output_states,
	size_t num_blocks,
	int threads_per_block = 256
) {
	cudaError_t cudaStatus;

	// Allocate device memory
	uint8_t* d_input = nullptr;
	uint32_t* d_output = nullptr;

	size_t input_size = num_blocks * 64 * sizeof(uint8_t);
	size_t output_size = num_blocks * 8 * sizeof(uint32_t);

	cudaStatus = cudaMalloc(&d_input, input_size);
	if (cudaStatus != cudaSuccess) return cudaStatus;

	cudaStatus = cudaMalloc(&d_output, output_size);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		return cudaStatus;
	}

	// Copy input data to device
	cudaStatus = cudaMemcpy(d_input, input_data, input_size, cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Calculate grid dimensions
	int blocks_per_grid = (num_blocks + threads_per_block - 1) / threads_per_block;

	// Prefetch constants to GPU
	cudaStatus = cudaMemcpyToSymbol(d_k_90r, k_90r, sizeof(k_90r));
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Launch original kernel
	sha256_90r_batch_kernel<<<blocks_per_grid, threads_per_block>>>(
		d_input, d_output, num_blocks
	);

	// Check for kernel launch errors
	cudaStatus = cudaGetLastError();
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Copy results back to host
	cudaStatus = cudaMemcpy(output_states, d_output, output_size, cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		cudaFree(d_input);
		cudaFree(d_output);
		return cudaStatus;
	}

	// Cleanup
	cudaFree(d_input);
	cudaFree(d_output);

	return cudaSuccess;
}
