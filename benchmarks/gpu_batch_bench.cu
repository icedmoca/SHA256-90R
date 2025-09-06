/*********************************************************************
* GPU Batch Benchmark for SHA256-90R
* Tests scaling with 100k+ concurrent messages
*********************************************************************/

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// SHA256-90R constants
#define SHA256_90R_ROUNDS 90
#define BLOCK_SIZE 64
#define DIGEST_SIZE 32

// GPU configuration
#define THREADS_PER_BLOCK 256
#define MAX_BLOCKS 65535

// Device constants
__constant__ uint32_t d_k[96];

// SHA256-90R device functions
__device__ uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__device__ uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

__device__ uint32_t ep0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

__device__ uint32_t ep1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

// SHA256-90R kernel - processes one message per thread
__global__ void sha256_90r_batch_kernel(const uint8_t* messages, uint32_t* hashes, int num_messages) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_messages) return;
    
    // Initialize state
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Load message (simplified - assumes 64-byte messages)
    uint32_t w[96];
    const uint8_t* msg = messages + idx * BLOCK_SIZE;
    
    // Load and byte swap
    #pragma unroll 16
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)msg[i*4] << 24) | ((uint32_t)msg[i*4+1] << 16) |
               ((uint32_t)msg[i*4+2] << 8) | (uint32_t)msg[i*4+3];
    }
    
    // Message expansion
    #pragma unroll
    for (int i = 16; i < 90; i++) {
        w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
    }
    
    // Compression
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    
    #pragma unroll
    for (int i = 0; i < 90; i++) {
        uint32_t t1 = h + ep1(e) + ch(e, f, g) + d_k[i] + w[i];
        uint32_t t2 = ep0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    // Store final state
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    
    // Write output
    uint32_t* out = hashes + idx * 8;
    #pragma unroll 8
    for (int i = 0; i < 8; i++) {
        out[i] = state[i];
    }
}

// Host constants
const uint32_t k_host[96] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    // Extended for rounds 64-89
    0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,
    0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,
    0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,
    0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,
    0xc76c51a3,0xd192e819
};

double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main() {
    printf("SHA256-90R GPU Batch Scaling Benchmark\n");
    printf("======================================\n\n");
    
    // Initialize CUDA
    int device_count;
    cudaGetDeviceCount(&device_count);
    if (device_count == 0) {
        printf("No CUDA devices found!\n");
        return 1;
    }
    
    cudaDeviceProp props;
    cudaGetDeviceProperties(&props, 0);
    printf("GPU: %s\n", props.name);
    printf("Compute Capability: %d.%d\n", props.major, props.minor);
    printf("Max threads/block: %d\n", props.maxThreadsPerBlock);
    printf("Max blocks: %d\n\n", props.maxGridSize[0]);
    
    // Copy constants to device
    cudaMemcpyToSymbol(d_k, k_host, sizeof(k_host));
    
    // Test different batch sizes
    int batch_sizes[] = {1000, 10000, 100000, 1000000, 10000000};
    int num_tests = sizeof(batch_sizes) / sizeof(batch_sizes[0]);
    
    printf("Batch Size | Time (s) | Throughput (Gbps) | Hashes/sec\n");
    printf("-----------|----------|-------------------|------------\n");
    
    for (int test = 0; test < num_tests; test++) {
        int num_messages = batch_sizes[test];
        size_t input_size = (size_t)num_messages * BLOCK_SIZE;
        size_t output_size = (size_t)num_messages * DIGEST_SIZE;
        
        // Allocate memory
        uint8_t* h_messages = (uint8_t*)malloc(input_size);
        uint32_t* h_hashes = (uint32_t*)malloc(output_size);
        
        if (!h_messages || !h_hashes) {
            printf("Failed to allocate host memory for %d messages\n", num_messages);
            continue;
        }
        
        // Initialize test data
        for (size_t i = 0; i < input_size; i++) {
            h_messages[i] = (uint8_t)(i & 0xFF);
        }
        
        // Allocate device memory
        uint8_t* d_messages;
        uint32_t* d_hashes;
        
        if (cudaMalloc(&d_messages, input_size) != cudaSuccess ||
            cudaMalloc(&d_hashes, output_size) != cudaSuccess) {
            printf("Failed to allocate device memory for %d messages\n", num_messages);
            free(h_messages);
            free(h_hashes);
            continue;
        }
        
        // Copy input to device
        cudaMemcpy(d_messages, h_messages, input_size, cudaMemcpyHostToDevice);
        
        // Configure kernel
        int blocks = (num_messages + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;
        if (blocks > MAX_BLOCKS) blocks = MAX_BLOCKS;
        
        // Warmup
        sha256_90r_batch_kernel<<<blocks, THREADS_PER_BLOCK>>>(d_messages, d_hashes, num_messages);
        cudaDeviceSynchronize();
        
        // Benchmark
        double start = get_time();
        
        sha256_90r_batch_kernel<<<blocks, THREADS_PER_BLOCK>>>(d_messages, d_hashes, num_messages);
        cudaDeviceSynchronize();
        
        double end = get_time();
        double elapsed = end - start;
        
        // Calculate throughput
        double bytes_processed = (double)input_size;
        double throughput_gbps = (bytes_processed * 8) / (elapsed * 1e9);
        double hashes_per_sec = num_messages / elapsed;
        
        printf("%10d | %8.4f | %17.2f | %.2e\n", 
               num_messages, elapsed, throughput_gbps, hashes_per_sec);
        
        // Cleanup
        cudaFree(d_messages);
        cudaFree(d_hashes);
        free(h_messages);
        free(h_hashes);
    }
    
    printf("\nNote: GPU performance is limited by kernel launch overhead for small batches.\n");
    printf("      Optimal performance requires 100k+ concurrent messages.\n");
    
    return 0;
}
