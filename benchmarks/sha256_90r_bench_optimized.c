#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <math.h>
#include "../src/sha256_90r/sha256.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/time.h>
#endif

// Test sizes
typedef struct {
    size_t size;
    const char* name;
} test_size_t;

test_size_t test_sizes[] = {
    {4 * 1024, "4 KB"},
    {1 * 1024 * 1024, "1 MB"},
    {10 * 1024 * 1024, "10 MB"},
    {100 * 1024 * 1024, "100 MB"}
};

// Thread test configurations
int thread_counts[] = {1, 2, 4, 8, 16};

// Timing functions
double get_time() {
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
#endif
}

// Get CPU frequency
double get_cpu_freq() {
#ifdef __x86_64__
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            double freq;
            if (sscanf(line, "cpu MHz : %lf", &freq) == 1) {
                fclose(fp);
                return freq * 1e6;  // Convert MHz to Hz
            }
        }
        fclose(fp);
    }
#endif
    return 3.5e9;  // Default 3.5 GHz
}

// Thread work structure
typedef struct {
    int thread_id;
    const BYTE* data;
    size_t data_len;
    size_t iterations;
    double elapsed_time;
    BYTE hash[32];
} thread_work_t;

// Worker thread function
void* worker_thread(void* arg) {
    thread_work_t* work = (thread_work_t*)arg;
    SHA256_90R_CTX ctx;
    
    double start = get_time();
    
    for (size_t i = 0; i < work->iterations; i++) {
        sha256_90r_init(&ctx);
        sha256_90r_update(&ctx, work->data, work->data_len);
        sha256_90r_final(&ctx, work->hash);
    }
    
    work->elapsed_time = get_time() - start;
    return NULL;
}

// Run single-threaded benchmark
double benchmark_single_thread(const BYTE* data, size_t len, int iterations) {
    SHA256_90R_CTX ctx;
    BYTE hash[32];
    
    double start = get_time();
    
    for (int i = 0; i < iterations; i++) {
        sha256_90r_init(&ctx);
        sha256_90r_update(&ctx, data, len);
        sha256_90r_final(&ctx, hash);
    }
    
    return get_time() - start;
}

// Run multi-threaded benchmark
double benchmark_multi_thread(const BYTE* data, size_t len, int iterations, int num_threads) {
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    thread_work_t* work = malloc(num_threads * sizeof(thread_work_t));
    
    // Divide work among threads
    int iters_per_thread = iterations / num_threads;
    int extra_iters = iterations % num_threads;
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        work[i].thread_id = i;
        work[i].data = data;
        work[i].data_len = len;
        work[i].iterations = iters_per_thread + (i < extra_iters ? 1 : 0);
        
        pthread_create(&threads[i], NULL, worker_thread, &work[i]);
    }
    
    // Wait for threads
    double total_time = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        if (work[i].elapsed_time > total_time) {
            total_time = work[i].elapsed_time;
        }
    }
    
    free(threads);
    free(work);
    
    return total_time;
}

// Print benchmark header
void print_header() {
    printf("SHA256-90R Comprehensive Benchmark Results\n");
    printf("==========================================\n");
    printf("Timestamp: %s", asctime(localtime(&(time_t){time(NULL)})));
    printf("CPU Frequency: %.2f GHz\n", get_cpu_freq() / 1e9);
    
    // Print compile flags
    printf("Compile flags: ");
#ifdef USE_SIMD
    printf("USE_SIMD ");
#endif
#ifdef SHA256_90R_ACCEL_MODE
    printf("ACCEL_MODE=%d ", SHA256_90R_ACCEL_MODE);
#endif
#ifdef SHA256_90R_SECURE_MODE
    printf("SECURE_MODE=%d ", SHA256_90R_SECURE_MODE);
#endif
    printf("\n\n");
}

int main() {
    print_header();
    
    // Results file
    FILE* fp_results = fopen("benchmarks/results_optimized.txt", "w");
    FILE* fp_multicore = fopen("benchmarks/results_multicore.txt", "w");
    
    if (!fp_results || !fp_multicore) {
        fprintf(stderr, "Failed to open results files\n");
        return 1;
    }
    
    // Write headers
    fprintf(fp_results, "Input_Size,Iterations,Time_s,Throughput_Gbps,Cycles_per_Byte\n");
    fprintf(fp_multicore, "Input_Size,Threads,Iterations,Time_s,Throughput_Gbps,Speedup\n");
    
    double cpu_freq = get_cpu_freq();
    
    // Run benchmarks for different input sizes
    for (size_t i = 0; i < sizeof(test_sizes)/sizeof(test_sizes[0]); i++) {
        size_t data_size = test_sizes[i].size;
        const char* size_name = test_sizes[i].name;
        
        printf("Testing with %s input...\n", size_name);
        
        // Allocate and initialize test data
        BYTE* data = malloc(data_size);
        if (!data) {
            fprintf(stderr, "Failed to allocate %zu bytes\n", data_size);
            continue;
        }
        
        // Fill with pattern
        for (size_t j = 0; j < data_size; j++) {
            data[j] = (BYTE)(j & 0xFF);
        }
        
        // Determine iterations based on data size
        int iterations = 1000;
        if (data_size >= 10 * 1024 * 1024) iterations = 100;
        if (data_size >= 100 * 1024 * 1024) iterations = 10;
        
        // Single-threaded benchmark
        printf("  Single-threaded: ");
        fflush(stdout);
        
        double single_time = benchmark_single_thread(data, data_size, iterations);
        double bytes_processed = (double)data_size * iterations;
        double throughput_gbps = (bytes_processed * 8) / (single_time * 1e9);
        double cycles_per_byte = (cpu_freq * single_time) / bytes_processed;
        
        printf("%.3f Gbps (%.2f cycles/byte)\n", throughput_gbps, cycles_per_byte);
        
        fprintf(fp_results, "%zu,%d,%.6f,%.6f,%.2f\n", 
                data_size, iterations, single_time, throughput_gbps, cycles_per_byte);
        
        // Multi-threaded benchmarks
        for (size_t t = 0; t < sizeof(thread_counts)/sizeof(thread_counts[0]); t++) {
            int num_threads = thread_counts[t];
            
            printf("  %d threads: ", num_threads);
            fflush(stdout);
            
            double multi_time = benchmark_multi_thread(data, data_size, iterations, num_threads);
            double multi_throughput = (bytes_processed * 8) / (multi_time * 1e9);
            double speedup = multi_throughput / throughput_gbps;
            
            printf("%.3f Gbps (%.2fx speedup)\n", multi_throughput, speedup);
            
            fprintf(fp_multicore, "%zu,%d,%d,%.6f,%.6f,%.2f\n",
                    data_size, num_threads, iterations, multi_time, multi_throughput, speedup);
        }
        
        printf("\n");
        free(data);
    }
    
    // Run a quick test to verify correctness
    printf("Correctness check:\n");
    BYTE test_data[] = "abc";
    BYTE hash[32];
    SHA256_90R_CTX ctx;
    
    sha256_90r_init(&ctx);
    sha256_90r_update(&ctx, test_data, 3);
    sha256_90r_final(&ctx, hash);
    
    printf("SHA256-90R(\"abc\") = ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    fclose(fp_results);
    fclose(fp_multicore);
    
    printf("\nResults saved to:\n");
    printf("  - benchmarks/results_optimized.txt\n");
    printf("  - benchmarks/results_multicore.txt\n");
    
    return 0;
}
