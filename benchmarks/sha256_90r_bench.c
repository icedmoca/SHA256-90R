/*********************************************************************
* Filename:   sha256_90r_bench.c
* Author:     SHA256-90R Benchmark Suite
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Comprehensive performance benchmark for SHA256-90R across
*             all backends (Scalar, SIMD, SHA-NI, GPU, FPGA, JIT).
*             Measures cycles/byte, throughput (Gbps), and relative slowdown.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <unistd.h>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif
#include <pthread.h>
#include "../src/sha256_90r/sha256.h"
#include "../src/sha256_90r/sha256_90r.h"

// Conditional CUDA support
#ifndef USE_CUDA
typedef int cudaError_t;
#define cudaSuccess 0
#endif

/****************************** MACROS ******************************/
#define BENCHMARK_RUNS (5)          // Number of benchmark runs for averaging
#define CPU_CLOCK_GHZ (3.5)         // Assumed CPU clock speed
#define CPU_CLOCK_HZ (CPU_CLOCK_GHZ * 1000000000.0)

// Global quick mode setting
static int quick_mode = 0;

// Input sizes for comprehensive benchmarking
#define INPUT_SIZE_1MB (1024 * 1024)        // 1 MB
#define INPUT_SIZE_10MB (10 * 1024 * 1024)  // 10 MB
#define INPUT_SIZE_100MB (100 * 1024 * 1024) // 100 MB

/**************************** DATA TYPES ****************************/
typedef struct {
    const char* name;
    const char* description;
    double throughput_1mb_gbps;
    double throughput_10mb_gbps;
    double throughput_100mb_gbps;
    double avg_throughput_gbps;
    double speedup_vs_scalar;
    int supported;
} benchmark_result_t;

typedef struct {
    size_t input_size;
    const char* size_name;
} input_size_config_t;

typedef struct {
    double mean;
    double std_dev;
    double min;
    double max;
} timing_stats_t;

/*********************** FUNCTION DEFINITIONS ***********************/

/**
 * Convert backend string to enum value
 */
sha256_90r_backend_t backend_string_to_enum(const char* backend) {
    if (strcmp(backend, "scalar") == 0) {
        return SHA256_90R_BACKEND_SCALAR;
    } else if (strcmp(backend, "simd") == 0 || strcmp(backend, "avx2") == 0) {
        return SHA256_90R_BACKEND_SIMD;
    } else if (strcmp(backend, "sha_ni") == 0) {
        return SHA256_90R_BACKEND_SHA_NI;
    } else if (strcmp(backend, "gpu") == 0) {
        return SHA256_90R_BACKEND_GPU;
    } else if (strcmp(backend, "fpga") == 0) {
        return SHA256_90R_BACKEND_FPGA;
    } else if (strcmp(backend, "jit") == 0) {
        return SHA256_90R_BACKEND_JIT;
    } else if (strcmp(backend, "pipelined") == 0) {
        // Map "pipelined" to AUTO for now, as there's no specific pipelined backend
        return SHA256_90R_BACKEND_AUTO;
    } else {
        // Default to scalar for unknown backends
        return SHA256_90R_BACKEND_SCALAR;
    }
}

/**
 * Get CPU information for feature detection
 */
void get_cpu_info(char* vendor, int* family, int* model, int* stepping) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t regs[4];
    __cpuid(0, regs[0], regs[1], regs[2], regs[3]);

    memcpy(vendor, &regs[1], 4);
    memcpy(vendor + 4, &regs[3], 4);
    memcpy(vendor + 8, &regs[2], 4);
    vendor[12] = '\0';

    __cpuid(1, regs[0], regs[1], regs[2], regs[3]);
    *family = ((regs[0] >> 8) & 0xF) + ((regs[0] >> 20) & 0xFF);
    *model = ((regs[0] >> 4) & 0xF) | ((regs[0] >> 12) & 0xF0);
    *stepping = regs[0] & 0xF;
#else
    // Default values for non-x86 platforms
    strcpy(vendor, "Unknown");
    *family = 0;
    *model = 0;
    *stepping = 0;
#endif
}

/**
 * Check if AVX2 is supported
 */
int cpu_supports_avx2(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t regs[4];
    __cpuid_count(7, 0, regs[0], regs[1], regs[2], regs[3]);
    return (regs[1] & (1 << 5)) != 0; // AVX2 bit
#else
    return 0; // Not supported on non-x86 platforms
#endif
}

/**
 * Check if SHA-NI is supported
 */
int cpu_supports_sha_ni(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t regs[4];
    __cpuid_count(7, 0, regs[0], regs[1], regs[2], regs[3]);
    return (regs[1] & (1 << 29)) != 0; // SHA-NI bit
#else
    return 0; // Not supported on non-x86 platforms
#endif
}

/**
 * Generate test input data
 */
void generate_test_input(BYTE* input, size_t size) {
    // Use deterministic pattern for reproducible benchmarks
    srand(42); // Fixed seed
    for (size_t i = 0; i < size; i++) {
        input[i] = rand() % 256;
    }
}

/**
 * Time SHA256-90R processing with iteration-based timing for accurate measurements
 * Returns throughput in Gbps for the given input size
 */
double benchmark_backend_throughput(const BYTE* input, size_t input_len, const char* backend, int num_runs) {
    double total_time = 0.0;
    
    // Determine iterations based on quick mode or input size
    int iterations;
    if (quick_mode) {
        iterations = 1;  // Quick mode: always use 1 iteration regardless of input size
    } else {
        // Normal mode: determine iterations based on input size (matching optimized benchmark approach)
        iterations = 1000;
        if (input_len >= 10 * 1024 * 1024) iterations = 100;  // 10MB+
        if (input_len >= 100 * 1024 * 1024) iterations = 10;  // 100MB+
    }

    for (int run = 0; run < num_runs; run++) {
        struct timespec start, end;
        uint8_t hash[SHA256_90R_DIGEST_SIZE];

        // Initialize context with specified backend
        sha256_90r_backend_t backend_enum = backend_string_to_enum(backend);
        SHA256_90R_CTX *ctx = sha256_90r_new_backend(backend_enum);
        if (!ctx) {
            fprintf(stderr, "Failed to create context for backend: %s\n", backend);
            continue;
        }

        // Start timing
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        // Iteration-based timing loop
        for (int iter = 0; iter < iterations; iter++) {
            // Progress indicator for longer benchmarks
            if (iter % 10 == 0 && iterations > 1) {
                printf("    Progress: iteration %d/%d complete\n", iter, iterations);
                fflush(stdout);
            }
            
            // Reset context for each iteration
            sha256_90r_reset(ctx);
            
            // Process input data in chunks to simulate real-world usage
            size_t remaining = input_len;
            size_t offset = 0;
            const size_t chunk_size = 1024 * 64; // 64KB chunks

            while (remaining > 0) {
                size_t process_size = (remaining > chunk_size) ? chunk_size : remaining;

                // Update with chunk - backend dispatch is handled internally
                sha256_90r_update(ctx, (const uint8_t*)(input + offset), process_size);

                offset += process_size;
                remaining -= process_size;
            }

            // Finalize hash
            sha256_90r_final(ctx, hash);
        }

        // End timing
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);

        // Calculate elapsed time in seconds
        double elapsed_sec = (end.tv_sec - start.tv_sec) +
                            (end.tv_nsec - start.tv_nsec) / 1000000000.0;

        total_time += elapsed_sec;

        // Free context
        sha256_90r_free(ctx);
    }

    // Calculate average throughput with iteration multiplier
    double avg_time_sec = total_time / num_runs;
    double total_bytes_processed = (double)input_len * iterations;
    double throughput_gbps = (total_bytes_processed * 8) / (avg_time_sec * 1e9);

    return throughput_gbps;
}

/**
 * Time standard SHA-256 for comparison
 */
double time_sha256_operation(const BYTE* input, size_t input_len) {
    struct timespec start, end;
    SHA256_CTX ctx;
    BYTE hash[SHA256_BLOCK_SIZE];

    // Start timing
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    // Initialize context
    sha256_init(&ctx);

    // Update with input data
    sha256_update(&ctx, input, input_len);

    // Finalize hash
    sha256_final(&ctx, hash);

    // End timing
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    // Calculate elapsed time in seconds
    double elapsed_sec = (end.tv_sec - start.tv_sec) +
                        (end.tv_nsec - start.tv_nsec) / 1000000000.0;

    return elapsed_sec;
}

/**
 * Run GPU batch benchmark for thousands of hashes
 * NOTE: Currently disabled due to CUDA function availability issues
 */
benchmark_result_t benchmark_gpu_batch(const BYTE* test_input, size_t input_size, size_t batch_size) {
    benchmark_result_t result;
    result.name = "gpu_batch";
    result.description = "CUDA batch processing";
    result.supported = 0;
    result.throughput_1mb_gbps = 0.0;
    result.throughput_10mb_gbps = 0.0;
    result.throughput_100mb_gbps = 0.0;
    result.avg_throughput_gbps = 0.0;
    result.speedup_vs_scalar = 0.0;

    // Suppress unused parameter warnings
    (void)test_input;
    (void)input_size;
    (void)batch_size;

    printf("GPU batch benchmark currently disabled\n");
    return result;
}

/**
 * Run comprehensive benchmark for a specific backend across multiple input sizes
 */
benchmark_result_t benchmark_backend_comprehensive(const char* backend_name, const char* description) {
    benchmark_result_t result;
    result.name = backend_name;
    result.description = description;
    result.supported = 1;

    printf("Benchmarking %s backend (%s)...\n", backend_name, description);

    // Check backend availability
    if (strcmp(backend_name, "simd") == 0 && !cpu_supports_avx2()) {
        printf("  AVX2 not supported - skipping SIMD benchmark\n");
        result.supported = 0;
        return result;
    }
    if (strcmp(backend_name, "sha_ni") == 0 && !cpu_supports_sha_ni()) {
        printf("  SHA-NI not supported - skipping SHA-NI benchmark\n");
        result.supported = 0;
        return result;
    }

    // Define input sizes for testing - respect quick mode
    input_size_config_t input_sizes[] = {
        {INPUT_SIZE_1MB, "1MB"},
        {INPUT_SIZE_10MB, "10MB"},
        {INPUT_SIZE_100MB, "100MB"}
    };
    const int num_sizes = quick_mode ? 1 : 3;  // Only test 1MB in quick mode

    // Benchmark each input size
    double throughputs[num_sizes];

    for (int i = 0; i < num_sizes; i++) {
        printf("  Testing with %s input...\n", input_sizes[i].size_name);

        // Generate test input for this size
        BYTE* test_input = malloc(input_sizes[i].input_size);
        if (!test_input) {
            fprintf(stderr, "Failed to allocate %s test input\n", input_sizes[i].size_name);
            result.supported = 0;
            return result;
        }
        generate_test_input(test_input, input_sizes[i].input_size);

        // Run benchmark with iteration-based timing - use 1 run in quick mode
        int runs = quick_mode ? 1 : BENCHMARK_RUNS;
        double throughput = benchmark_backend_throughput(test_input, input_sizes[i].input_size, backend_name, runs);
        throughputs[i] = throughput;
        
        // Calculate cycles per byte for additional insight
        double cycles_per_byte = (CPU_CLOCK_HZ / 1e9) / (throughput / 8.0);
        printf("    %s throughput: %.4f Gbps (%.2f cycles/byte)\n", input_sizes[i].size_name, throughput, cycles_per_byte);

        free(test_input);
    }

    // Store results - handle quick mode properly
    result.throughput_1mb_gbps = throughputs[0];
    if (quick_mode) {
        // In quick mode, only 1MB is tested
        result.throughput_10mb_gbps = 0.0;
        result.throughput_100mb_gbps = 0.0;
        result.avg_throughput_gbps = throughputs[0];
    } else {
        result.throughput_10mb_gbps = throughputs[1];
        result.throughput_100mb_gbps = throughputs[2];
        // Calculate average throughput across all sizes
        result.avg_throughput_gbps = (throughputs[0] + throughputs[1] + throughputs[2]) / 3.0;
    }

    // Speedup will be calculated later after we have scalar baseline
    result.speedup_vs_scalar = 0.0;

    printf("  Average throughput: %.4f Gbps\n", result.avg_throughput_gbps);

    return result;
}

/**
 * Print benchmark results table
 */
void print_results_table(benchmark_result_t results[], int num_results, double scalar_baseline) {
    printf("\n");
    printf("=== SHA256-90R Comprehensive Benchmark Results ===\n");
    if (quick_mode) {
        printf("Testing input sizes: 1MB only (1 run each) - Quick Mode\n");
        printf("Iteration-based timing: 1 iteration (1MB)\n");
    } else {
        printf("Testing input sizes: 1MB, 10MB, 100MB (averaged over %d runs each)\n", BENCHMARK_RUNS);
        printf("Iteration-based timing: 1000 iterations (1MB), 100 (10MB), 10 (100MB)\n");
    }
    printf("Throughput calculation: (total_bytes_processed * 8) / (elapsed_time * 1e9) Gbps\n");
    printf("CPU Clock: %.1f GHz (assumed)\n", CPU_CLOCK_GHZ);
    printf("\n");

    if (quick_mode) {
        printf("%-12s | %-12s | %-12s\n",
               "Backend", "1MB (Gbps)", "Speedup");
        printf("%-12s | %-12s | %-12s\n",
               "------------", "------------", "----------");
    } else {
        printf("%-12s | %-12s | %-12s | %-12s | %-12s | %-12s\n",
               "Backend", "1MB (Gbps)", "10MB (Gbps)", "100MB (Gbps)", "Avg (Gbps)", "Speedup");
        printf("%-12s | %-12s | %-12s | %-12s | %-12s | %-12s\n",
               "------------", "------------", "------------", "------------", "------------", "----------");
    }

    for (int i = 0; i < num_results; i++) {
        if (results[i].supported) {
            double speedup = (scalar_baseline > 0.0) ? results[i].avg_throughput_gbps / scalar_baseline : 0.0;
            if (quick_mode) {
                printf("%-12s | %-12.4f | %-12.2fx\n",
                       results[i].name,
                       results[i].throughput_1mb_gbps,
                       speedup);
            } else {
                printf("%-12s | %-12.4f | %-12.4f | %-12.4f | %-12.4f | %-12.2fx\n",
                       results[i].name,
                       results[i].throughput_1mb_gbps,
                       results[i].throughput_10mb_gbps,
                       results[i].throughput_100mb_gbps,
                       results[i].avg_throughput_gbps,
                       speedup);
            }
        } else {
            if (quick_mode) {
                printf("%-12s | %-12s | %-12s\n",
                       results[i].name,
                       "N/A", "N/A");
            } else {
                printf("%-12s | %-12s | %-12s | %-12s | %-12s | %-12s\n",
                       results[i].name,
                       "N/A", "N/A", "N/A", "N/A", "N/A");
            }
        }
    }
}

/**
 * Save results to file
 */
void save_results_to_file(benchmark_result_t results[], int num_results, const char* filename, double scalar_baseline) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Error opening file for writing: %s\n", filename);
        return;
    }

    fprintf(fp, "# SHA256-90R Comprehensive Benchmark Results\n");
    fprintf(fp, "# Generated: %s", ctime(&(time_t){time(NULL)}));
    if (quick_mode) {
        fprintf(fp, "# Input sizes tested: 1MB only (Quick Mode)\n");
        fprintf(fp, "# Runs per test: 1\n");
        fprintf(fp, "# Iteration-based timing: 1 iteration (1MB)\n");
    } else {
        fprintf(fp, "# Input sizes tested: 1MB, 10MB, 100MB\n");
        fprintf(fp, "# Runs per test: %d\n", BENCHMARK_RUNS);
        fprintf(fp, "# Iteration-based timing: 1000 iterations (1MB), 100 (10MB), 10 (100MB)\n");
    }
    fprintf(fp, "# Throughput calculation: (total_bytes_processed * 8) / (elapsed_time * 1e9) Gbps\n");
    fprintf(fp, "# CPU Clock: %.1f GHz\n", CPU_CLOCK_GHZ);
    if (scalar_baseline > 0.0) {
        fprintf(fp, "# Scalar baseline: %.4f Gbps\n", scalar_baseline);
    }
    fprintf(fp, "\n");

    if (quick_mode) {
        fprintf(fp, "Backend,Throughput_1MB_Gbps,Speedup_vs_Scalar,Supported\n");
        for (int i = 0; i < num_results; i++) {
            if (results[i].supported) {
                double speedup = (scalar_baseline > 0.0) ? results[i].avg_throughput_gbps / scalar_baseline : 0.0;
                fprintf(fp, "%s,%.4f,%.2f,1\n",
                        results[i].name,
                        results[i].throughput_1mb_gbps,
                        speedup);
            } else {
                fprintf(fp, "%s,N/A,N/A,0\n", results[i].name);
            }
        }
    } else {
        fprintf(fp, "Backend,Throughput_1MB_Gbps,Throughput_10MB_Gbps,Throughput_100MB_Gbps,Avg_Throughput_Gbps,Speedup_vs_Scalar,Supported\n");
        for (int i = 0; i < num_results; i++) {
            if (results[i].supported) {
                double speedup = (scalar_baseline > 0.0) ? results[i].avg_throughput_gbps / scalar_baseline : 0.0;
                fprintf(fp, "%s,%.4f,%.4f,%.4f,%.4f,%.2f,1\n",
                        results[i].name,
                        results[i].throughput_1mb_gbps,
                        results[i].throughput_10mb_gbps,
                        results[i].throughput_100mb_gbps,
                        results[i].avg_throughput_gbps,
                        speedup);
            } else {
                fprintf(fp, "%s,N/A,N/A,N/A,N/A,N/A,0\n", results[i].name);
            }
        }
    }

    fclose(fp);
    printf("\nResults saved to: %s\n", filename);
}

/**
 * Print system information
 */
void print_system_info(void) {
    char vendor[13];
    int family, model, stepping;

    get_cpu_info(vendor, &family, &model, &stepping);

    printf("=== System Information ===\n");
    printf("CPU Vendor: %s\n", vendor);
    printf("CPU Family: %d, Model: %d, Stepping: %d\n", family, model, stepping);
    printf("AVX2 Support: %s\n", cpu_supports_avx2() ? "Yes" : "No");
    printf("SHA-NI Support: %s\n", cpu_supports_sha_ni() ? "Yes" : "No");
    printf("Benchmark Input Sizes: 1MB, 10MB, 100MB\n");
    printf("Benchmark Runs per Test: %d\n", BENCHMARK_RUNS);
    printf("\n");
}

/*********************** FORWARD DECLARATIONS ***********************/
void benchmark_multicore_scaling(const char* backend, int max_threads);
void run_perf_profiling(const char* backend, size_t input_size);

/*********************** MAIN FUNCTION ***********************/
int main(int argc, char* argv[]) {
    printf("=== SHA256-90R Comprehensive Benchmark Suite ===\n");
    printf("Measuring throughput across multiple input sizes with iteration-based timing\n");

    // Parse command line arguments
    int enable_perf = 0;
    int enable_multicore = 0;
    const char* perf_backend = "scalar";
    const char* multicore_backend = "scalar";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--perf") == 0 && i + 1 < argc) {
            enable_perf = 1;
            perf_backend = argv[i + 1];
            i++; // Skip next argument
        } else if (strcmp(argv[i], "--multicore") == 0 && i + 1 < argc) {
            enable_multicore = 1;
            multicore_backend = argv[i + 1];
            i++; // Skip next argument
        } else if (strcmp(argv[i], "--quick") == 0) {
            quick_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --perf <backend>      Run perf stat profiling for specified backend\n");
            printf("  --multicore <backend> Run multi-core scaling test for specified backend\n");
            printf("  --quick               Run quick benchmarks (1 run, 1MB input only)\n");
            printf("  --help                Show this help message\n");
            printf("\nAvailable backends: scalar, simd, avx2, sha_ni, gpu, pipelined, fpga, jit\n");
            return 0;
        }
    }

    // Print system information
    print_system_info();

    // Print iteration count information and quick mode status
    if (quick_mode) {
        printf("Iteration count: 1 (Quick Mode)\n");
        printf("Quick mode enabled: only 1 run at 1MB input for each backend.\n\n");
    } else {
        printf("Iteration counts: 1000 (1MB), 100 (10MB), 10 (100MB) for accurate measurements\n\n");
    }

    // Define backends to benchmark
    const char* backends[] = {
        "scalar", "simd", "sha_ni", "gpu", "pipelined", "fpga", "jit"
    };
    const char* descriptions[] = {
        "Portable C implementation",
        "AVX2 SIMD acceleration",
        "Intel SHA-NI hardware acceleration",
        "CUDA/OpenCL GPU acceleration",
        "Pipelined message prep + compression",
        "FPGA pipeline simulation",
        "JIT code generation"
    };

    const int num_backends = 7;
    benchmark_result_t* results = malloc(num_backends * sizeof(benchmark_result_t));

    if (!results) {
        fprintf(stderr, "Failed to allocate results memory\n");
        return 1;
    }

    // Run comprehensive benchmarks for all backends
    printf("=== Running Comprehensive Benchmarks ===\n");
    if (quick_mode) {
        printf("Testing each backend with 1MB input (1 run each)\n\n");
    } else {
        printf("Testing each backend with 1MB, 10MB, and 100MB inputs (%d runs each)\n\n", BENCHMARK_RUNS);
    }

    for (int i = 0; i < num_backends; i++) {
        results[i] = benchmark_backend_comprehensive(backends[i], descriptions[i]);
        printf("\n");
    }

    // Calculate scalar baseline for speedup calculations
    double scalar_baseline = 0.0;
    for (int i = 0; i < num_backends; i++) {
        if (strcmp(results[i].name, "scalar") == 0 && results[i].supported) {
            scalar_baseline = results[i].avg_throughput_gbps;
            break;
        }
    }

    // Print results table
    print_results_table(results, num_backends, scalar_baseline);

    // Save results to both files
    save_results_to_file(results, num_backends, "benchmarks/results_latest.txt", scalar_baseline);

    // Also save to full results file
    char full_results_filename[256];
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    sprintf(full_results_filename, "benchmarks/results_%04d%02d%02d_%02d%02d%02d.txt",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
    save_results_to_file(results, num_backends, full_results_filename, scalar_baseline);

    // Run optional multi-core scaling test
    if (enable_multicore) {
        printf("\n");
        benchmark_multicore_scaling(multicore_backend, 8); // Test up to 8 cores by default
    }

    // Run optional perf profiling
    if (enable_perf) {
        printf("\n");
        run_perf_profiling(perf_backend, INPUT_SIZE_10MB);
    }

    // Print summary
    printf("\n=== Benchmark Summary ===\n");
    printf("Comprehensive testing completed with large input sizes.\n");
    printf("Scalar baseline: %.4f Gbps\n", scalar_baseline);
    printf("Results saved to:\n");
    printf("  - benchmarks/results_latest.txt\n");
    printf("  - %s\n", full_results_filename);
    if (enable_multicore) {
        printf("  - benchmarks/results_multicore.txt\n");
    }
    if (enable_perf) {
        printf("  - benchmarks/perf_counters.txt\n");
    }
    printf("Use these results to update performance tables in documentation.\n");

    // Cleanup
    free(results);

    return 0;
}

/**
 * Multi-core scaling benchmark
 */
typedef struct {
    BYTE* input;
    size_t input_size;
    const char* backend;
    double* result_throughput;
    int thread_id;
} thread_data_t;

void* multicore_worker(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;

    // Each thread processes its own copy of the data
    double throughput = benchmark_backend_throughput(data->input, data->input_size, data->backend, BENCHMARK_RUNS);

    *data->result_throughput = throughput;
    return NULL;
}

/**
 * Run multi-core scaling benchmark
 */
void benchmark_multicore_scaling(const char* backend, int max_threads) {
    printf("=== Multi-Core Scaling Test (%s backend) ===\n", backend);
    printf("Testing with 1MB input per thread, scaling from 1 to %d threads\n\n", max_threads);

    // Generate base test input
    size_t input_size = INPUT_SIZE_1MB;
    BYTE* base_input = malloc(input_size);
    if (!base_input) {
        fprintf(stderr, "Failed to allocate base input memory\n");
        return;
    }
    generate_test_input(base_input, input_size);

    // Results storage
    double* throughputs = malloc(max_threads * sizeof(double));
    double* speedups = malloc(max_threads * sizeof(double));

    if (!throughputs || !speedups) {
        fprintf(stderr, "Failed to allocate results memory\n");
        free(base_input);
        return;
    }

    // Test single-threaded baseline
    printf("Testing single-threaded baseline...\n");
    throughputs[0] = benchmark_backend_throughput(base_input, input_size, backend, BENCHMARK_RUNS);
    speedups[0] = 1.0;
    printf("1 thread: %.4f Gbps (baseline)\n\n", throughputs[0]);

    // Test multi-threaded scaling
    for (int num_threads = 2; num_threads <= max_threads; num_threads++) {
        printf("Testing %d threads...\n", num_threads);

        // Prepare thread data
        pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
        thread_data_t* thread_data = malloc(num_threads * sizeof(thread_data_t));

        if (!threads || !thread_data) {
            fprintf(stderr, "Failed to allocate thread memory\n");
            free(threads);
            free(thread_data);
            continue;
        }

        // Create threads
        for (int i = 0; i < num_threads; i++) {
            // Each thread gets its own copy of the input data
            thread_data[i].input = malloc(input_size);
            if (!thread_data[i].input) {
                fprintf(stderr, "Failed to allocate thread input memory\n");
                continue;
            }
            memcpy(thread_data[i].input, base_input, input_size);
            thread_data[i].input_size = input_size;
            thread_data[i].backend = backend;
            thread_data[i].result_throughput = &throughputs[num_threads - 1];
            thread_data[i].thread_id = i;

            if (pthread_create(&threads[i], NULL, multicore_worker, &thread_data[i]) != 0) {
                fprintf(stderr, "Failed to create thread %d\n", i);
            }
        }

        // Wait for all threads to complete
        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }

        // Calculate aggregate throughput and speedup
        double aggregate_throughput = throughputs[num_threads - 1];
        double speedup = aggregate_throughput / throughputs[0];
        speedups[num_threads - 1] = speedup;

        printf("%d threads: %.4f Gbps (speedup: %.2fx, efficiency: %.1f%%)\n",
               num_threads, aggregate_throughput, speedup, (speedup / num_threads) * 100.0);

        // Cleanup
        for (int i = 0; i < num_threads; i++) {
            free(thread_data[i].input);
        }
        free(threads);
        free(thread_data);
    }

    // Save multicore results
    FILE* fp = fopen("benchmarks/results_multicore.txt", "w");
    if (fp) {
        fprintf(fp, "# SHA256-90R Multi-Core Scaling Results (%s backend)\n", backend);
        fprintf(fp, "# Generated: %s", ctime(&(time_t){time(NULL)}));
        fprintf(fp, "# Input size per thread: 1MB\n");
        fprintf(fp, "# Backend: %s\n", backend);
        fprintf(fp, "\n");
        fprintf(fp, "Threads,Aggregate_Throughput_Gbps,Speedup,Efficiency\n");

        for (int i = 1; i <= max_threads; i++) {
            double efficiency = speedups[i - 1] / i * 100.0;
            fprintf(fp, "%d,%.4f,%.2f,%.1f\n", i, throughputs[i - 1], speedups[i - 1], efficiency);
        }
        fclose(fp);
        printf("\nMulti-core results saved to: benchmarks/results_multicore.txt\n");
    }

    // Print summary table
    printf("\nMulti-Core Scaling Summary:\n");
    printf("Threads | Throughput (Gbps) | Speedup | Efficiency\n");
    printf("--------|------------------|---------|-----------\n");
    for (int i = 1; i <= max_threads; i++) {
        double efficiency = speedups[i - 1] / i * 100.0;
        printf("%7d | %16.4f | %7.2f | %9.1f%%\n", i, throughputs[i - 1], speedups[i - 1], efficiency);
    }

    // Cleanup
    free(base_input);
    free(throughputs);
    free(speedups);
}

/**
 * Run perf stat profiling (Linux only)
 */
void run_perf_profiling(const char* backend, size_t input_size) {
    printf("=== Perf Counter Profiling (%s backend) ===\n", backend);
    printf("Running with Linux perf stat for hardware counters\n\n");

    // Generate test input
    BYTE* test_input = malloc(input_size);
    if (!test_input) {
        fprintf(stderr, "Failed to allocate test input memory\n");
        return;
    }
    generate_test_input(test_input, input_size);

    // Build perf command
    char perf_cmd[1024];
    snprintf(perf_cmd, sizeof(perf_cmd),
             "perf stat -e cycles,instructions,cache-misses,cache-references,branch-misses,branch-instructions,stalled-cycles-frontend,stalled-cycles-backend,L1-dcache-load-misses,L1-dcache-loads,LLC-load-misses,LLC-loads "
             "./bin/sha256_90r_bench --backend %s --input-size %zu --runs 3",
             backend, input_size);

    printf("Running perf command:\n%s\n\n", perf_cmd);

    // Execute perf stat
    int result = system(perf_cmd);
    if (result != 0) {
        printf("Perf stat completed with exit code: %d\n", result);
    }

    // Save perf results to file
    FILE* fp = fopen("benchmarks/perf_counters.txt", "a");
    if (fp) {
        fprintf(fp, "\n=== Perf Counter Results for %s backend ===\n", backend);
        fprintf(fp, "Input size: %zu bytes\n", input_size);
        fprintf(fp, "Command: %s\n", perf_cmd);
        fprintf(fp, "Timestamp: %s", ctime(&(time_t){time(NULL)}));
        fprintf(fp, "----------------------------------------\n");
        fclose(fp);
    }

    free(test_input);
}
