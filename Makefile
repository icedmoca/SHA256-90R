# Makefile for SHA256-90R Cryptographic Algorithms

.PHONY: all clean test test-aes test-blowfish test-sha256 test-base64 bench-sha256 \
        bench-sha256-cuda timing-test timing-test-gpu timing-test-fpga timing-test-jit help

# Default target
all: test

# Build and run all tests
test: test-aes test-blowfish test-sha256 test-base64

# AES-XR tests
test-aes:
	@echo "=== Building AES-XR tests ==="
	cd src/aes_xr && gcc -o ../../bin/aes_xr_test aes_test.c aes.c -I.
	./bin/aes_xr_test

# Blowfish-XR tests
test-blowfish:
	@echo "=== Building Blowfish-XR tests ==="
	cd src/blowfish_xr && gcc -o ../../bin/blowfish_xr_test blowfish_test.c blowfish.c -I.
	./bin/blowfish_xr_test

# SHA256-90R tests (unified test harness)
test-sha256:
	@echo "=== Building SHA256-90R tests ==="
	cd tests && gcc -o ../bin/sha256_90r_test crypto_xr_test.c ../src/sha256_90r/sha256.c -I../src/sha256_90r -O2
	./bin/sha256_90r_test

# Base64X tests
test-base64:
	@echo "=== Building Base64X tests ==="
	cd src/base64x && gcc -o ../../bin/base64x_test base64_test.c base64.c -I.
	./bin/base64x_test

# SHA256-90R benchmarks (CPU SIMD + optional JIT/FPGA)
bench-sha256:
	@echo "=== Building SHA256-90R CPU benchmarks ==="
	cd src/sha256_90r && gcc -o ../../bin/sha256_90r_bench sha256.c sha256_90r_jit.c sha256_90r_fpga.c \
		-I. -O3 -march=native -DUSE_SIMD -DUSE_JIT_CODEGEN -DUSE_FPGA_PIPELINE
	./bin/sha256_90r_bench

# CUDA-enabled benchmarks (requires CUDA toolkit)
bench-sha256-cuda:
	@echo "=== Building SHA256-90R CUDA benchmarks ==="
	cd src/sha256_90r && nvcc -o ../../bin/sha256_90r_bench_cuda sha256.c sha256_90r_cuda.cu -I. -O3 -DUSE_CUDA -arch=sm_50
	./bin/sha256_90r_bench_cuda

# Timing side-channel leak test (scalar baseline)
timing-test:
	@echo "=== Building SHA256-90R Timing Leak Test ==="
	cd tests && gcc -o ../bin/timing_leak_test timing_leak_test.c ../src/sha256_90r/sha256.c \
		-I../src/sha256_90r -lm -O2 -fno-tree-vectorize
	./bin/timing_leak_test

# Timing test for GPU backend
timing-test-gpu:
	@echo "=== Building SHA256-90R GPU Timing Leak Test ==="
	cd tests && gcc -o ../bin/timing_leak_test_gpu timing_leak_test.c ../src/sha256_90r/sha256.c \
		-I../src/sha256_90r -lm -O2 -DUSE_CUDA -fno-tree-vectorize
	./bin/timing_leak_test_gpu gpu

# Timing test for FPGA backend
timing-test-fpga:
	@echo "=== Building SHA256-90R FPGA Timing Leak Test ==="
	cd tests && gcc -o ../bin/timing_leak_test_fpga timing_leak_test.c ../src/sha256_90r/sha256.c ../src/sha256_90r/sha256_90r_fpga.c \
		-I../src/sha256_90r -lm -O2 -DUSE_FPGA_PIPELINE -fno-tree-vectorize
	./bin/timing_leak_test_fpga fpga

# Timing test for JIT backend
timing-test-jit:
	@echo "=== Building SHA256-90R JIT Timing Leak Test ==="
	cd tests && gcc -o ../bin/timing_leak_test_jit timing_leak_test.c ../src/sha256_90r/sha256.c ../src/sha256_90r/sha256_90r_jit.c \
		-I../src/sha256_90r -lm -O2 -DUSE_JIT_CODEGEN -fno-tree-vectorize
	./bin/timing_leak_test_jit jit

# Run all timing tests
timing-test-all: timing-test timing-test-gpu timing-test-fpga timing-test-jit
	@echo "=== All timing tests completed ==="

# Clean build artifacts
clean:
	@echo "=== Cleaning build artifacts ==="
	rm -rf bin/*

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Build and run all tests (default)"
	@echo "  test             - Same as all"
	@echo "  test-aes         - Build and run AES-XR tests"
	@echo "  test-blowfish    - Build and run Blowfish-XR tests"
	@echo "  test-sha256      - Build and run SHA256-90R tests"
	@echo "  test-base64      - Build and run Base64X tests"
	@echo "  bench-sha256     - Build and run SHA256-90R CPU benchmarks"
	@echo "  bench-sha256-cuda- Build and run SHA256-90R CUDA benchmarks"
	@echo "  timing-test*     - Run timing side-channel tests (scalar/gpu/fpga/jit)"
	@echo "  clean            - Remove all build artifacts"
