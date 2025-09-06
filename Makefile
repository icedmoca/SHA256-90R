# Makefile for SHA256-90R Cryptographic Algorithms

.PHONY: all clean test test-aes test-blowfish test-sha256 test-base64 bench-sha256 \
        bench-sha256-cuda bench-comprehensive bench-simple bench-optimized bench-fast bench timing-test timing-test-gpu timing-test-fpga timing-test-jit \
        install uninstall help

# Ensure bin directory exists
$(shell mkdir -p bin)

# Default target
all: test

# Build and run all tests
test: test-aes test-blowfish test-sha256 test-base64

# Build and run all verification tests
verify-all: verify-aes verify-blowfish verify-sha256 verify-base64

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
	cd tests && gcc -o ../bin/sha256_90r_test crypto_xr_test.c ../src/sha256_90r/sha256_90r.c ../src/sha256_90r/sha256.c ../src/aes_xr/aes.c ../src/base64x/base64.c ../src/blowfish_xr/blowfish.c -I../src/sha256_90r -I../src/aes_xr -I../src/base64x -I../src/blowfish_xr -O2
	./bin/sha256_90r_test

# Base64X tests
test-base64:
	@echo "=== Building Base64X tests ==="
	cd src/base64x && gcc -o ../../bin/base64x_test base64_test.c base64.c -I.
	./bin/base64x_test

# AES-XR verification tests
verify-aes:
	@echo "=== Building AES-XR verification tests ==="
	cd tests && gcc -o ../bin/aes_xr_verification aes_xr_verification.c ../src/aes_xr/aes.c -I../src/aes_xr -lm -O2
	./bin/aes_xr_verification

# Blowfish-XR verification tests
verify-blowfish:
	@echo "=== Building Blowfish-XR verification tests ==="
	cd tests && gcc -o ../bin/blowfish_xr_verification blowfish_xr_verification.c ../src/blowfish_xr/blowfish.c -I../src/blowfish_xr -lm -O2
	./bin/blowfish_xr_verification

# SHA256-90R verification tests
verify-sha256:
	@echo "=== Building SHA256-90R verification tests ==="
	cd tests && gcc -o ../bin/sha256_90r_verification sha256_90r_verification.c ../src/sha256_90r/sha256.c ../src/sha256_90r/sha256_90r.c -I../src/sha256_90r -lm -O3 -march=native -funroll-loops -finline-functions
	./bin/sha256_90r_verification

# Base64X verification tests
verify-base64:
	@echo "=== Building Base64X verification tests ==="
	cd tests && gcc -o ../bin/base64x_verification base64x_verification.c ../src/base64x/base64.c -I../src/base64x -lm -O2
	./bin/base64x_verification

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

# Comprehensive benchmark suite (all backends)
bench-comprehensive: bin/sha256_90r_comprehensive_bench
	@echo "=== Running SHA256-90R Comprehensive Benchmark Suite ==="
	./bin/sha256_90r_comprehensive_bench > benchmarks/results_full.txt 2>&1 || echo "Benchmark completed with exit code $$?"

# Build comprehensive benchmark binary
bin/sha256_90r_comprehensive_bench:
	@echo "=== Building SHA256-90R Comprehensive Benchmark Suite ==="
	mkdir -p bin
	gcc -o bin/sha256_90r_comprehensive_bench benchmarks/sha256_90r_bench.c src/sha256_90r/sha256.c \
		src/sha256_90r/sha256_90r.c src/sha256_90r/sha256_90r_jit.c src/sha256_90r/sha256_90r_fpga.c \
		-Isrc/sha256_90r -lm -lpthread -O3 -march=native -DUSE_SIMD -DUSE_SHA_NI -DUSE_FPGA_PIPELINE -DUSE_JIT_CODEGEN

# Simple benchmark (recommended for debugging throughput)
bench-simple:
	@echo "=== Building SHA256-90R Simple Benchmark ==="
	gcc -O3 -march=native -DUSE_SIMD -DSHA256_90R_ACCEL_MODE=1 -DSHA256_90R_SECURE_MODE=0 -o bin/bench_simple benchmarks/bench_simple.c src/sha256_90r/sha256_90r.c src/sha256_90r/sha256.c -Isrc/sha256_90r -lm
	@echo "=== Running SHA256-90R Simple Benchmark ==="
	./bin/bench_simple

# Optimized benchmark with AVX2 support
bench-optimized:
	@echo "=== Building SHA256-90R Optimized Benchmark ==="
	gcc -O3 -march=native -mavx2 -DUSE_SIMD -DSHA256_90R_ACCEL_MODE=1 -DSHA256_90R_SECURE_MODE=0 \
		-o bin/bench_optimized benchmarks/sha256_90r_bench_optimized.c src/sha256_90r/sha256_90r.c src/sha256_90r/sha256.c \
		-Isrc/sha256_90r -lm -lpthread -funroll-loops -finline-functions
	@echo "=== Running SHA256-90R Optimized Benchmark ==="
	./bin/bench_optimized

# Fast implementation benchmark
bench-fast:
	@echo "=== Building SHA256-90R Fast Implementation Benchmark ==="
	gcc -O3 -march=native -mavx2 -DUSE_SIMD -DSHA256_90R_ACCEL_MODE=1 -DSHA256_90R_SECURE_MODE=0 \
		-o bin/bench_fast benchmarks/bench_fast.c src/sha256_90r/sha256.c \
		-Isrc/sha256_90r -lm -funroll-loops -finline-functions -ffast-math
	@echo "=== Running SHA256-90R Fast Implementation Benchmark ==="
	./bin/bench_fast

# Quick benchmark alias (assumes binary is already built)
bench: bin/sha256_90r_comprehensive_bench
	@echo "=== Running SHA256-90R Quick Benchmark ==="
	./bin/sha256_90r_comprehensive_bench > benchmarks/results_latest.txt 2>&1 || echo "Benchmark completed with exit code $$?"

# Timing side-channel leak test (scalar baseline)
timing-test:
	@echo "=== Building SHA256-90R Timing Leak Test ==="
	cd tests && gcc -o ../bin/timing_leak_test timing_leak_test.c ../src/sha256_90r/sha256.c ../src/sha256_90r/sha256_90r.c \
		-I../src/sha256_90r -lm -O2 -fno-tree-vectorize
	./bin/timing_leak_test

# Timing test for GPU backend
timing-test-gpu:
	@echo "=== Building SHA256-90R GPU Timing Leak Test ==="
	cd tests && gcc -o ../bin/timing_leak_test_gpu timing_leak_test.c ../src/sha256_90r/sha256.c ../src/sha256_90r/sha256_90r.c \
		-I../src/sha256_90r -lm -O2 -DUSE_CUDA -fno-tree-vectorize
	./bin/timing_leak_test_gpu gpu

# Timing test for FPGA backend
timing-test-fpga:
	@echo "=== Building SHA256-90R FPGA Timing Leak Test ==="
	cd tests && gcc -o ../bin/timing_leak_test_fpga timing_leak_test.c ../src/sha256_90r/sha256.c ../src/sha256_90r/sha256_90r.c ../src/sha256_90r/sha256_90r_fpga.c \
		-I../src/sha256_90r -lm -O2 -DUSE_FPGA_PIPELINE -fno-tree-vectorize
	./bin/timing_leak_test_fpga fpga

# Timing test for JIT backend
timing-test-jit:
	@echo "=== Building SHA256-90R JIT Timing Leak Test ==="
	cd tests && gcc -o ../bin/timing_leak_test_jit timing_leak_test.c ../src/sha256_90r/sha256.c ../src/sha256_90r/sha256_90r.c ../src/sha256_90r/sha256_90r_jit.c \
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
	@echo "  verify-all       - Run all verification tests with benchmarks"
	@echo "  verify-aes       - Run AES-XR verification with performance tests"
	@echo "  verify-blowfish  - Run Blowfish-XR verification with performance tests"
	@echo "  verify-sha256    - Run SHA256-90R verification with performance tests"
	@echo "  verify-base64    - Run Base64X verification with performance tests"
	@echo "  bench-simple      - Simple benchmark (recommended, clean throughput measurement)"
	@echo "  bench-optimized   - Optimized benchmark with AVX2/AVX-512 and multi-threading"
	@echo "  bench             - Quick benchmark (uses pre-built binary, saves to results_latest.txt)"
	@echo "  bench-comprehensive - Full benchmark suite (all backends, saves to results_full.txt)"
	@echo "  bench-sha256     - Build and run SHA256-90R CPU benchmarks"
	@echo "  bench-sha256-cuda- Build and run SHA256-90R CUDA benchmarks"
	@echo "  timing-test*     - Run timing side-channel tests (scalar/gpu/fpga/jit)"
	@echo "  install          - Install libraries and headers"
	@echo "  uninstall        - Remove installed files"
	@echo "  clean            - Remove all build artifacts"

# Installation configuration
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include
PKGCONFIGDIR = $(LIBDIR)/pkgconfig

# Build library
lib/libsha256_90r.a: src/sha256_90r/sha256.c src/sha256_90r/sha256_90r.c
	@mkdir -p lib
	gcc -c src/sha256_90r/sha256.c -o lib/sha256.o -O3 -march=native $(CFLAGS)
	gcc -c src/sha256_90r/sha256_90r.c -o lib/sha256_90r.o -O3 -march=native -Isrc/sha256_90r $(CFLAGS)
	ar rcs lib/libsha256_90r.a lib/sha256.o lib/sha256_90r.o

# Install target
install: lib/libsha256_90r.a
	@echo "=== Installing SHA256-90R ==="
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)/sha256_90r
	install -d $(DESTDIR)$(PKGCONFIGDIR)
	install -m 644 lib/libsha256_90r.a $(DESTDIR)$(LIBDIR)/
	install -m 644 src/sha256_90r/sha256.h $(DESTDIR)$(INCLUDEDIR)/sha256_90r/
	install -m 644 src/sha256_90r/sha256_90r.h $(DESTDIR)$(INCLUDEDIR)/sha256_90r/
	@echo "Creating pkg-config file..."
	@echo "prefix=$(PREFIX)" > $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "exec_prefix=\$${prefix}" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "libdir=\$${exec_prefix}/lib" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "includedir=\$${prefix}/include" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "Name: SHA256-90R" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "Description: Extended round SHA-256 cryptographic hash function" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "Version: 3.0.0" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "Libs: -L\$${libdir} -lsha256_90r -lm" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "Cflags: -I\$${includedir}/sha256_90r" >> $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	@echo "Installation complete!"

# Uninstall target
uninstall:
	@echo "=== Uninstalling SHA256-90R ==="
	rm -f $(DESTDIR)$(LIBDIR)/libsha256_90r.a
	rm -f $(DESTDIR)$(INCLUDEDIR)/sha256_90r/sha256.h
	rm -f $(DESTDIR)$(INCLUDEDIR)/sha256_90r/sha256_90r.h
	rm -f $(DESTDIR)$(PKGCONFIGDIR)/sha256_90r.pc
	-rmdir $(DESTDIR)$(INCLUDEDIR)/sha256_90r 2>/dev/null || true
	@echo "Uninstall complete!"

bench-quick:
	@echo "=== Building SHA256-90R Quick Benchmark Suite ==="
	mkdir -p bin
	gcc -o bin/sha256_90r_comprehensive_bench benchmarks/sha256_90r_bench.c src/sha256_90r/sha256.c \
		src/sha256_90r/sha256_90r.c src/sha256_90r/sha256_90r_jit.c src/sha256_90r/sha256_90r_fpga.c \
		-Isrc/sha256_90r -lm -lpthread -O3 -march=native -DUSE_SIMD -DUSE_SHA_NI -DUSE_FPGA_PIPELINE -DUSE_JIT_CODEGEN
	@echo "=== Running Quick Benchmarks (1 iteration, 1MB only) ==="
	./bin/sha256_90r_comprehensive_bench --quick | tee benchmarks/results_quick.txt

bench-full:
	@echo "=== Building SHA256-90R Full Benchmark Suite ==="
	mkdir -p bin
	gcc -o bin/sha256_90r_comprehensive_bench benchmarks/sha256_90r_bench.c src/sha256_90r/sha256.c \
		src/sha256_90r/sha256_90r.c src/sha256_90r/sha256_90r_jit.c src/sha256_90r/sha256_90r_fpga.c \
		-Isrc/sha256_90r -lm -lpthread -O3 -march=native -DUSE_SIMD -DUSE_SHA_NI -DUSE_FPGA_PIPELINE -DUSE_JIT_CODEGEN
	@echo "=== Running Full Comprehensive Benchmarks ==="
	./bin/sha256_90r_comprehensive_bench | tee benchmarks/results_full.txt
