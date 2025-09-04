# Makefile for SHA256-90R Cryptographic Algorithms

.PHONY: all clean test test-aes test-blowfish test-sha256 test-base64

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

# SHA256-90R tests
test-sha256:
	@echo "=== Building SHA256-90R tests ==="
	cd src/sha256_90r && gcc -o ../../bin/sha256_90r_test sha256_test.c sha256.c -I.
	./bin/sha256_90r_test

# Base64X tests
test-base64:
	@echo "=== Building Base64X tests ==="
	cd src/base64x && gcc -o ../../bin/base64x_test base64_test.c base64.c -I.
	./bin/base64x_test

# Clean build artifacts
clean:
	@echo "=== Cleaning build artifacts ==="
	find src -name "*.o" -delete
	find src -name "*_test" -delete
	find . -name "*.o" -delete
	rm -rf bin/*

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Build and run all tests (default)"
	@echo "  test       - Same as all"
	@echo "  test-aes   - Build and run AES-XR tests"
	@echo "  test-blowfish - Build and run Blowfish-XR tests"
	@echo "  test-sha256   - Build and run SHA256-90R tests"
	@echo "  test-base64   - Build and run Base64X tests"
	@echo "  clean      - Remove all build artifacts"
	@echo "  help       - Show this help message"
