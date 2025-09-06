cmake_minimum_required(VERSION 3.16...3.28)
project(SHA256_90R VERSION 3.0.0 LANGUAGES C CXX)

# Force include dirs to stay relative-safe in generated files
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Use modern CMake policies for better portability
cmake_policy(SET CMP0076 NEW)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build test programs" ON)
option(BUILD_BENCHMARKS "Build benchmark programs" ON)
option(ENABLE_SIMD "Enable SIMD optimizations" ON)
option(ENABLE_SHA_NI "Enable SHA-NI hardware acceleration" ON)
option(ENABLE_ARM_CRYPTO "Enable ARM crypto extensions" ON)
option(ENABLE_CUDA "Enable CUDA GPU acceleration" OFF)
option(ENABLE_FPGA "Enable FPGA simulation" ON)
option(ENABLE_JIT "Enable JIT compilation" ON)
option(SECURE_MODE "Default to constant-time implementation" ON)
option(FAST_MODE "Enable fast mode optimizations" OFF)

# Compiler flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform detection and flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64)")
    set(X86_64 TRUE)
    if(ENABLE_SIMD)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
        add_definitions(-DUSE_SIMD)
    endif()
    if(ENABLE_SHA_NI)
        add_definitions(-DUSE_SHA_NI)
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(aarch64|arm64)")
    set(ARM64 TRUE)
    if(ENABLE_SIMD)
        add_definitions(-DUSE_SIMD)
    endif()
    if(ENABLE_ARM_CRYPTO)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+crypto")
        add_definitions(-DUSE_ARMV8_CRYPTO)
    endif()
endif()

# Security modes
if(SECURE_MODE)
    add_definitions(-DSHA256_90R_SECURE_MODE=1)
else()
    add_definitions(-DSHA256_90R_SECURE_MODE=0)
endif()

if(FAST_MODE)
    add_definitions(-DSHA256_90R_FAST_MODE=1)
endif()

# Optimization flags
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -funroll-loops -finline-functions")
    if(X86_64)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
    endif()
endif()

# Source files
set(SHA256_90R_SOURCES
    src/sha256_90r/sha256.c
)

set(SHA256_90R_HEADERS
    src/sha256_90r/sha256.h
    src/sha256_90r/sha256_90r.h
)

# Optional sources
if(ENABLE_CUDA)
    enable_language(CUDA)
    list(APPEND SHA256_90R_SOURCES src/sha256_90r/sha256_90r_cuda.cu)
    add_definitions(-DUSE_CUDA)
endif()

if(ENABLE_FPGA)
    list(APPEND SHA256_90R_SOURCES src/sha256_90r/sha256_90r_fpga.c)
    add_definitions(-DUSE_FPGA_PIPELINE)
endif()

if(ENABLE_JIT)
    list(APPEND SHA256_90R_SOURCES src/sha256_90r/sha256_90r_jit.c)
    add_definitions(-DUSE_JIT_CODEGEN)
endif()

# SHA256-90R library
add_library(sha256_90r ${SHA256_90R_SOURCES})
target_include_directories(sha256_90r PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/sha256_90r>
    $<INSTALL_INTERFACE:include/sha256_90r>
)

# Link libraries
target_link_libraries(sha256_90r PUBLIC m)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(sha256_90r PUBLIC pthread)
endif()

# AES-XR
add_library(aes_xr src/aes_xr/aes.c)
target_include_directories(aes_xr PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/aes_xr>
    $<INSTALL_INTERFACE:include/aes_xr>
)

# Blowfish-XR
add_library(blowfish_xr src/blowfish_xr/blowfish.c)
target_include_directories(blowfish_xr PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/blowfish_xr>
    $<INSTALL_INTERFACE:include/blowfish_xr>
)

# Base64X
add_library(base64x src/base64x/base64.c)
target_include_directories(base64x PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/base64x>
    $<INSTALL_INTERFACE:include/base64x>
)

# Install rules
install(TARGETS aes_xr blowfish_xr base64x
    EXPORT SHA256-90RTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(DIRECTORY src/aes_xr/ DESTINATION include/aes_xr FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/blowfish_xr/ DESTINATION include/blowfish_xr FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/base64x/ DESTINATION include/base64x FILES_MATCHING PATTERN "*.h")

# Test programs
if(BUILD_TESTS)
    # SHA256-90R tests
    add_executable(sha256_90r_test tests/crypto_xr_test.c)
    target_include_directories(sha256_90r_test PRIVATE
        src/sha256_90r
        src/aes_xr
        src/blowfish_xr
        src/base64x
    )
    target_link_libraries(sha256_90r_test sha256_90r aes_xr blowfish_xr base64x)
    
    add_executable(sha256_90r_verification tests/sha256_90r_verification.c)
    target_link_libraries(sha256_90r_verification sha256_90r m)
    
    add_executable(timing_leak_test tests/timing_leak_test.c)
    target_link_libraries(timing_leak_test sha256_90r m)
    
    # Other algorithm tests
    add_executable(aes_xr_test src/aes_xr/aes_test.c src/aes_xr/aes.c)
    target_include_directories(aes_xr_test PRIVATE src/aes_xr)
    target_link_libraries(aes_xr_test aes_xr)

    add_executable(blowfish_xr_test src/blowfish_xr/blowfish_test.c src/blowfish_xr/blowfish.c)
    target_include_directories(blowfish_xr_test PRIVATE src/blowfish_xr)
    target_link_libraries(blowfish_xr_test blowfish_xr)

    add_executable(base64x_test src/base64x/base64_test.c src/base64x/base64.c)
    target_include_directories(base64x_test PRIVATE src/base64x)
    target_link_libraries(base64x_test base64x)
    
    # Enable testing
    enable_testing()
    add_test(NAME sha256_90r_test COMMAND sha256_90r_test)
    add_test(NAME sha256_90r_verification COMMAND sha256_90r_verification)
    add_test(NAME timing_leak_test COMMAND timing_leak_test)
    add_test(NAME aes_xr_test COMMAND aes_xr_test)
    add_test(NAME blowfish_xr_test COMMAND blowfish_xr_test)
    add_test(NAME base64x_test COMMAND base64x_test)
endif()

# Benchmark programs
if(BUILD_BENCHMARKS)
    add_executable(bench_simple benchmarks/bench_simple.c)
    target_link_libraries(bench_simple sha256_90r m)
    
    add_executable(bench_optimized benchmarks/sha256_90r_bench_optimized.c)
    target_link_libraries(bench_optimized sha256_90r m pthread)
    
    add_executable(bench_comprehensive benchmarks/sha256_90r_bench.c)
    target_link_libraries(bench_comprehensive sha256_90r m pthread)
endif()

# Installation
install(TARGETS sha256_90r aes_xr blowfish_xr base64x
    EXPORT SHA256_90R_Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(FILES ${SHA256_90R_HEADERS}
    DESTINATION include/sha256_90r
)

install(DIRECTORY src/aes_xr/ DESTINATION include/aes_xr
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/blowfish_xr/ DESTINATION include/blowfish_xr
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/base64x/ DESTINATION include/base64x
        FILES_MATCHING PATTERN "*.h")

# pkg-config file
configure_file(sha256_90r.pc.in sha256_90r.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/sha256_90r.pc
    DESTINATION lib/pkgconfig
)

# CMake config
install(EXPORT SHA256_90R_Targets
    FILE SHA256_90RTargets.cmake
    DESTINATION lib/cmake/SHA256_90R
)

# Create config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/SHA256_90RConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SHA256_90RConfig.cmake
    INSTALL_DESTINATION lib/cmake/SHA256_90R
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/SHA256_90RConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/SHA256_90RConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/SHA256_90RConfigVersion.cmake
    DESTINATION lib/cmake/SHA256_90R
)
