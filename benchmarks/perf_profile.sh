#!/bin/bash
# SHA256-90R Performance Profiling Script
# Requires Linux perf tools

# Check if perf is available
if ! command -v perf &> /dev/null; then
    echo "Error: perf not found. Install with: sudo apt-get install linux-tools-common"
    exit 1
fi

# Build optimized binary if not exists
if [ ! -f bin/bench_optimized ]; then
    echo "Building optimized benchmark..."
    make bench-optimized
fi

# Output file
OUTPUT="benchmarks/perf_analysis.txt"
echo "SHA256-90R Performance Analysis" > $OUTPUT
echo "==============================" >> $OUTPUT
echo "Date: $(date)" >> $OUTPUT
echo "" >> $OUTPUT

# Basic performance counters
echo "=== Basic Performance Counters ===" >> $OUTPUT
echo "Running basic performance analysis..." 
perf stat -e cycles,instructions,cache-references,cache-misses,branches,branch-misses \
    ./bin/bench_simple 2>&1 | tee -a $OUTPUT

echo "" >> $OUTPUT
echo "=== Detailed CPU Pipeline Analysis ===" >> $OUTPUT
echo "Running detailed pipeline analysis..."
perf stat -d ./bin/bench_simple 2>&1 | tee -a $OUTPUT

echo "" >> $OUTPUT
echo "=== IPC and Stall Analysis ===" >> $OUTPUT
echo "Running IPC analysis..."
perf stat -e cycles,instructions,stalled-cycles-frontend,stalled-cycles-backend \
    ./bin/bench_simple 2>&1 | tee -a $OUTPUT

echo "" >> $OUTPUT
echo "=== Memory Access Pattern ===" >> $OUTPUT
echo "Running memory analysis..."
perf stat -e L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses \
    ./bin/bench_simple 2>&1 | tee -a $OUTPUT

echo "" >> $OUTPUT
echo "=== SIMD Instruction Usage ===" >> $OUTPUT
echo "Running SIMD analysis..."
if [ -f /proc/cpuinfo ] && grep -q avx2 /proc/cpuinfo; then
    perf stat -e fp_arith_inst_retired.256b_packed_single,fp_arith_inst_retired.256b_packed_double \
        ./bin/bench_simple 2>&1 | tee -a $OUTPUT
fi

echo "" >> $OUTPUT
echo "=== Branch Prediction ===" >> $OUTPUT
echo "Running branch analysis..."
perf stat -e branches,branch-misses,branch-loads,branch-load-misses \
    ./bin/bench_simple 2>&1 | tee -a $OUTPUT

# Generate cycle breakdown
echo "" >> $OUTPUT
echo "=== Where the Cycles Go ===" >> $OUTPUT
echo "Analyzing cycle distribution..."

# Run perf record and report
perf record -g ./bin/bench_simple > /dev/null 2>&1
perf report --stdio --no-children | head -50 >> $OUTPUT

# Clean up
rm -f perf.data*

echo ""
echo "Performance analysis complete. Results saved to: $OUTPUT"

# Summary
echo ""
echo "=== Quick Summary ==="
grep -E "(cycles|instructions|IPC|cache-misses|branch-misses)" $OUTPUT | tail -10
