#!/bin/bash

cargo clean

echo "\n\nBuilding All Packages!\n\n"
cargo build

echo "\n\nRunning Computation Time Benchmarks!\n\n"
cargo bench

echo "\n\nRunning Basic Scheme!\n\n"
cargo run -- --basic

echo "\n\nGenerating Benchmark Tables!\n\n"
python3 scripts/generate_table.py

echo "\n\nGenerating Benchmark Plots!\n\n"
python3 scripts/generate_plot.py