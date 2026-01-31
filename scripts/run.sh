#!/bin/bash

cargo clean

echo "\n\nBuilding All Packages!\n\n"
cargo build

echo "\n\nRunning Basic Core Functions Scheme!\n\n"
cargo bench -- "basic/frank" "basic/verify" "basic/moderate"

echo "\n\nGenerating Benchmark Tables!\n\n"
python3 scripts/generate_table.py

echo "\n\nGenerating Benchmark Plots!\n\n"
python3 scripts/generate_plot.py