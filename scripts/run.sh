#!/bin/bash

cargo clean

echo "\n\nBuilding All Packages!\n\n"
cargo build

echo "\n\nRunning Benchmarks for Basic Scheme!\n\n"
cargo bench -- "basic/frank" "basic/verify" "basic/moderate"

echo "\n\nRunning Benchmarks for ElGamal Scheme!\n\n"
cargo bench -- "elgamal/frank" "elgamal/verify" "elgamal/moderate"

echo "\n\nGenerating Benchmark Tables!\n\n"
python3 scripts/generate_table.py --scheme all

echo "\n\nGenerating Benchmark Plots!\n\n"
python3 scripts/generate_plot.py --scheme all

echo "\n\nRunning Schemes and Reporting Communication Costs!\n\n"
cargo run -- --msg-size 100 --basic --elgamal --print-costs