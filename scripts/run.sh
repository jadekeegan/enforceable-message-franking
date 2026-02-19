#!/bin/bash

cargo clean

echo "\n\nBuilding All Packages!\n\n"
cargo build

echo "\n\nRunning Benchmarks for Lite Scheme!\n\n"
cargo bench --bench lite_frank --bench lite_verify --bench lite_moderate

echo "\n\nRunning Benchmarks for EMF Scheme!\n\n"
cargo bench --bench emf_frank --bench emf_verify --bench emf_moderate

echo "\n\nGenerating Benchmark Tables!\n\n"
python3 scripts/generate_table.py --scheme all

echo "\n\nRunning Schemes and Reporting Communication Costs!\n\n"
cargo run -- --msg-size 100 --lite --emf --print-costs