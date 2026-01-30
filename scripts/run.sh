#!/bin/bash

cargo clean

echo "\n\nBuilding All Packages!\n\n"
cargo build

echo "\n\nRunning Computation Time Benchmarks!\n\n"
cargo bench

echo "\n\nRunning Basic Scheme!\n\n"
cargo run -- --basic