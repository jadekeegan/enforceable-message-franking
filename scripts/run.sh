#!/bin/bash

if [ "$1" = "--amf" ]; then
	if [ -z "$2" ]; then
		echo "Usage: $0 [--amf PATH_TO_AMF_REPOSITORY]" >&2
		exit 1
	fi
	amf_repository="$2"
elif [ -n "$1" ]; then
	echo "Usage: $0 [--amf PATH_TO_AMF_REPOSITORY]" >&2
	exit 1
fi

cargo clean

echo ""
echo "Building All Packages!"
echo ""
cargo build

echo ""
echo "Running Benchmarks for Lite Scheme!"
echo ""
cargo bench --bench lite_frank --bench lite_verify --bench lite_moderate

echo ""
echo "Running Benchmarks for EMF Scheme!"
echo ""
cargo bench --bench emf_frank --bench emf_verify --bench emf_moderate

echo ""
echo "Generating Benchmark Tables!"
echo ""
python3 scripts/generate_table.py --scheme all

echo ""
echo "Running Schemes and Reporting Communication Costs!"
echo ""
cargo run -- --msg-size 100 --lite --emf --print-costs

if [ -n "$amf_repository" ]; then
	echo ""
	echo "Running Optional AMF Comparison!"
	echo ""
	python3 scripts/run_comparison.py --amf "$amf_repository"
fi