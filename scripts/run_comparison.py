#!/usr/bin/env python3
"""Run the separate AMF benchmark and print its results."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from benchmark_utils import format_time


Benchmark = Tuple[str, int, float]


def run_command(command: list[str], cwd: Path, target_dir: Path) -> None:
    environment = {**os.environ, "CARGO_TARGET_DIR": str(target_dir)}
    print(f"Running {' '.join(command)} in {cwd}")
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def read_estimate(path: Path) -> float:
    with path.open(encoding="utf-8") as estimate_file:
        return float(json.load(estimate_file)["mean"]["point_estimate"])


def collect_results(target_dir: Path) -> Iterable[Benchmark]:
    group_dir = target_dir / "criterion" / "compressed_amf"
    for function in ("franking", "verifying", "judging"):
        estimate = group_dir / function / "new" / "estimates.json"
        if estimate.exists():
            yield function, 100, read_estimate(estimate)


def print_markdown_table(data: Dict[str, Dict[int, float]], sizes: List[int]) -> None:
    """Print benchmark results with one column for each message size."""
    function_width = max((len(function) for function in data), default=8)
    function_width = max(function_width, len("Function"))

    size_widths = {}
    for size in sizes:
        column_width = len(f"{size} bytes")
        for function in data:
            if size in data[function]:
                column_width = max(column_width, len(format_time(data[function][size])))
        size_widths[size] = column_width

    header = f"| {'Function':<{function_width}} |"
    separator = f"|{'-' * (function_width + 2)}|"
    for size in sizes:
        width = size_widths[size]
        header += f" {f'{size} bytes':<{width}} |"
        separator += f"{'-' * (width + 2)}|"

    print(header)
    print(separator)
    for function in sorted(data):
        row = f"| {function:<{function_width}} |"
        for size in sizes:
            width = size_widths[size]
            value = format_time(data[function][size]) if size in data[function] else "-"
            row += f" {value:<{width}} |"
        print(row)


def generate_table(results: Iterable[Benchmark]) -> None:
    """Format collected AMF benchmark results as a Markdown table."""
    data: Dict[str, Dict[int, float]] = {}
    for function, message_size, nanoseconds in results:
        data.setdefault(function, {})[message_size] = nanoseconds

    sizes = sorted({size for function_data in data.values() for size in function_data})
    print_markdown_table(data, sizes)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--amf", required=True, type=Path, help="Path to the separate AMF repository")
    args = parser.parse_args()

    project_dir = Path(__file__).resolve().parents[1]
    amf_dir = args.amf.expanduser().resolve()
    if not (amf_dir / "Cargo.toml").is_file():
        parser.error(f"AMF repository does not contain Cargo.toml: {amf_dir}")

    target_dir = project_dir / "target" / "comparison" / "amf"
    run_command(["cargo", "bench", "--bench", "compressed_franking"], amf_dir, target_dir)

    results = list(collect_results(target_dir))
    if not results:
        print("Error: no AMF benchmark results were found", file=sys.stderr)
        return 1

    print("\n### AMF Comparison\n")
    generate_table(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
