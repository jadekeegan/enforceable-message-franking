#!/usr/bin/env python3
"""
Format benchmark results for the core scheme functions into a table.
Usage: python generate_table.py [--csv]
"""

import argparse
from pathlib import Path
from typing import Dict, List

from benchmark_utils import load_benchmark_data, format_time


def print_markdown_table(data: Dict[str, Dict[int, float]], sizes: List[int]):
    """Print a markdown table with aligned columns."""
    # Calculate column widths
    func_width = max(len(func) for func in data.keys()) if data else 8
    func_width = max(func_width, 8)  # Minimum width for "Function"
    
    size_widths = {}
    for size in sizes:
        col_width = len(f"{size} bytes")
        for func in data.keys():
            if size in data[func]:
                col_width = max(col_width, len(format_time(data[func][size])))
        size_widths[size] = max(col_width, 3)  # Minimum 3 for " - "
    
    # Build header
    header = f"| {'Function':<{func_width}} |"
    separator = f"|{'-' * (func_width + 2)}|"
    
    for size in sizes:
        width = size_widths[size]
        header += f" {f'{size} bytes':<{width}} |"
        separator += f"{'-' * (width + 2)}|"
    
    print(header)
    print(separator)
    
    # Build rows
    for func in sorted(data.keys()):
        row = f"| {func:<{func_width}} |"
        for size in sizes:
            width = size_widths[size]
            value = format_time(data[func][size]) if size in data[func] else "-"
            row += f" {value:<{width}} |"
        print(row)


def print_csv_table(data: Dict[str, Dict[int, float]], sizes: List[int], output_file: str):
    """Save benchmark data as CSV."""
    lines = ["Function," + ",".join(str(size) for size in sizes)]
    
    for func in sorted(data.keys()):
        row = [func]
        for size in sizes:
            row.append(f"{data[func][size]:.2f}" if size in data[func] else "-")
        lines.append(",".join(row))
    
    Path(output_file).write_text("\n".join(lines))
    print(f"CSV saved to {output_file}")


def main():
    """Generate benchmark results table."""
    parser = argparse.ArgumentParser(description='Generate benchmark results table.')
    parser.add_argument('--csv', action='store_true', 
                       help='Save as CSV to scripts/benchmark_results.csv')
    args = parser.parse_args()
    
    # Load benchmark data
    data = load_benchmark_data(__file__)
    sizes = sorted({size for func_data in data.values() for size in func_data.keys()})
    
    # Output table
    if args.csv:
        print_csv_table(data, sizes, str(Path(__file__).parent / 'benchmark_results.csv'))
    else:
        print_markdown_table(data, sizes)


if __name__ == '__main__':
    main()