#!/usr/bin/env python3
"""
Format benchmark results for the core scheme functions into a table.
Usage: python scripts/generate_table.py [--scheme basic|elgamal|all]
"""

import argparse
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


def generate_table(scheme: str):
    # Load benchmark data
    data = load_benchmark_data(scheme, __file__)
    sizes = sorted({size for func_data in data.values() for size in func_data.keys()})
    
    # Output table
    print_markdown_table(data, sizes)


def main():
    """Generate benchmark results table."""
    parser = argparse.ArgumentParser(description='Generate benchmark results table.')
    parser.add_argument('--scheme', type=str, default='basic', help='Name of the scheme (e.g., "basic", "elgamal")')
    args = parser.parse_args()

    if (args.scheme == 'all'):
        for scheme in ['basic', 'elgamal']:
            print(f"\n===> Scheme: {scheme.upper()}\n")
            generate_table(scheme)
    else:
        generate_table(args.scheme)
    

if __name__ == '__main__':
    main()