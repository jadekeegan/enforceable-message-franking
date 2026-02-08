#!/usr/bin/env python3
"""
Format benchmark results for core scheme functions into a CSV file.
Usage: python scripts/generate_csv.py [--scheme basic|elgamal|all]
"""

import argparse
import csv
from pathlib import Path
from typing import Dict

from benchmark_utils import load_benchmark_data, format_time


def write_csv_file(data: Dict[str, Dict[int, float]], output_file: str):
    """Write benchmark data to a CSV file."""
    sizes = sorted({size for func_data in data.values() for size in func_data.keys()})
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Function'] + [f'{size} bytes' for size in sizes]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        
        for func in sorted(data.keys()):
            row = {'Function': func}
            for size in sizes:
                col_name = f'{size} bytes'
                if size in data[func]:
                    row[col_name] = format_time(data[func][size])
                else:
                    row[col_name] = ''
            writer.writerow(row)
    
    print(f"CSV saved to {output_file}")


def generate_csv(scheme: str):
    # Load benchmark data
    data = load_benchmark_data(scheme, __file__)
    
    # Generate CSV
    output_file = str(Path(__file__).parent / f'{scheme}_benchmark.csv')
    write_csv_file(data, output_file)


def main():
    """Generate benchmark results CSV file."""
    parser = argparse.ArgumentParser(description='Generate benchmark results CSV file.')
    parser.add_argument('--scheme', type=str, default='basic', help='Name of the scheme (e.g., "basic", "elgamal")')
    args = parser.parse_args()

    if args.scheme == 'all':
        for scheme in ['basic', 'elgamal']:
            generate_csv(scheme)
    else:
        generate_csv(args.scheme)


if __name__ == '__main__':
    main()
