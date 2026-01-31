#!/usr/bin/env python3
"""
Plot benchmark results for core scheme functions.
Usage: python generate_plot.py
"""

from pathlib import Path
from typing import Dict
import matplotlib.pyplot as plt

from benchmark_utils import load_benchmark_data


def plot_benchmark_data(data: Dict[str, Dict[int, float]], output_file: str):
    """Create a plot of message size vs. execution time."""
    plt.figure(figsize=(12, 7))
    
    # Plot each function
    for func in sorted(data.keys()):
        sizes = sorted(data[func].keys())
        times_us = [data[func][size] / 1000 for size in sizes]  # Convert ns to µs
        plt.plot(sizes, times_us, marker='o', linewidth=2, markersize=6, label=func)
    
    # Configure plot
    plt.xlabel('Message Size (bytes)', fontsize=12)
    plt.ylabel('Execution Time (µs)', fontsize=12)
    plt.title('Benchmark Performance: Message Size vs. Execution Time', fontsize=14, fontweight='bold')
    plt.legend(fontsize=11)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    # Use log scale for better visualization if data spans multiple orders of magnitude
    plt.xscale('log')
    
    # Save plot
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_file}")
    plt.close()


def main():
    """Generate benchmark performance plot."""
    # Load benchmark data
    data = load_benchmark_data(__file__)
    
    # Generate plot
    output_file = str(Path(__file__).parent / 'benchmark_plot.png')
    plot_benchmark_data(data, output_file)


if __name__ == '__main__':
    main()
