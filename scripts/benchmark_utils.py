"""
Shared utilities for parsing and collecting Criterion benchmark data.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def parse_benchmark_result(benchmark_path: Path) -> Optional[Tuple[str, int, float]]:
    """
    Parse benchmark result and return (function_name, message_size, mean_time_ns) or None.
    
    Args:
        benchmark_path: Path to the benchmark directory
        
    Returns:
        Tuple of (function_name, message_size, mean_time_ns) if valid, None otherwise
    """
    try:
        estimates_file = benchmark_path / 'new' / 'estimates.json'
        if not estimates_file.exists():
            return None
        
        with open(estimates_file) as f:
            data = json.load(f)
        
        mean_time = data['mean']['point_estimate']
        
        # Parse "frank() message of size 100" -> ("frank", 100)
        bench_name = benchmark_path.name
        if "message of size" in bench_name:
            parts = bench_name.split()
            func_name = parts[0].replace("()", "")
            msg_size = int(parts[-1])
            return (func_name, msg_size, mean_time)
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, IndexError):
        pass
    
    return None


def collect_benchmark_data(criterion_dir: Path, functions: List[str]) -> Dict[str, Dict[int, float]]:
    """
    Collect benchmark data for specified functions.
    
    Args:
        criterion_dir: Path to the criterion benchmark directory
        functions: List of function names to collect data for
        
    Returns:
        Dictionary mapping function names to {message_size: mean_time_ns}
    """
    data = {func: {} for func in functions}
    
    for func in functions:
        group_path = criterion_dir / "basic" / func
        if not group_path.exists():
            continue
        
        # Parse all benchmark directories
        for bench_dir in group_path.iterdir():
            if bench_dir.is_dir():
                result = parse_benchmark_result(bench_dir)
                if result:
                    func_name, msg_size, mean_time = result
                    data[func_name][msg_size] = mean_time
    
    return data


def format_time(nanoseconds: float) -> str:
    """
    Format time in nanoseconds to human-readable format.
    
    Args:
        nanoseconds: Time value in nanoseconds
        
    Returns:
        Formatted string with appropriate unit (ns, µs, ms, s)
    """
    if nanoseconds < 1_000:
        return f"{nanoseconds:.2f} ns"
    elif nanoseconds < 1_000_000:
        return f"{nanoseconds / 1_000:.2f} µs"
    elif nanoseconds < 1_000_000_000:
        return f"{nanoseconds / 1_000_000:.2f} ms"
    else:
        return f"{nanoseconds / 1_000_000_000:.2f} s"


def load_benchmark_data(
    script_path: str,
    functions: List[str] = ['frank', 'verify', 'moderate']
) -> Dict[str, Dict[int, float]]:
    """
    Load benchmark data from Criterion output directory.
    
    Args:
        script_path: Path to the calling script (__file__)
        functions: List of function names to collect data for
        
    Returns:
        Dictionary mapping function names to {message_size: mean_time_ns}
        
    Exits with error if benchmark data not found.
    """
    script_dir = Path(script_path).parent
    criterion_dir = script_dir.parent / 'target' / 'criterion'
    
    if not criterion_dir.exists():
        print("Error: Run benchmarks first with: cargo bench")
        sys.exit(1)
    
    data = collect_benchmark_data(criterion_dir, functions)
    
    if not any(data.values()):
        print("Error: No benchmark data found")
        sys.exit(1)
    
    return data
