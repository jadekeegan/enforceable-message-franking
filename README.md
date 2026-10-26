# Enforceable Message Franking Implementation

This is the Rust implementation and benchmarking of Enforceable Message Franking.

## Project Structure

The implementations for the standard EMF scheme and its lite version can be found in the `src/schemes` directory as `lib_emf.rs` and `lib_lite.rs` respectively. The `src/toolbox` directory contains implementations of primitives in individual `lib_{primitive}.rs` files, as well as a `lib_common.rs` file for shared code between both schemes.

## Scheme Details

### EMF-Lite Primitives:

- Algebraic MAC-GGM
- Non-Interactive Zero Knowledge Proof of Knowledge
- SHA256/SHA512_256 Hash
- Ristretto Elliptic Curve Group ([Ristretto](https://ristretto.group/) and its [Rust Implementation](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto))

### EMF Primitives:

- All primitives used in EMF-lite.
- El-Gamal Encryption Scheme

## Usage

The most straightforward method for producing results for the schemes is by executing `scripts/run.sh` or `bash scripts/run.sh`. This script runs and formats Frank, Verify, and Moderate benchmarks for the EMF and EMF-lite schemes. It also runs the flow of both schemes with communication costs printed.

> [!NOTE]
> If necessary, give the script execute permissions by first running `chmod u+x scripts/run.sh`.

The commands listed in `run.sh` can be run individually with some parameterization. Read further for more information.

### Requirements

- [Rust](https://www.rust-lang.org/tools/install) 1.85 or newer, including Cargo.
- Python 3, required by `scripts/run.sh` to generate benchmark tables.

The minimum supported Rust version is 1.85.0 to support Rust 2024. Dependencies are resolved by Cargo from `Cargo.toml`.

## Running Tests & Viewing Communication Costs

We implement basic unit tests for correctness, which can be found in their corresponding files. Run `cargo test` to see the results of these tests. These tests are **not** intended to be comprehensive.

To run the schemes, run the `main.rs` file using `cargo run --` with the appropriate parameters.

```bash
Usage: enforceable_message_franking.exe [OPTIONS]

Options:
      --lite
      --emf
      --msg-size <MSG_SIZE>  [default: 100]
      --print-costs
  -h, --help                 Print help
  -V, --version              Print version

# Run both EMF-lite and EMF with a 1000B message and print communication costs.
> cargo run -- --msg-size 1000 --lite --emf --print-costs
```

## Running Benchmarks

This project uses [Criterion.rs](https://github.com/bheisler/criterion.rs) for benchmarking. Benchmark functions are located in the `benches/` directory. In order to run the benchmarks, you will need to ensure that the Rust tool chain is installed on your machine.

Where relevant, our benchmarks are parameterized by message size. You will need to modify the `MSG_SIZE_SCALE` constant in `bench_helpers.rs` if you would like to run benchmarks on different message sizes than we use.

Run `cargo bench` to run all benchmarks.

Run `cargo bench -- {group}` to run benchmarks for a particular group of benchmarks. The benchmarks are organized in groups as follows:

- `lite`: all benchmarks specific to the EMF-lite scheme
- `emf`: all benchmarks specific to the EMF scheme
- `elgamal`: all benchmarks used in the El Gamal encryption primitive
- `mac_ggm`: all benchmarks used in the Mac GGM primitive
- `common`: all benchmarks for scheme-agnostic utility functions

Run `cargo bench --bench {scheme}_{method}` to run benchmarks for a specific method, where scheme is `lite` for EMF-lite and `emf` for EMF. For example, `cargo bench --bench lite_verify` would run the benchmark for the EMF-lite scheme's `verify` method.

Here are a few other useful command line prompt formats:

```bash
# Run benchmarks for frank from both the EMF-lite and EMF schemes.
cargo bench -- frank

# Run benchmarks for verify from both the EMF-lite and EMF schemes
# for messages of size 100.
cargo bench --bench lite_verify --bench emf_verify -- "size 100"

# Run benchmarks for the core functions of the EMF-lite scheme.
cargo bench --bench lite_frank --bench lite_verify --bench lite_moderate
```

Criterion also generates HTML reports of all benchmarks. From the repository root, open the report with the command for your operating system:

```bash
# macOS
open target/criterion/report/index.html

# Linux
xdg-open target/criterion/report/index.html

# Windows
start target/criterion/report/index.html
```

### Benchmark Results

Below are our results on an 11th Gen Intel i7 processor @ 3.6 GHz in microseconds for a 100 byte message.

| Scheme   | Frank | Verify | Moderate |
| -------- | ----- | ------ | -------- |
| EMF-lite | 167.9 | 191.9  | 11.9     |
| EMF      | 244.5 | 250.0  | 42.4     |

Benchmark results may vary across hardware and software environments due to differing cryptographic implementations, particularly in the case of SHA-256 acceleration.

SHA-256 acceleration discrepancy is particularly relevant to the message size vs. computation time table generated by our `run.sh` script. Higher hashing overhead may dominate the computation time, resulting in higher computation times for large message sizes and thus lower ratios than the EMF paper reports.

### Comparison to Asymmetric Message Franking

If you would like to compare the benchmarks of Enforceable Message Franking to Asymmetric Message Franking, please refer to the following Rust implementation of AMF: https://github.com/jadekeegan/amaze-compressed.

We have included an optional parameter that allows you to run the AMF benchmarks after the EMF and EMF-lite benchmarks. To run the command as written below, you will need both repositories to be in the same parent directory, with the AMF implementation under the name `amaze-compressed`.

```bash
./scripts/run.sh --amf ../amaze-compressed
```

The second parameter is simply the path to the repository, so if the AMF repository is under a different name or location, you may adjust the path as needed.
