# Federated Franking Implementation

## Running Benchmarks

This project uses [Criterion.rs](https://github.com/bheisler/criterion.rs) for benchmarking. Benchmark functions are located in the `benches/` directory. In order to run the benchmarks, you will need to ensure that the Rust tool chain is installed on your machine.

Run `cargo bench` to run all benchmarks.

Run `cargo bench -- {group}` to run benchmarks for a particular group of benchmarks. The benchmarks are organized in groups as follows:

- `basic`: prefixes all functions specific to the basic scheme
- `elgamal`: prefixes all functions specific to the El Gamal scheme
- `elgamal_enc`: prefixes all functions used in the El Gamal encryption primitive
- `mac_ggm`: prefixes all functions used in the Mac GGM primitive
- `common`: prefixes all scheme agnostic utility functions

Run `cargo bench --bench {scheme}_{method}` to run benchmarks for a specific method. For example, `cargo bench --bench basic_accept_session` would run the benchmark for the basic scheme's `accept_session` method.

Here are a few other useful command line prompts (maybe turn into scripts):

```bash
# Run benchmarks for frank from both the basic and elgamal schemes.
cargo bench -- frank

# Run benchmarks for verify from both the basic and elgamal schemes
# for messages of size 100.
cargo bench --bench basic_verify --bench elgamal_verify -- "size 100"

# Run benchmarks for the core functions of the basic scheme.
cargo bench --bench basic_frank --bench basic_verify --bench basic_moderate

# Run benchmarks for the ZK proofs of the basic scheme.
cargo bench -- "basic/zk"
```

Criterion also generates HTML reports for all benchmarks run. To view these, you may run `start target/criterion/report/index.html` in the root directory.
