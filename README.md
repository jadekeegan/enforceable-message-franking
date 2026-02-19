# Enforceable Message Franking Implementation

## Running Benchmarks

This project uses [Criterion.rs](https://github.com/bheisler/criterion.rs) for benchmarking. Benchmark functions are located in the `benches/` directory. In order to run the benchmarks, you will need to ensure that the Rust tool chain is installed on your machine.

Run `cargo bench` to run all benchmarks.

Run `cargo bench -- {group}` to run benchmarks for a particular group of benchmarks. The benchmarks are organized in groups as follows:

- `lite`: prefixes all functions specific to the EMF-lite scheme
- `emf`: prefixes all functions specific to the EMF scheme
- `elgamal_enc`: prefixes all functions used in the El Gamal encryption primitive
- `mac_ggm`: prefixes all functions used in the Mac GGM primitive
- `common`: prefixes all scheme agnostic utility functions

Run `cargo bench --bench {scheme}_{method}` to run benchmarks for a specific method. For example, `cargo bench --bench lite_accept_session` would run the benchmark for the EMF-lite scheme's `accept_session` method.

Here are a few other useful command line prompts (maybe turn into scripts):

```bash
# Run benchmarks for frank from both the EMF-lite and EMF schemes.
cargo bench -- frank

# Run benchmarks for verify from both the EMF-lite and EMF schemes
# for messages of size 100.
cargo bench --bench lite_verify --bench emf_verify -- "size 100"

# Run benchmarks for the core functions of the EMF-lite scheme.
cargo bench --bench lite_frank --bench lite_verify --bench lite_moderate

# Run benchmarks for the ZK proofs of the EMF-lite scheme.
cargo bench -- "lite/zk"
```

Criterion also generates HTML reports for all benchmarks run. To view these, you may run `start target/criterion/report/index.html` in the root directory.
