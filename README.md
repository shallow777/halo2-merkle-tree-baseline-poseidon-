# halo2-merkle-tree

This repo includes a few chips and circuits that slowly towards a fully function merkle tree chip implementation in Halo2 with the Poseidon hash function.

## Instruction

Compile the repo

```
cargo build
```

Run examples

```
cargo test -- --nocapture test
```

run the poseidon baseline
```
RAYON_NUM_THREADS=1 cargo run --example prove_merkle --release
```