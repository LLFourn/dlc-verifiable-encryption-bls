# Sketch of DLCs using cut-and-choose verifiable encryption to BLS signatures

DLCs via verifiable encryption with BLS as the attestation scheme.

In the protocol "Alice" verifiably encrypts a list of secret scalar's to their corresponding anticipated oracle attestation points such that when the oracle attests to an outcome "Bob" can decrypt it.


important points:

1. I implemented the cut-and-choose interactively (not via Fiat-Shamir) but this could easily be changed.
2. It's slow because ElGamal in `G_T` is slow.


## Run it

```
cargo run --release -- -s 30 --n-outcomes 100 --threshold 2 --n-oracles 3
```
