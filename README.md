# Sketch of DLCs using cut-and-choose verifiable encryption to BLS signatures

DLCs via verifiable encryption with BLS as the attestation scheme.

In the protocol "Alice" verifiably encrypts two secret scalars (representing 0 and 1) for each bit that an oracle will attest to.
In addition she pads secret shares of secret values by these secret scalars such that if an oracle attests to a certain outcome the receiver of the encryption will be able to decrypt the secret share corresponding to that outcome (and that oracle). Should enough oracles attest to the same thing they will recover the secret values.



## Run it

```
cargo run --release -- -s 30 --n-outcomes 100 --threshold 2 --n-oracles 3
```
