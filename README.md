# Benchmarking of DLCs using cut-and-choose verifiable encryption to BLS signatures

DLCs via verifiable encryption with BLS as the attestation scheme.
See the paper: https://eprint.iacr.org/2022/499
The point of this repo is to benchmark. The code is not good or secure in practice.

In the protocol "Alice" verifiably encrypts two secret scalars (representing 0 and 1, or just 0 if `--monotone` is enabled) for each bit that an oracle will attest to.
In addition she pads shares of secret values by a combination of these secret scalars such that if an oracle attests to a certain outcome the receiver of the encryption will be able to decrypt the secret share corresponding to that outcome (and that oracle). Should enough oracles attest to the same thing they will recover the secret value for that outcome.

If `--monotone` is enabled then Bob will be able to decrypt not only the secret corresponding to the exact outcome but also all outcomes indexed above the outcome. This models the case where Bob values lower attestations than higher ones so Alice doesn't mind giving him the secrets for the attested outcome and all those above it.

## Run it

E.g. 2-of-3 oracles attesting to 100 possible outcomes with 30 bit statistical security:

```
cargo run --release -- -s 30 --n-outcomes 100 --threshold 2 --n-oracles 3
```

with *monotone* payouts:

```
cargo run --release -- -s 30 --n-outcomes 100 --threshold 2 --n-oracles 3 --monotone
```

To model computational security just set `-s` to `128` or whatever you find tolerable.

```
cargo run --release -- -s 128 --n-outcomes 100 --threshold 2 --n-oracles 3 --monotone
```


To compare against `rust-dlc` you should model time taken to sign and verify ECDSA adaptor sigs:


```
cargo run --release -- -s 128 --n-outcomes 100 --threshold 2 --n-oracles 3 --monotone --model-ecdsa-adaptor
```


