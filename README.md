# Sketch of DLCs using cut-and-choose verifiable encryption

important points:

1. The ElGamal commits are made to a single fixed NUMS point
2. The first group element in the ElGamal commitments/encryption is in `G_2` but it should probably be in `G_1` instead.
3. It doesn't work I think because elements of `G_T` can't be hashed or serialized properly at the moment and the hack I used (hashing the debug printing of them) doesn't work 😫
4. The parameters I took are from https://eprint.iacr.org/2014/667.pdf Appendix A table 2 (number of outcomes 1024, bucket_size: 6, proportion of balls not to break: 0.85).
5. I implemented the cut-and-choose interactively (not via Fiat-Shamir) but this could easily be changed.
6. It's slow because ElGamal in `G_T` is slow.


## Run it

```
cargo run --release
```
