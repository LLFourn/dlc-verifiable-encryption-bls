## Sketch of DLCs using cut-and-choose verifiable encryption

important points:

1. The ElGamal commits are made to a single fixed nums point
2. The first group element in the ElGamal commitments/encryption is in `G_2` but it should probably be in `G_1` instead.
3. It doesn't work I think because elements of `G_T` can't be hashed or serialized properly at the moment and the hack I used (hashing the debug printing of them) doesn't work 😫
