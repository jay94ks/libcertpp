# Post-quantum cryptography

[한국어](PQC.ko.md)

The library implements ML-KEM (FIPS 203) and ML-DSA (FIPS 204) from scratch.
This page is the current inventory; the implementation sequence and completed
investigations are preserved in [History](HISTORY.md).

## Current implementation

| Area | Current code |
| --- | --- |
| ML-KEM | `CMlKem` exposes the raw FIPS 203 operations and `MLKEM` implements `IKem` for ML-KEM-512/768/1024. Keys use the FIPS 203 encodings. |
| ML-DSA | `CMlDsa` implements `IAsymmetric` for ML-DSA-44/65/87. Signing consumes the message directly and uses hedged randomness. |
| Shared primitives | SHA3-256/512, SHAKE128/256 with incremental squeezing, secure compare/select/zeroization, and algorithm-specific NTT rings are implemented in-tree. |
| X.509 | ML-DSA public keys and signatures are wired into certificate and CSR parsing/building. The third-party IdenTrust ML-DSA-87 pilot root verifies in the test suite. ML-KEM SubjectPublicKeyInfo support is not implemented. |

ML-KEM and ML-DSA are checked against NIST ACVP vectors for every parameter
set. The tests include ML-KEM implicit rejection and key validation, ML-DSA
verification rejection cases, and an independently produced ML-DSA
certificate. See [engineering and risk](pqc/engineering.md) for the exact test
surfaces and current security limits.

## Detailed pages

- [Standards and interface design](pqc/design.md)
- [Engineering, validation, and risk](pqc/engineering.md)
- [Remaining PQC work](pqc/implementation.md)

Completed implementation work is organized in History chapters
[04](history/04-ml-kem.md), [05](history/05-secure-memory-and-ml-dsa.md),
[06](history/06-ml-dsa-and-portability.md), [07](history/07-protocol-primitives.md),
and [13](history/13-ml-dsa.md).
