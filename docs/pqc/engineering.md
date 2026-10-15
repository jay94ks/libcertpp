# Engineering, validation, and risk

[한국어](engineering.ko.md)

← [Post-quantum cryptography](../PQC.md)

## Implemented substrate

ML-KEM and ML-DSA share Keccak primitives but use separate polynomial-ring
implementations because their moduli and NTT structures differ. The current
code is organized as follows:

- `SHAKE128` and `SHAKE256` provide incremental `squeeze()` output; SHA3-256
  and SHA3-512 share the same Keccak permutation with fixed-output framing.
- `src/crypto/kems/mlkemring.hpp`, `mlkemcodec.hpp`, and
  `mlkemsampler.cpp` implement ML-KEM's ring, packing, compression, and
  samplers.
- `src/crypto/asyms/mldsaring.hpp`, `mldsacodec.hpp`,
  `mldsarounding.hpp`, and `mldsasampler.hpp` implement the corresponding
  ML-DSA units.
- `CSecure` supplies constant-time equality and selection plus explicit
  zeroization. ML-KEM decapsulation uses implicit rejection rather than
  reporting a distinguishable ciphertext failure.

## Validation in the tree

`tests/crypto/kems/kat_mlkem.cpp` checks key generation, encapsulation,
decapsulation, implicit rejection, and key validation against NIST ACVP data
for all three ML-KEM parameter sets. The surrounding `mlkem*.cpp` tests cover
the ring, codec, public interface, tampering, and chunk boundaries.

`tests/crypto/asyms/kat_mldsa.cpp` and `kat_mldsaver.cpp` check ML-DSA key
generation, deterministic and hedged signing, valid verification, and every
represented rejection reason across all three parameter sets. The remaining
`mldsa*.cpp` tests exercise the ring, samplers, rounding, packing, and public
interface. `tests/x509/realcerts.cpp` verifies an independently produced
ML-DSA-87 certificate, so the evidence does not rely only on the library
round-tripping its own output.

## Security limits

ML-DSA signing uses Fiat-Shamir-with-aborts, so the number of attempts depends
on secret-derived values. The implementation uses an unbounded retry loop,
zeroizes secret intermediates on every exit path, and avoids secret-indexed
tables within an attempt. It has not undergone a dedicated timing-side-channel
audit against published Dilithium attacks.

The ACVP and interoperability tests establish functional compatibility; they
do not constitute a third-party security audit. This limitation is tracked as
remaining work in both the [PQC work list](implementation.md) and the
[constant-time roadmap](../roadmap/performance.md).
