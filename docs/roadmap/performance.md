# Constant-time and performance work

[한국어](performance.ko.md)

This page contains only work that remains open. Current benchmark results and
methodology live in [Performance](../concepts/performance.md). Completed
optimizations, investigations, and negative results are recorded in
[History](../HISTORY.md) and [Not planned](not-planned.md).

## Security work

- **Finish constant-time prime-curve ECDH and ECDSA signing.** The ladder now
  processes the full group-order width, masked-swaps its registers, and uses no
  secret-indexed fixed-base table. The remaining blocker is `CBigNum` itself:
  it allocates and trims variable-width limbs and its arithmetic has
  operand-dependent cost. A shared fixed-width field strategy is still needed
  across the supported prime curves.
- **Audit ML-DSA signing for timing leakage.** The retry count in
  Fiat-Shamir-with-aborts is data-dependent by design. The current
  implementation zeroizes secret intermediates and avoids secret-indexed
  tables inside an iteration, but it has not had a dedicated timing-side-channel
  review against published Dilithium attacks. See [PQC engineering and
  risk](../pqc/engineering.md).

## Performance investigations

### OpenSSL 90% program

The active performance goal covers every algorithm and operation implemented by
the library. A directly comparable row is complete when certpp reaches at least
90% of the equivalent OpenSSL operation under matched conditions. Throughput
rows use `certpp / OpenSSL`; latency rows use `OpenSSL / certpp`, so a larger
ratio is always better. The comparison uses Release builds on the same machine,
identical inputs and key sizes, independent warmed-up loops, and at least three
complete harness runs. The median ratio is the decision value; a repeatable run
below 0.90 must be investigated rather than hidden by a best result.

OpenSSL does not expose every algorithm or parameter set that certpp implements.
For such a row, record the OpenSSL version and provider configuration that lacks
the operation, name an established alternative implementation when one exists,
and retain an internal before/after baseline. Do not invent an OpenSSL ratio for
an unavailable operation. The goal is complete only when every direct row is at
least 0.90 and every unavailable row has that evidence and an alternative
baseline. Automatic CI and a platform matrix remain outside this goal.

Work proceeds in this order:

1. Extend `examples/06_openssl_compare.cpp` until every row in
   `examples/05_benchmark.cpp` has either a direct OpenSSL measurement or an
   explicit unavailable result.
2. Optimize rows below 0.90, beginning with the largest measured gap. Add or
   strengthen hardware paths where the target instruction set provides a real
   gain, while preserving the portable fallback.
3. Keep published known-answer, interoperability, malformed-input, and negative
   tests passing. Exercise both accelerated and portable configurations for a
   changed primitive.
4. Refresh [Performance](../concepts/performance.md) with the matched results
   and move completed investigations to [History](../HISTORY.md).

The first complete hash/CBC inventory puts SHA-1, SHA-224, SHA-256, SHA3-256,
SHA3-512, SHAKE-128, SHAKE-256, and AES-128-CBC at or above the threshold. A
four-lane SSE2 compression path subsequently raised BLAKE2s from about 0.74 to
0.96, so it now also meets the threshold. Expanded MD4 and MD5 compression
kernels subsequently raised both paired-run medians to about 0.90; they meet
the threshold narrowly and remain remeasurement-sensitive. Four-way AVX-512VL
schedule generation subsequently raised SHA-384/SHA-512 to about 0.90/0.91;
SHA-384 is likewise remeasurement-sensitive. An AVX-512VL register-resident
permutation raised every SHA-3/SHAKE row well above the threshold.
Direct whole-block streaming subsequently raised AES-128/192/256-CBC to about
0.97/0.97/0.98, so all three now meet the threshold. Combined S/P tables, rotated lookup keys,
one permutation pair per TripleDES EDE block, and direct CBC streaming subsequently raised DES
and 2-key 3DES-CBC to about 1.04 and 1.01, so both now meet the threshold. An expanded 32-bit
S-box/diffusion path and direct CBC loop subsequently raised all three ARIA rows to about
1.03--1.04, so they now meet the threshold. Ed25519 signing is about 0.65 and verification about
0.27. Streebog is unavailable from the tested
OpenSSL default and legacy providers. The next inventory stage added AEAD,
X25519, ML-KEM, Ed448, and ML-DSA. The largest new gaps are AES-256-GCM bulk at
about 0.27 after its first CTR/GHASH optimization, Ed448 verification at about
0.03 after dedicated doubling and a joint public-scalar verifier, X25519 key
generation at about 0.24 after removing its redundant derived-point cofactor
ladder, and ML-KEM operations at about 0.30--0.52. ML-DSA operations currently
range from about 0.64 to 0.78 and remain
below the threshold. XChaCha20-Poly1305 is unavailable through the
tested OpenSSL EVP interface. The next inventory stage covered all 20 prime-field ECDSA/ECDH
curves and all 10 binary ECDSA curves with bidirectional interoperability; prime-curve ECDH also
checks the exact cross-implementation secret. A joint public-scalar multiplication improved ECDSA
verification by about 2.3x on representative prime curves and 1.9--2.0x on representative binary
curves. Current prime-curve operations range from below 0.01 to about 0.27 of OpenSSL;
binary-curve operations range from about 0.08 to 0.77. The next inventory stage added RSA-2048
and DSA-2048 with bidirectional signature interoperability and altered-digest rejection.
Montgomery-backed Miller--Rabin, a sliding window for long exponents, and a joint public-exponent
DSA verifier improved the initial measurements substantially, but current three-run median ratios
remain about 0.05/0.06/0.11 for RSA keygen/sign/verify and 0.10/0.14/0.09 for DSA. OpenSSL
3.6.4's tested default and legacy providers expose no GOST signature implementation, so GOST
keeps an internal before/after baseline and an explicit unavailable result.

- **Profile the remaining RSA/DSA arithmetic gap.** The division-free paths removed the known
  `divMod()` bottleneck, but OpenSSL still has much faster limb assembly and exponentiation.
  Profile the current native GCC build before changing multiplication, reduction, or window size;
  keep the existing CRT fault check and the documented variable-time boundary intact.
- **Profile binary curves on GCC.** All ten GF(2^m) curves moved in the same
  direction in the WSL2 comparison, pointing to shared `CGf2m` code. Reproduce
  on bare-metal Linux and isolate the shared cost before proposing an
  optimization.
- **Evaluate a verify-time public-key table.** Signature verification uses a
  variable base, but a certificate issuer key is commonly reused. Measure
  whether caching a table per public key improves that workload without adding
  unacceptable memory or setup cost.

Any optimization begins with a reproducible baseline and a profile. Changes
smaller than the benchmark machine's run-to-run spread are not treated as
wins. Every accepted change must keep the relevant known-answer and negative
tests passing.
