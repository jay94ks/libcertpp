# Constant-time and performance work

[한국어](performance.ko.md)

This page contains only work that remains open. Current benchmark results and
methodology live in [Performance](../concepts/performance.md). Completed
optimizations, investigations, and negative results are recorded in
[History](../HISTORY.md) and [Not planned](not-planned.md).

## Security work

- **Finish the portable constant-time prime-curve fallback.** Native x86-64
  Clang/GCC builds now keep field coordinates in fixed-width Montgomery limbs,
  scan every private-window candidate, and process the full group-order width.
  The portable fallback still uses `CBigNum`, whose allocation, limb trimming,
  and arithmetic have operand-dependent cost. Replace that fallback or keep its
  variable-time boundary explicit before making a platform-independent claim.
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
1.03--1.04, so they now meet the threshold. Mixed precomputed point addition, generated field
squaring, joint verification, per-public-key odd-multiple tables, and the native radix-51 field
path subsequently raised Ed25519 signing/verification to about 1.53/1.28, so both meet the
threshold. Streebog is unavailable
from the tested
OpenSSL default and legacy providers. The next inventory stage added AEAD,
X25519, ML-KEM, Ed448, and ML-DSA. Fixed-width Fe448 arithmetic, mixed point
addition, and 10-column comb tables subsequently raised Ed448 signing and
verification to about 1.48/0.99 in the matched WSL comparison, so both rows now
meet the threshold. The native radix-51 field path and flattened ladder first raised X25519 key
generation/derivation from about 0.24/0.21 to about 0.77/0.62. Two-chain carry reduction,
dedicated squaring, CPU-tuned whole-ladder dispatch, and bound-key caching subsequently raised
the matched Windows medians to about 1.03/0.91, so both now meet the threshold. Bit-reservoir
codecs, fixed-lane CBD sampling, bounded NTT reduction, and prepared
key material subsequently raised the nine ML-KEM keygen/encapsulate/decapsulate rows to
seven-run median ratios of 1.07--1.25, so all three parameter sets now meet the threshold.
Fixed-modulus Montgomery NTT products, reservoir bit packing, and rate-block SHAKE sampling
subsequently raised the six ML-DSA sign/verify rows to seven-run median ratios of 1.17--1.38,
so all three parameter sets now meet the threshold.
Sixteen-block fused VAES/GHASH processing subsequently raised AES-256-GCM bulk and short-record
rows to about 0.90/0.93. Thirty-two-block IFMA aggregation raised ChaCha20-Poly1305 bulk and
short-record rows to about 0.92/0.97. These AEAD rows now meet the threshold but remain
remeasure-sensitive. The classical asymmetric rows remain the largest direct gaps.
XChaCha20-Poly1305 is unavailable through the
tested OpenSSL EVP interface. The next inventory stage covered all 20 prime-field ECDSA/ECDH
curves and all 10 binary ECDSA curves with bidirectional interoperability; prime-curve ECDH also
checks the exact cross-implementation secret. A joint public-scalar multiplication improved ECDSA
verification by about 2.3x on representative prime curves and 1.9--2.0x on representative binary
curves. Fixed-width Montgomery fields and private windows first brought 72 of the 80 prime-curve
rows to the threshold. Fixed-count multiplication kernels and key-bound width-six verification
tables then raised every remaining non-P-256 row above 0.90. A compact seven-bit P-256 base table,
one-way masked selection, and width-eight Montgomery-limb verification tables subsequently raised
the four P-256 rows to five-run medians of 0.318--0.614. Field-product inlining, a four-bit
public-verification comb, AVX-512 full-scan private-comb selection, and a signed radix-256 base
comb later raised the fixed-base rows. A peer-bound private full-scan comb raised repeated ECDH, and
batched P-256 nonce preparation shared coordinate and order inversions across repeated signatures.
The current balanced medians are 0.980/0.990/0.983/1.168, so all 80 prime-curve rows pass.
Fixed-count PCLMUL product and square kernels,
descending word reduction, mixed
Lopez-Dahab addition, and removal of redundant generated-key validation then raised all 30
binary-curve keygen/sign/verify rows to five-run median ratios of 1.12--1.83. The next inventory stage added RSA-2048
and DSA-2048 with bidirectional signature interoperability and altered-digest rejection.
Montgomery-backed Miller--Rabin, sliding windows, and joint public-exponent verification improved
the initial measurements substantially. Cached RSA modulus contexts, packed 64-bit chains for both
short and long exponents, a packed two-base DSA verifier, and binary modular inversion first raised
the comparison substantially. An integrated CIOS pass now advances product and reduction carries
together, while a two-bit simultaneous DSA window reduces verification multiplications. Separate
16- and 32-limb kernels with up to 32-way loop unrolling then raised stable sign/verify medians to
0.316/0.668 for RSA and 0.720/0.535 for DSA. Context-bound DSA position tables subsequently raised
its repeated sign/verify ratios to 1.667/1.103. The original eleven runs measured key-generation
ratios of 0.393 and 0.594. Grouping the small-prime sieve divisors into 32-bit products made its worst
2048-bit path 5.16x faster locally; randomized prime search still gives the key-generation rows much wider run-to-run
variance than signing and verification. OpenSSL
3.6.4's tested default and legacy providers expose no GOST signature implementation, so GOST
keeps an internal before/after baseline and an explicit unavailable result.

- **Generate a dual-carry RSA/DSA Montgomery kernel.** Packed chains removed repeated 32/64-bit
  conversion, integrated CIOS removed the second accumulator pass, fixed-count kernels exposed the
  common 1024/2048-bit loops to the compiler, and binary inversion removed quotient-sized
  extended-Euclidean work. A Clang 18 `perf` run attributed 35.85% of the combined RSA comparison's
  self cycles to the 16-limb Montgomery kernel; its call tree covered both prime testing and private
  CRT exponentiation. A separate 200,000-operation RSA verification profile attributed 88.24% to
  the 32-limb kernel and 6.95% to the input-domain conversion. Moving that conversion into the
  packed chain passed the full Montgomery checks but left five-run verification medians unchanged
  at 5.48 seconds, because it replaced one Montgomery product with another; that experiment was
  rejected. Replacing the wide-integer expression with `_mulx_u64` plus `_addcarryx_u64`
  remained correct but made seven-run RSA signing and DSA signing/verification medians 5--8% slower,
  because it serialized carries that Clang had interleaved across the product and reduction chains.
  The earlier full-square REDC experiment made RSA signing more than twice as slow. Reusing one
  operand pointer in fixed-count square wrappers preserved the CIOS body and produced a smaller but
  repeatable 2.5--4.2% improvement across RSA and DSA sign/verify. The current WSL RSA sign/verify
  ratios remain 0.310/0.628, so further RSA work still needs a generated
  ADCX/ADOX dual-carry schedule rather than either intrinsic chaining or a generic full-product
  buffer. DSA's context-bound position tables subsequently raised its repeated sign/verify ratios
  to 1.667/1.103, so the remaining work here is RSA plus RSA/DSA key generation. Keep the existing
  CRT fault check and documented variable-time boundary intact.

Any optimization begins with a reproducible baseline and a profile. Changes
smaller than the benchmark machine's run-to-run spread are not treated as
wins. Every accepted change must keep the relevant known-answer and negative
tests passing.
