# Project history

[한국어](HISTORY.ko.md)

This repository's git history starts late: everything up to and including
the initial source commit was developed as uncommitted working-tree state,
so `git log` says nothing about how any of it came to be. This file is that
record instead, and stays the place to look for the reasoning behind work
that predates the history (and for anything a commit message states too
briefly). Chapters follow the project's development in order. See
[`docs/CONCEPTS.md`](CONCEPTS.md) for what the library looks like *now* —
this history explains how it got there.

## Recent reliability and integration program

The 1.1.0 work completed one coordinated program rather than adding more
fine-grained history chapters: an explicit-trust X.509 path validator; five
sanitizer-backed parser fuzz targets; masked prime-curve ladder exchanges and
an ML-DSA timing review tool; owning-output overloads and a centralized
generation policy; RFC 9215 GOST certificate/CSR support, RFC 9558 DNSSEC
algorithm 23, and RFC 9935 ML-KEM SPKI support; plus a documented SemVer/ABI
contract and an installed-package consumer test. Published RFC artifacts and
negative inputs cover the new wire formats. Hardware follow-up added a
sixteen-block AVX-512F ChaCha20 path, made the existing accelerated paths
compile under Clang's Windows ABI, corrected GFNI feature detection, and
removed an AVX-512 vector-argument ABI boundary from Poly1305. On the review
machine the complete AVX-512 ChaCha20-Poly1305 path measured 1979.7 MiB/s for
64 KiB records versus 494.8 MiB/s with both AVX-512 tiers disabled. The
OpenSSL 3.6 comparison program then expanded to the complete hash/CBC
inventory plus AEAD, X25519, ML-KEM, EdDSA, and ML-DSA. A circular SHA-512
schedule with rotated round arguments improved its median throughput by 36%,
and parallel AES-CTR, VAES, and four-block GHASH raised 64 KiB AES-256-GCM from
517 to 2953 MiB/s while preserving the short-record path. The OpenSSL inventory
then covered all 20 prime-field ECDSA/ECDH and 10 binary ECDSA curves. Joint public-scalar
multiplication reduced representative prime-curve ECDSA verification by about
2.3x and binary-curve verification by about 1.9--2.0x, and the same prime-field
path accelerates GOST verification. Fixed-width stack-resident Montgomery fields, full-scan
private windows, signed public verification windows, and fixed-base comb tables first raised 72 of
the 80 prime-field key-generation, signing, verification, and ECDH rows to at least 0.90 of
OpenSSL. Fixed-count field kernels and key-bound width-six affine verification tables then raised
every non-P-256 row above the gate. A compact seven-bit P-256 base table, one-way masked selection,
and width-eight verification tables stored directly as Montgomery limbs raised its five-run
keygen/sign/verify/ECDH ratios from 0.403/0.345/0.315/0.302 to
0.614/0.434/0.361/0.318. Forcing the fixed-width field selector and sparse P-256 product into the
point formulas then reduced their single-CPU 15-run latencies by 5.2--15.6%, producing ratios of
0.797/0.477/0.406/0.322. A position-dependent four-bit P-256 public-verification comb subsequently
removed 256 point doublings. The base table is shared process-wide while each bound public key keeps
one 60 KiB table. Twenty-one alternating runs reduced verification from 0.142 to 0.058 ms and raised
its OpenSSL ratio to 0.999. An AVX-512F private-comb selector then loaded every 64-byte affine entry
and retained the requested point with masks, preserving the full-row scan while improving key
generation and signing by 15.8% and 8.3% against the preceding binary. The comparison harness now
warms both sides and alternates independent batch order; seven pinned runs with 1,000 operations per
batch measured P-256 keygen/sign/verify/ECDH medians of 0.838/0.497/1.007/0.322. Seventy-seven of
80 prime-field rows passed at that point. Replacing the unsigned seven-bit base comb with 33-row
signed radix-256 then reduced its table from about 296 to 266 KiB and its expected mixed additions
from 36.7 to 32.4. Seven alternating before/after runs reduced certpp keygen/sign medians from
0.027/0.039 to 0.025/0.037 ms and produced current OpenSSL ratios of
0.959/0.535/0.971/0.311. Key generation now passes, raising the prime-field count to 78 of 80.
A context-cached, position-dependent four-bit comb for the current P-256 ECDH peer then replaced
256 doublings and 64 general additions with 64 mixed additions whose private digit scans all
fifteen candidates. Seven alternating runs reduced repeated certpp derive from 0.140 to 0.039 ms
and raised its OpenSSL ratio from 0.315 to 1.164. The current P-256 ratios are
0.959/0.543/0.994/1.164, so 79 of 80 prime-field rows pass and only signing remains.
fixed-count PCLMUL product and square kernels plus descending word reduction subsequently removed
the shared GF(2^m) bottleneck. Mixed Lopez-Dahab additions and eliminating redundant validation of
freshly generated keys brought all 30 binary-curve keygen/sign/verify rows above the OpenSSL gate,
with five-run pinned medians from 1.12 to 1.83.
The comparison then added RSA and DSA interoperability;
Montgomery-backed primality tests, sliding-window exponentiation, and joint DSA verification
reduced the first direct RSA key-generation/signing measurements by about 5.7x/1.3x and DSA
key-generation/signing/verification by about 3.7x/3.4x/5.5x. The tested OpenSSL providers do not
offer GOST signatures. Caching each RSA key's public-modulus context and keeping small public exponents
in one packed 64-bit Montgomery chain later raised pinned Windows RSA verification from 0.11 to
0.54 of OpenSSL. Keeping long exponentiation and two-base DSA verification in packed 64-bit form,
plus binary modular inversion for odd moduli, raised the remaining operations substantially.
Caching the private CRT `p` and `q` Montgomery contexts removed their per-signature setup divisions.
Integrated CIOS multiplication and a two-bit simultaneous DSA window then produced fresh pinned
ratios of 0.36/0.27/0.61 for RSA and 0.61/0.65/0.48 for DSA keygen/sign/verify while preserving
the CRT fault check and portable fallbacks.
Grouping small-prime trial divisors into 32-bit products then reduced a fixed 2048-bit worst-sieve
case from a nine-run median of 86.687 to 16.790 microseconds per call. Fresh eleven-run pinned
ratios became 0.41/0.27/0.61 for RSA and 0.75/0.65/0.48 for DSA; key-generation ratios retain wide
random-prime-search variance. Separate 16- and 32-limb CIOS kernels with up to 32-way loop unrolling
then reduced RSA sign/verify from 0.948/0.027 to 0.805/0.025 ms and DSA sign/verify from
0.514/0.616 to 0.471/0.558 ms. Their paired ratios rose to 0.316/0.668 and 0.720/0.535;
key-generation ratios remained dominated by random prime-search variance.
The X25519 and packed-Montgomery BMI2/ADX gates then moved from compiler-specific feature strings
to direct CPUID checks; X25519 additionally verifies OSXSAVE/XCR0 before entering its AVX2 body.
This keeps the optimized paths buildable with Clang 18 while preserving cached dispatch and the
portable fallback. AES VAES dispatch later made the same change, decoding AVX2/AVX-512F and VAES
bits plus the required XCR0 state directly so the complete accelerated build also compiles with
Clang 18. A profile attributed 35.85% of a combined RSA comparison's self cycles to the
16-limb kernel. An explicit `_mulx_u64`/`_addcarryx_u64` rewrite passed 914,917 Montgomery assertions
but was rejected after making stable RSA/DSA operations 5--8% slower. Fixed-count square wrappers
then kept the existing integrated CIOS arithmetic but exposed the shared operand to the compiler.
Seven alternating WSL runs improved RSA sign/verify and DSA sign/verify medians by 2.5--4.2%, while
the accelerated full suite and the SIMD-disabled Montgomery/RSA/DSA tests retained their answers.
Dedicated edwards448
doubling, a public subgroup-check window, and a
joint `S*B - k*A` verifier first reduced median Ed448 verification latency from 11.454 to
6.055 ms. A fixed-width Fe448 implementation and 10-column comb tables then reduced signing and
verification to 0.139/0.191 ms in a matched WSL comparison, reaching 1.48/0.99 of OpenSSL; the
portable 16-limb fallback passed the same field and RFC tests under MSVC. Removing X25519 key generation's redundant
derived-point cofactor ladder reduced its median from 0.270 to 0.139 ms. Test processes now
route assertions and crashes to console diagnostics without Windows error dialogs. Automated CI
and the platform matrix intentionally remain in [the roadmap](PLANS.md). A four-lane SSE2
BLAKE2s compression path then raised its 64 KiB median from 406 to 512 MiB/s and its matched
OpenSSL ratio from 0.74 to 0.96, while the SIMD-disabled scalar path retained the same RFC and
keyed-reference answers. Fully expanded compression kernels and one dispatch per input then
raised MD4 from 0.61 to 0.90 of OpenSSL and MD5 from 0.81 to 0.90. MD4 uses AVX-512VL ternary
logic and rotates; MD5 uses BMI1 ANDN with scalar ROL after its BMI2 RORX alternative measured
slower. Accelerated and SIMD-disabled known-answer tests retained the same results.
An AVX-512VL SHA-384/SHA-512 path then generated four message schedules together and removed a
round-chain addition from prepared blocks, raising their OpenSSL ratios to 0.90 and 0.91.
An AVX-512VL Keccak permutation then kept all 25 lanes in registers and folded theta and chi with
ternary logic. Five-run median OpenSSL ratios rose to 1.40 for SHA3-256, 1.35 for SHA3-512, and
1.38 for both SHAKE variants while the portable permutation retained the same FIPS and independent
reference answers.
Passing safe complete CBC input directly to the AES-NI bulk loop then removed an input-sized
staging copy and empty-buffer allocation from `CbcTransformer`. Seven-run median OpenSSL ratios
rose to 0.97 for AES-128/192-CBC and 0.98 for AES-256-CBC, with buffered overlap and partial-output
semantics retained. DES then replaced bit-by-bit round permutations with generated S/P tables and
two rotated lookup-key words, while DES/TripleDES bulk CBC kept chaining local and retained the
permuted value between EDE stages. Seven-run median OpenSSL ratios rose from 0.07/0.06 to
1.04/1.01 for DES/2-key TripleDES, with the published two-key and three-key vectors unchanged.
ARIA then replaced byte-at-a-time substitution and diffusion with expanded 32-bit S-boxes, word
diffusion, and an inlined CBC bulk loop. Its 128/192/256-bit seven-run median OpenSSL ratios rose
from about 0.31 to 1.04/1.03/1.03 while the RFC 5794 vectors remained unchanged.
Generated Fe25519 squaring, mixed precomputed point addition, one-exponent point recovery, joint
public verification, and per-public-key odd-multiple tables then raised the eleven-run median
Ed25519 sign/verify ratios to 0.94/0.97 while retaining RFC 8032 and low-order-point checks. Making
the five-limb radix-51 path the GCC/Clang 64-bit default, keeping its unsigned loose bounds
explicit, and flattening the X25519 ladder then raised Ed25519 to 1.53/1.28 and X25519
keygen/derive from 0.24/0.21 to 0.77/0.62 of OpenSSL in the matched WSL comparison. The portable
ten-limb path remains the MSVC and no-native-wide-product fallback. A later radix-51 pass used
two independent carry chains, a dedicated ten-product square, shorter ladder live ranges,
runtime AVX2/BMI2/ADX and exact Tiger Lake tuning, and bound-key caches. Fifteen matched Windows
runs pinned to one logical processor then measured median X25519 keygen/derive ratios of
1.035/0.909 against OpenSSL 3.6.4.
ML-KEM then replaced bit-at-a-time codecs and CBD sampling with word-sized paths, used bounded
Barrett reduction in its NTT, and prepared decoded/expanded key material when a context binds a
key. In seven matched Windows runs, all nine ML-KEM keygen/encapsulate/decapsulate median ratios
reached 1.07--1.25 of OpenSSL 3.6.4 while the NIST ACVP and cross-implementation checks remained
unchanged.
ML-DSA then replaced per-coefficient modular division in its NTT with fixed-modulus Montgomery
products, moved bit packing to a reservoir, and consumed SHAKE rejection streams by rate block.
Seven matched Windows runs raised all six sign/verify median ratios to 1.17--1.38 of OpenSSL 3.6.4;
the official signing and verification vectors and arithmetic reference checks retained their
results.

## Chapters

- [Foundations and early hardening](history/01-foundations.md)
- [Audit, documentation, and planning](history/02-audit-and-planning.md)
- [Verification and arithmetic performance](history/03-verification-and-performance.md)
- [ML-KEM implementation](history/04-ml-kem.md)
- [Secure memory and ML-DSA groundwork](history/05-secure-memory-and-ml-dsa.md)
- [ML-DSA internals and portability](history/06-ml-dsa-and-portability.md)
- [Protocol cryptography primitives](history/07-protocol-primitives.md)
- [Curve25519 and performance](history/08-curve25519-and-performance.md)
- [Field arithmetic and AEAD](history/09-field-and-aead.md)
- [GOST and DNSSEC](history/10-gost-and-dnssec.md)
- [Integration and real certificates](history/11-integration-and-certificates.md)
- [Ed25519 on Fe25519](history/12-ed25519.md)
- [ML-DSA and the first PQ certificate](history/13-ml-dsa.md)
- [Modular arithmetic and certificate requests](history/14-modular-arithmetic-and-csr.md)
- [PEM certificate chains](history/15-pem-chains.md)
- [PKCS#12 and PBKDF2](history/16-pkcs12.md)
- [API gaps, key validation, and measurement](history/17-api-and-measurement.md)
- [RSA profiling and Montgomery arithmetic](history/18-rsa-profiling.md)
- [AES-CBC register chaining](history/19-aes-cbc.md)
- [OIDs and correctness fixes](history/20-oids-and-correctness.md)
- [Hash and MAC optimization](history/21-hash-and-mac-optimization.md)
