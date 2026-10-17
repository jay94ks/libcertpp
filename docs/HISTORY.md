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
path accelerates GOST verification. The comparison then added RSA and DSA interoperability;
Montgomery-backed primality tests, sliding-window exponentiation, and joint DSA verification
reduced the first direct RSA key-generation/signing measurements by about 5.7x/1.3x and DSA
key-generation/signing/verification by about 3.7x/3.4x/5.5x. The tested OpenSSL providers do not
offer GOST signatures. Dedicated edwards448 doubling, a public subgroup-check window, and a
joint `S*B - k*A` verifier then reduced median Ed448 verification latency from 11.454 to
6.055 ms while retaining the secret-scalar ladder. Removing X25519 key generation's redundant
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
