# Performance

[한국어](performance.ko.md)

Measured by [`examples/05_benchmark.cpp`](../../examples/05_benchmark.cpp) and
[`examples/06_openssl_compare.cpp`](../../examples/06_openssl_compare.cpp), so these are reproducible
rather than claimed: build them and run them on your own hardware. Both toolchains, both Release,
measured in one session on a single 4-core i7-11370H (3.30 GHz base, around 3.92 GHz sustained
under this load): MSVC 19.36 (VS 2022 17.6) on Windows, and GCC 13.3 on Ubuntu 24.04
**under WSL2**. Each figure is the fastest of three batches of 20 iterations, best of three runs,
and the two were run one after the other rather than at once so neither could end up measuring the
other's compiler. The run-to-run spread is 20--30%, so nothing smaller than that is a result.
Bold is the faster entry in its row.

The tables cover every algorithm the library implements: 14 hashers, 8 block-cipher configurations,
3 KEM parameter sets, and 34 signature and key-agreement schemes. No row in the harness's own
output reports "(unavailable)", which was the point of covering all of them.

GF(2^m) curves appear under signatures but not under key agreement because that is what they
implement: they do ECDSA and not ECDH.

## Current optimization checks

### AVX-512 AEAD

The ChaCha20-Poly1305 bulk result was refreshed on 2026-10-16 after adding the
sixteen-block AVX-512F ChaCha20 path and removing the Poly1305 AVX-512 vector-argument ABI
boundary. This focused comparison used the same i7-11370H host under Windows, Clang 22.1.8
targeting the MSVC ABI, Ninja, and a Release build. It ran the 64 KiB row from
[`examples/05_benchmark.cpp`](../../examples/05_benchmark.cpp); each build kept all other
hardware acceleration enabled.

| ChaCha20-Poly1305 seal, 64 KiB | Throughput | Relative |
|---|---:|---:|
| AVX-512F ChaCha20 + AVX512-IFMA Poly1305 | **1979.7 MiB/s** | **4.00x** |
| `CERTPP_DISABLE_HWACCEL_AVX512=ON` (AVX2/SSE2 retained) | 494.8 MiB/s | 1.00x |

This isolates the combined effect of the two AVX-512 tiers. It does not assign the gain to
ChaCha20 and Poly1305 individually. The larger tables below remain the original full MSVC/GCC
cross-toolchain run; their conditions are stated separately so results from different compiler
versions are not mixed into one column.

### Ed25519 point arithmetic

The same Windows/Clang 22.1.8 Release harness was run before and after replacing
unified-addition doubling with a dedicated formula, using a public-scalar window during
verification, and changing fixed-base multiplication to a masked signed-radix-16 table.

| Operation | Before | Current | Speedup |
|---|---:|---:|---:|
| Ed25519 sign | 0.153 ms | **0.056 ms** | **2.73x** |
| Ed25519 verify | 0.675 ms | **0.388 ms** | **1.74x** |

These are the corresponding rows from [`examples/05_benchmark.cpp`](../../examples/05_benchmark.cpp),
which reports the fastest of three 20-iteration batches. The signing path now performs four
fixed-base point doublings instead of 256 and scans every candidate table entry for each secret
digit. Verification keeps the strict subgroup checks and uses windowing only for public values.

## Against OpenSSL

A number means nothing in isolation, so the repository also measures the same algorithms against
OpenSSL on the same machine with
[`examples/06_openssl_compare.cpp`](../../examples/06_openssl_compare.cpp).

**Both sides are timed alone, in their own loops.** Interleaving the two implementations in one
loop -- the obvious way to keep them on equal footing -- turns out to corrupt both: certpp's
SHA-256 drops from 1523 to 765 MiB/s and OpenSSL's halves too, because alternating caches and
branch predictors penalises both. OpenSSL is called through EVP directly rather than through this
library's wrapper, which measures the cryptography rather than the per-call allocations a caller
through `certpp` would add. Both sides are warmed up first: OpenSSL resolves its constructors
lazily, and a cold first SHA-256 of 64 KiB costs 963 us against 38.9 us warm.

Each figure is the best of three runs of the harness on a quiet machine. Run-to-run ranges are
recorded for the refreshed comparison below where they materially affect the ratio; one run's
absolute value should not be treated as the algorithm's universal speed.

### Current SHA-384 and SHA-512 comparison

The SHA-384/SHA-512 rows were refreshed on 2026-10-16 after first replacing the 80-word message
schedule and per-round state shifts with a 16-word circular schedule and rotated round arguments,
then adding an AVX-512VL round kernel. For bulk input it computes four independent message
schedules together in YMM lanes. The first block is compressed while those schedules are formed;
the remaining three store `W[t] + K[t]`, removing one addition from their serial round chains.
One runtime dispatch covers the complete input. BMI2 RORX and portable paths remain available.

| Five-run paired median, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| SHA-384, previous inventory | 550 MiB/s | 703 MiB/s | 0.79x |
| SHA-384, current | **632 MiB/s** | 700 MiB/s | **0.90x** |
| SHA-512, initial | 404 MiB/s | 704 MiB/s | 0.57x |
| SHA-512, circular scalar schedule | 551 MiB/s | 708 MiB/s | 0.78x |
| SHA-512, current | **632 MiB/s** | 695 MiB/s | **0.91x** |

The final five paired runs produced rounded ratios of 0.90x, 0.90x, 0.96x, 0.86x, and 0.92x
for SHA-384, and 0.91x, 0.89x, 0.91x, 0.93x, and 0.95x for SHA-512. Their medians meet the
active threshold, though SHA-384 remains close enough to require remeasurement after related
compiler or dispatch changes. FIPS 180-4, million-`a`, chunking, reset, boundary, and portable
load tests pass. An eight-block ZMM schedule and a packed variable-rotate round both measured
slower and are not part of the implementation.

### Current BLAKE2s comparison

The BLAKE2s row was refreshed on 2026-10-16 after vectorizing the four independent G functions
in each column and diagonal step with SSE2. SSE2 is guaranteed by the x86-64 ABI, so that path
needs no runtime feature branch; `CERTPP_DISABLE_HWACCEL_SIMD=ON` retains and exercises the
portable scalar implementation.

| Three-run median, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| Before | 406 MiB/s | 539 MiB/s | 0.74x |
| Current | **512 MiB/s** | 533 MiB/s | **0.96x** |

The three current runs measured 512, 531, and 502 MiB/s for certpp against 533, 544, and
533 MiB/s for OpenSSL, giving per-run ratios of 0.96x, 0.98x, and 0.94x. The comparison's
digest equality check passed before every timing run. The RFC 7693 unkeyed vectors and the
reference keyed BLAKE2s KAT pass in both accelerated and SIMD-disabled builds. BLAKE2s therefore
meets the active 0.90 threshold on this comparison host; other algorithms remain open.

### Current MD4 and MD5 comparison

The MD4 and MD5 rows were refreshed on 2026-10-16 after expanding every compression step at
compile time and moving the feature decision outside the multi-block loop. MD4 uses AVX-512VL
ternary logic and vector rotates when available. MD5 uses BMI1 ANDN but deliberately keeps the
destructive scalar ROL instruction: the otherwise identical BMI2 RORX variant measured slower
for this dependency chain. Runtime CPU checks select both paths, and
`CERTPP_DISABLE_HWACCEL_SIMD=ON` retains the portable implementations.

| Ten-run paired median, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| MD4, before | 840 MiB/s | 1377 MiB/s | 0.61x |
| MD4, current | about 1237 MiB/s | about 1383 MiB/s | **0.90x** |
| MD5, before | 674 MiB/s | 837 MiB/s | 0.81x |
| MD5, current | about 758 MiB/s | about 843 MiB/s | **0.90x** |

The ten paired-run ratios had medians of 0.900x for MD4 and 0.901x for MD5. Individual rounded
ratios ranged from 0.87x to 0.94x for MD4 and 0.87x to 0.92x for MD5, so these rows meet the
threshold narrowly on this host and should be remeasured after related compiler or dispatch
changes. Digest equality passed before every timing run. The accelerated known-answer tests and
the SIMD-disabled portable tests both pass.

### Current SHA-3 and SHAKE comparison

The Keccak rows were refreshed on 2026-10-16 after adding an AVX-512VL permutation. It keeps all
25 lanes in the expanded vector register file, performs rho/pi as one in-place 24-lane cycle, and
uses ternary logic for theta parity and chi. Runtime feature checks retain the BMI1 and portable
fallbacks.

| Five-run paired median, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| SHA3-256 | about 580 MiB/s | about 418 MiB/s | **1.40x** |
| SHA3-512 | about 311 MiB/s | about 228 MiB/s | **1.35x** |
| SHAKE-128, 64-byte output | about 724 MiB/s | about 526 MiB/s | **1.38x** |
| SHAKE-256, 64-byte output | about 544 MiB/s | about 399 MiB/s | **1.38x** |

The FIPS SHA-3 vectors, independently generated SHAKE vectors, streaming boundaries, repeated
finish, and multi-block squeeze tests pass through the accelerated path. The SIMD-disabled build
continues to exercise the portable permutation. All four direct rows exceed the 0.90 threshold.

### Current AES-CBC comparison

The AES-CBC rows were refreshed on 2026-10-16 after changing `CbcTransformer` to pass a safe run
of complete input blocks directly to the AES-NI bulk function when no earlier fragment is pending.
Previously every `transform()` call copied its complete input into an internal staging buffer and
allocated another empty buffer after consuming it. The direct path buffers only an unprocessed
remainder. Exact in-place input and output behind the input are safe; forward-overlapping output
retains the buffered path so ciphertext cannot overwrite plaintext that has not been read.

| Seven-run paired median, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| AES-128-CBC, before direct streaming | 1745 MiB/s | 1881 MiB/s | 0.93x |
| AES-128-CBC, current | **1818 MiB/s** | 1882 MiB/s | **0.97x** |
| AES-192-CBC, before direct streaming | 1495 MiB/s | 1576 MiB/s | 0.95x |
| AES-192-CBC, current | **1542 MiB/s** | 1586 MiB/s | **0.97x** |
| AES-256-CBC, before direct streaming | 1050 MiB/s | 1373 MiB/s | 0.76x |
| AES-256-CBC, current | **1346 MiB/s** | 1377 MiB/s | **0.98x** |

The seven current paired runs produced rounded ratios of 0.94--0.98 for AES-128, 0.96--1.08 for
AES-192, and 0.88--1.02 for AES-256; each median exceeds the 0.90 threshold. The AES-256 low run
was isolated rather than repeatable. NIST SP 800-38A vectors and accelerated-versus-portable bulk
comparisons pass, including chunked input, exact in-place input, forward overlap, and limited
output that leaves complete blocks buffered. The same tests pass with AES hardware acceleration
disabled.

### Current DES and TripleDES comparison

The DES rows were refreshed on 2026-10-16 after replacing bit-by-bit Feistel expansion and
P-permutation work with generated S/P tables and two rotated round-key words. Complete CBC input
also uses the direct streaming path: the chaining value stays local, and TripleDES retains the
permuted block between EDE stages instead of applying three canceling final/initial permutation
pairs.

| Seven-run paired median, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| DES-CBC, before | about 6 MiB/s | about 80 MiB/s | 0.07x |
| DES-CBC, current | **81 MiB/s** | 78 MiB/s | **1.04x** |
| 2-key 3DES-CBC, before | about 2 MiB/s | about 30 MiB/s | 0.06x |
| 2-key 3DES-CBC, current | **30 MiB/s** | about 30 MiB/s | **1.01x** |

All seven current paired runs produced rounded ratios of 0.99 or higher for both ciphers.
Published DES and TripleDES
known-answer tests pass, including both two-key and three-key EDE. These are compatibility-only
ciphers; meeting the performance target does not change their security status.

### Current ARIA-CBC comparison

The ARIA rows were refreshed on 2026-10-16 after replacing byte-at-a-time diffusion with the
RFC-equivalent 32-bit formulation. Expanded S-box entries perform the substitution and first
diffusion step together; two word-diffusion stages surround fixed byte permutations. The CBC bulk
loop converts the schedule to words once, retains the chaining state in words, and inlines the
round path for every block.

| Seven-run paired median, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| ARIA-128-CBC, before | 48 MiB/s | 157 MiB/s | 0.31x |
| ARIA-128-CBC, current | **154 MiB/s** | 149 MiB/s | **1.04x** |
| ARIA-192-CBC, before | 42 MiB/s | 133 MiB/s | 0.31x |
| ARIA-192-CBC, current | **136 MiB/s** | 130 MiB/s | **1.03x** |
| ARIA-256-CBC, before | 36 MiB/s | 119 MiB/s | 0.31x |
| ARIA-256-CBC, current | **117 MiB/s** | 115 MiB/s | **1.03x** |

The current rounded per-run ratios ranged from 0.98 to 1.09, and every median exceeds the 0.90
threshold. RFC 5794 key-schedule, block, and CBC known-answer tests pass in the normal and
portable builds.

### Current AES-GCM comparison

The 64 KiB AES-256-GCM row was refreshed after adding eight-counter AES-CTR processing, a
256-bit VAES tier, and four-block GHASH aggregation. Counter blocks are constructed in registers;
building eight byte arrays and incrementing each one had been a larger cost than the AES rounds.
GHASH folds four recurrence steps into independent carry-less products and one reduction, while
short records retain the single-block path and avoid power-table setup.

| Three-run median | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| Before, 64 KiB | 517 MiB/s | 11608 MiB/s | 0.04x |
| Current, 64 KiB | **2953 MiB/s** | 10569 MiB/s | **0.28x** |
| Current, 64-byte record | 176 ns | **78 ns** | **0.43x** |

Bulk certpp throughput improved 5.71x. The three current per-run ratios are 0.28x, 0.24x, and
0.29x; the median remains below the 0.90 goal. The accelerated path is checked against portable
AES across all key sizes and a 32-bit counter carry, and long GHASH input is compared with the
serial path under different chunk boundaries. Both accelerated and fully portable test builds
pass.

### Current algorithm inventory comparison

The comparison harness was expanded on 2026-10-16 from six hashes and two CBC configurations to
all 14 implemented hashes, all eight implemented CBC configurations, all three AEADs, X25519,
all three ML-KEM parameter sets, RSA-2048, DSA-2048, the EdDSA and ML-DSA signatures, all 20
prime-field ECDSA/ECDH curve choices, and all 10 binary-field ECDSA choices. It verifies digest,
ciphertext, tag, signature, or shared-secret equality before timing the directly interoperable
rows. EC signatures are cross-verified in both directions and reject an altered digest;
prime-curve ECDH compares the exact shared secret. The
ML-KEM checks also cross the implementation boundary in both directions. CBC now advances both
implementations as one continuous stream; the earlier harness reset only OpenSSL on every call,
charging it context setup and overstating certpp's relative result. The table reports the median
per-run ratio from three complete runs. Latency ratios use `OpenSSL latency / certpp latency`, so
every ratio has the same direction and 1.00x means parity.
The RSA/DSA rows come from three targeted `--classic-signatures` runs after the same setup and
warm-up rules; both directions verify across the implementation boundary and reject an altered
digest before timing.

| Operation, 64 KiB unless noted | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| MD4 | about 1237 MiB/s | about 1383 MiB/s | 0.90x |
| MD5 | about 758 MiB/s | about 843 MiB/s | 0.90x |
| SHA-1 | 1709 MiB/s | 1839 MiB/s | 0.93x |
| SHA-224 | 1532 MiB/s | 1601 MiB/s | 0.96x |
| SHA-256 | 1536 MiB/s | 1598 MiB/s | 0.96x |
| SHA-384 | 632 MiB/s | 700 MiB/s | 0.90x |
| SHA-512 | 632 MiB/s | 695 MiB/s | 0.91x |
| SHA3-256 | about 580 MiB/s | about 418 MiB/s | 1.40x |
| SHA3-512 | about 311 MiB/s | about 228 MiB/s | 1.35x |
| SHAKE-128, 64-byte output | about 724 MiB/s | about 526 MiB/s | 1.38x |
| SHAKE-256, 64-byte output | about 544 MiB/s | about 399 MiB/s | 1.38x |
| BLAKE2s | 512 MiB/s | 533 MiB/s | 0.96x |
| Streebog-256 |  | unavailable |  |
| Streebog-512 |  | unavailable |  |
| AES-128-CBC | 1818 MiB/s | 1882 MiB/s | 0.97x |
| AES-192-CBC | 1542 MiB/s | 1586 MiB/s | 0.97x |
| AES-256-CBC | 1346 MiB/s | 1377 MiB/s | 0.98x |
| DES-CBC | 81 MiB/s | 78 MiB/s | 1.04x |
| 2-key 3DES-CBC | 30 MiB/s | about 30 MiB/s | 1.01x |
| ARIA-128-CBC | 154 MiB/s | 149 MiB/s | 1.04x |
| ARIA-192-CBC | 136 MiB/s | 130 MiB/s | 1.03x |
| ARIA-256-CBC | 117 MiB/s | 115 MiB/s | 1.03x |
| RSA-2048 keygen | 266.524 ms | 15.088 ms | 0.05x |
| RSA-2048 sign | 4.340 ms | 0.260 ms | 0.06x |
| RSA-2048 verify | 0.148 ms | 0.016 ms | 0.11x |
| DSA-2048 keygen, including fresh parameters | 1392.749 ms | 142.425 ms | 0.10x |
| DSA-2048 sign | 2.382 ms | 0.337 ms | 0.14x |
| DSA-2048 verify | 3.417 ms | 0.297 ms | 0.09x |
| GOST R 34.10-2012 |  | unavailable |  |
| Ed25519 sign, 32-byte message | 0.052 ms | 0.035 ms | 0.65x |
| Ed25519 verify, 32-byte message | 0.369 ms | 0.097 ms | 0.26x |
| ChaCha20-Poly1305 seal, 64 KiB | 923 MiB/s | 4117 MiB/s | 0.22x |
| XChaCha20-Poly1305 seal, 64 KiB |  | unavailable |  |
| AES-256-GCM seal, 64 KiB | 2953 MiB/s | 10569 MiB/s | 0.28x |
| ChaCha20-Poly1305 seal, 64-byte record | 363 ns | 255 ns | 0.70x |
| XChaCha20-Poly1305 seal, 64-byte record |  | unavailable |  |
| AES-256-GCM seal, 64-byte record | 176 ns | 78 ns | 0.43x |
| X25519 keygen | 0.139 ms | 0.034 ms | 0.24x |
| X25519 derive | 0.136 ms | 0.029 ms | 0.21x |
| ML-KEM-512 keygen | 0.079 ms | 0.032 ms | 0.40x |
| ML-KEM-512 encapsulate | 0.063 ms | 0.028 ms | 0.44x |
| ML-KEM-512 decapsulate | 0.067 ms | 0.035 ms | 0.52x |
| ML-KEM-768 keygen | 0.125 ms | 0.047 ms | 0.37x |
| ML-KEM-768 encapsulate | 0.094 ms | 0.030 ms | 0.32x |
| ML-KEM-768 decapsulate | 0.100 ms | 0.047 ms | 0.47x |
| ML-KEM-1024 keygen | 0.186 ms | 0.069 ms | 0.37x |
| ML-KEM-1024 encapsulate | 0.140 ms | 0.042 ms | 0.30x |
| ML-KEM-1024 decapsulate | 0.143 ms | 0.063 ms | 0.44x |
| Ed448 sign, 32-byte message | 2.855 ms | 0.191 ms | 0.08x |
| Ed448 verify, 32-byte message | 6.055 ms | 0.183 ms | 0.03x |
| ML-DSA-44 sign, 32-byte message | 0.733 ms | 0.523 ms | 0.78x |
| ML-DSA-44 verify, 32-byte message | 0.159 ms | 0.118 ms | 0.74x |
| ML-DSA-65 sign, 32-byte message | 1.217 ms | 0.883 ms | 0.71x |
| ML-DSA-65 verify, 32-byte message | 0.251 ms | 0.181 ms | 0.72x |
| ML-DSA-87 sign, 32-byte message | 1.410 ms | 1.024 ms | 0.73x |
| ML-DSA-87 verify, 32-byte message | 0.461 ms | 0.287 ms | 0.64x |

The EC rows use the same three-run median methodology. This compact table reports the
`certpp / OpenSSL` performance ratio; `examples/06_openssl_compare.cpp` prints both absolute
latencies. Binary-curve ECDH is marked unavailable because `CEcdsa2` implements signatures only.

| Curve | Keygen | ECDSA sign | ECDSA verify | ECDH derive |
|---|---:|---:|---:|---:|
| P-192 | 0.08x | 0.22x | 0.24x | 0.23x |
| P-224 | 0.09x | 0.24x | 0.25x | 0.24x |
| P-256 | <0.01x | 0.01x | 0.04x | 0.03x |
| P-384 | 0.07x | 0.22x | 0.21x | 0.23x |
| P-521 | 0.08x | 0.25x | 0.22x | 0.23x |
| secp256k1 | 0.08x | 0.23x | 0.25x | 0.23x |
| brainpoolP160r1 | 0.10x | 0.24x | 0.27x | 0.25x |
| brainpoolP192r1 | 0.08x | 0.21x | 0.24x | 0.21x |
| brainpoolP224r1 | 0.08x | 0.23x | 0.26x | 0.24x |
| brainpoolP256r1 | 0.07x | 0.21x | 0.25x | 0.21x |
| brainpoolP320r1 | 0.08x | 0.22x | 0.23x | 0.22x |
| brainpoolP384r1 | 0.07x | 0.22x | 0.22x | 0.21x |
| brainpoolP512r1 | 0.05x | 0.15x | 0.16x | 0.15x |
| brainpoolP160t1 | 0.09x | 0.24x | 0.27x | 0.24x |
| brainpoolP192t1 | 0.08x | 0.21x | 0.24x | 0.21x |
| brainpoolP224t1 | 0.09x | 0.23x | 0.25x | 0.24x |
| brainpoolP256t1 | 0.07x | 0.21x | 0.22x | 0.22x |
| brainpoolP320t1 | 0.08x | 0.22x | 0.22x | 0.22x |
| brainpoolP384t1 | 0.07x | 0.22x | 0.21x | 0.21x |
| brainpoolP512t1 | 0.05x | 0.15x | 0.15x | 0.15x |
| B-163 | 0.09x | 0.34x | 0.39x | unavailable |
| K-163 | 0.08x | 0.35x | 0.35x | unavailable |
| B-233 | 0.09x | 0.38x | 0.41x | unavailable |
| K-233 | 0.10x | 0.39x | 0.41x | unavailable |
| B-283 | 0.11x | 0.43x | 0.47x | unavailable |
| K-283 | 0.10x | 0.45x | 0.47x | unavailable |
| B-409 | 0.14x | 0.61x | 0.66x | unavailable |
| K-409 | 0.14x | 0.62x | 0.63x | unavailable |
| B-571 | 0.16x | 0.74x | 0.77x | unavailable |
| K-571 | 0.16x | 0.72x | 0.76x | unavailable |

ECDSA and GOST verification now use one public-scalar `linearCombination()` instead of two
private-scalar ladders followed by an affine addition. Representative certpp verification latency
fell from 3.171 to 1.315 ms for P-256, 15.847 to 6.776 ms for P-521, 7.648 to 4.048 ms for B-571,
and 7.270 to 3.745 ms for K-571. The new operation is deliberately variable-time because both
verification scalars are public; signing, key generation, and ECDH continue to use the existing
private-scalar paths.

Ed448 verification now uses a dedicated untwisted-Edwards doubling formula, a public 4-bit
window for subgroup checks, and one public-scalar Straus loop for `S*B - k*A`. Across three
complete runs, certpp verification measured 7.433, 6.055, and 5.994 ms; the 6.055 ms median is
about 47% lower than the previous 11.454 ms row. The median per-run OpenSSL ratio rose from 0.02x
to 0.03x. RFC 8032 TEST 1 and the malformed-point, identity-point, altered-message, altered-
signature, and wrong-key negative controls continue to pass. The window and Straus branches see
only the public order, signature scalar, and challenge hash; private scalar multiplication keeps
the existing ladder.

X25519 key generation no longer runs a second 255-step ladder to multiply its freshly derived
public value by the cofactor. The private scalar is clamped to a multiple of 8 before it is
multiplied by the standard base point, so the result is already in the prime-order subgroup;
the retained all-zero check covers the only invalid derived result. Three targeted comparison
runs measured certpp key generation at 0.136, 0.141, and 0.139 ms with per-run OpenSSL ratios
0.24x, 0.24x, and 0.25x. The median 0.139 ms is about 49% below the previous 0.270 ms row.
The RFC 7748 vectors and the low-order-peer rejection test continue to pass.

The harness explicitly loads OpenSSL 3.6.4's default and legacy providers, which makes MD4 and
DES measurable. Streebog needs a provider this installation does not include, and OpenSSL does
not expose XChaCha20-Poly1305 through EVP; those unavailable rows remain in the executable
inventory instead of being silently omitted. The ML-KEM setup imports each implementation's raw
public key into the other and checks both `certpp encapsulate -> OpenSSL decapsulate` and the
reverse before timing. RSA and DSA import certpp's traditional private-key DER into OpenSSL, then
cross-verify both signatures and altered-digest rejection. OpenSSL 3.6.4 exposes no GOST signature
implementation through the tested default/legacy providers, so that row has no invented ratio.

The first direct classic-signature run measured RSA keygen/sign at 1522.626/5.831 ms and DSA
keygen/sign/verify at 5162.961/8.089/18.882 ms. Reusing Montgomery reduction in Miller--Rabin,
using a sliding window for long modular exponents, and combining DSA verification's two public
exponents reduced the current three-run medians to the values above. Key generation varies with
how quickly random prime candidates are found, but the repeated signing and verification gains
are stable. The remaining gap is tracked in
[the performance roadmap](../roadmap/performance.md#openssl-90-program).

### Current Ed25519 comparison

The Ed25519 row was refreshed on 2026-10-16 after the point-arithmetic optimization above. This
was a native Windows Release build with GCC 16.2.0 and OpenSSL 3.6.4 from MSYS2 MinGW64. Three
complete harness runs were made; each run measured each side independently after warm-up and took
the fastest of five 200-operation batches.

| Operation | certpp | OpenSSL EVP | certpp / OpenSSL performance |
|---|---:|---:|---:|
| Ed25519 sign, 32-byte message | 0.059 ms | **0.040 ms** | **0.67x** |
| Ed25519 verify, 32-byte message | 0.430 ms | **0.107 ms** | **0.25x** |

The three certpp/OpenSSL latency ratios were 1.46x, 1.49x, and 1.42x for signing; verification
was 3.97x, 3.99x, and 4.03x. OpenSSL still has lower latency, but the current matched signing
comparison is much closer than the
earlier 4.5x row. That old result used a different compiler and OpenSSL session, so the change in
ratio is evidence of the present gap, not a compiler-isolated attribution of the whole gain.
The verification row is end-to-end API behavior rather than an isolated group-equation benchmark:
certpp retains its strict full `L·R` subgroup check on the signature point in addition to checking
the signature equation.

### Earlier full comparison

The broader table below is the earlier OpenSSL 3.0.13 session. It is retained as historical
context for the optimization sequence; the current inventory above owns the active comparison.

| | certpp | OpenSSL | certpp is |
|---|---|---|---|
| SHA-256, 64 KiB | 1490 MiB/s | 1550 MiB/s | 0.97x |
| SHA-1, 64 KiB | 1720 MiB/s | 1820 MiB/s | 0.95x |
| MD5, 64 KiB | 690 MiB/s | 795 MiB/s | 0.87x |
| SHA3-256, 64 KiB | 380 MiB/s | 410 MiB/s | 0.93x |
| SHAKE-256, 64 KiB | 375 MiB/s | 405 MiB/s | 0.92x |
| SHA-512, 64 KiB | 385 MiB/s | 655 MiB/s | 0.58x |
| AES-256-CBC, 64 KiB | 1280 MiB/s | 1350 MiB/s | 0.95x |
| ARIA-256-CBC, 64 KiB | 27 MiB/s | 103 MiB/s | 0.26x |

SHA-256 is at parity because both sides call SHA-NI for it. The historical SHA-512 row has been
superseded by the current comparison above; BMI2 RORX and the circular schedule narrowed that gap,
but the result remains below the active target.

**What each remaining gap actually is, which ones have been closed and why, and the decompositions
behind the ones that have not are in
[`docs/PLANS.md`](../PLANS.md)** -- along with the two cross-toolchain gaps this section's
own coverage surfaced (DSA-2048 and the GF(2^m) curves), what the slower rows mean, and the WSL2
caveat on the GCC column.

### Signatures

| | MSVC | GCC |
|---|---|---|
| RSA-2048 sign | **5.619 ms** | 5.250 ms |
| RSA-2048 verify | 0.143 ms | **0.150 ms** |
| DSA-2048 sign | 2.695 ms | **7.292 ms** |
| DSA-2048 verify | 6.581 ms | **18.069 ms** |
| Ed25519 sign | 0.198 ms | **0.201 ms** |
| Ed25519 verify | **0.873 ms** | 0.702 ms |
| Ed448 sign | **2.527 ms** | 2.499 ms |
| Ed448 verify | 10.661 ms | **10.758 ms** |
| ECDSA P-192 sign | **0.580 ms** | 0.520 ms |
| ECDSA P-192 verify | **1.448 ms** | 1.308 ms |
| ECDSA P-224 sign | **0.755 ms** | 0.670 ms |
| ECDSA P-224 verify | **1.945 ms** | 1.774 ms |
| ECDSA P-256 sign | **0.908 ms** | 0.862 ms |
| ECDSA P-256 verify | **2.428 ms** | 2.379 ms |
| ECDSA P-384 sign | **2.026 ms** | 2.016 ms |
| ECDSA P-384 verify | **5.694 ms** | 5.523 ms |
| ECDSA P-521 sign | **4.737 ms** | 4.379 ms |
| ECDSA P-521 verify | **13.545 ms** | 12.464 ms |
| ECDSA secp256k1 sign | **0.901 ms** | 0.843 ms |
| ECDSA secp256k1 verify | **2.435 ms** | 2.285 ms |
| Brainpool-160r1 sign | **0.462 ms** | 0.385 ms |
| Brainpool-160r1 verify | **1.078 ms** | 1.002 ms |
| Brainpool-192r1 sign | **0.569 ms** | 0.523 ms |
| Brainpool-192r1 verify | **1.407 ms** | 1.398 ms |
| Brainpool-224r1 sign | **0.705 ms** | 0.694 ms |
| Brainpool-224r1 verify | 1.888 ms | **1.980 ms** |
| Brainpool-256r1 sign | **0.919 ms** | 0.890 ms |
| Brainpool-256r1 verify | 2.412 ms | **2.415 ms** |
| Brainpool-320r1 sign | **1.412 ms** | 1.402 ms |
| Brainpool-320r1 verify | **3.741 ms** | 3.678 ms |
| Brainpool-384r1 sign | 2.004 ms | **2.186 ms** |
| Brainpool-384r1 verify | 5.369 ms | **5.908 ms** |
| Brainpool-512r1 sign | 4.007 ms | **4.314 ms** |
| Brainpool-512r1 verify | 11.341 ms | **11.553 ms** |
| Brainpool-160t1 sign | **0.412 ms** | 0.388 ms |
| Brainpool-160t1 verify | **1.074 ms** | 1.029 ms |
| Brainpool-192t1 sign | **0.546 ms** | 0.522 ms |
| Brainpool-192t1 verify | 1.361 ms | **1.381 ms** |
| Brainpool-224t1 sign | 0.708 ms | **0.712 ms** |
| Brainpool-224t1 verify | 1.851 ms | **1.918 ms** |
| Brainpool-256t1 sign | **0.903 ms** | 0.879 ms |
| Brainpool-256t1 verify | **2.414 ms** | 2.360 ms |
| Brainpool-320t1 sign | **1.400 ms** | 1.391 ms |
| Brainpool-320t1 verify | 3.815 ms | **3.887 ms** |
| Brainpool-384t1 sign | 2.086 ms | **2.147 ms** |
| Brainpool-384t1 verify | 5.484 ms | **5.902 ms** |
| Brainpool-512t1 sign | 4.086 ms | **4.166 ms** |
| Brainpool-512t1 verify | 11.223 ms | **11.557 ms** |
| ECDSA B-163 sign | 0.527 ms | **0.635 ms** |
| ECDSA B-163 verify | 1.760 ms | **2.282 ms** |
| ECDSA K-163 sign | 0.493 ms | **0.595 ms** |
| ECDSA K-163 verify | 1.681 ms | **2.214 ms** |
| ECDSA B-233 sign | 0.596 ms | **0.895 ms** |
| ECDSA B-233 verify | 1.983 ms | **3.296 ms** |
| ECDSA K-233 sign | 0.564 ms | **0.846 ms** |
| ECDSA K-233 verify | 1.971 ms | **3.023 ms** |
| ECDSA B-283 sign | 0.935 ms | **1.421 ms** |
| ECDSA B-283 verify | 3.112 ms | **5.049 ms** |
| ECDSA K-283 sign | 0.863 ms | **1.342 ms** |
| ECDSA K-283 verify | 2.910 ms | **4.731 ms** |
| ECDSA B-409 sign | 1.223 ms | **2.588 ms** |
| ECDSA B-409 verify | 4.057 ms | **9.392 ms** |
| ECDSA K-409 sign | 1.151 ms | **2.314 ms** |
| ECDSA K-409 verify | 3.834 ms | **8.651 ms** |
| ECDSA B-571 sign | 2.358 ms | **5.303 ms** |
| ECDSA B-571 verify | 7.586 ms | **19.857 ms** |
| ECDSA K-571 sign | 2.057 ms | **4.888 ms** |
| ECDSA K-571 verify | 7.161 ms | **18.295 ms** |
| GOST-256 Test sign | **0.822 ms** | 0.783 ms |
| GOST-256 Test verify | **2.372 ms** | 2.245 ms |
| GOST-256 A sign | 0.819 ms | **0.866 ms** |
| GOST-256 A verify | **2.495 ms** | 2.271 ms |
| GOST-256 B sign | **0.845 ms** | 0.816 ms |
| GOST-256 B verify | **2.391 ms** | 2.377 ms |
| GOST-256 C sign | **0.843 ms** | 0.794 ms |
| GOST-256 C verify | **2.325 ms** | 2.282 ms |
| GOST-256 D sign | 0.804 ms | **0.914 ms** |
| GOST-256 D verify | 2.370 ms | **2.381 ms** |
| GOST-512 Test sign | 3.820 ms | **3.949 ms** |
| GOST-512 Test verify | 11.152 ms | **11.435 ms** |
| GOST-512 A sign | **3.865 ms** | 3.829 ms |
| GOST-512 A verify | **12.447 ms** | 11.206 ms |
| GOST-512 B sign | **3.878 ms** | 3.817 ms |
| GOST-512 B verify | **11.184 ms** | 11.047 ms |
| GOST-512 C sign | **3.856 ms** | 3.806 ms |
| GOST-512 C verify | **11.117 ms** | 11.049 ms |
| ML-DSA-44 sign | 1.045 ms | **1.194 ms** |
| ML-DSA-44 verify | **0.346 ms** | 0.290 ms |
| ML-DSA-65 sign | 1.528 ms | **2.218 ms** |
| ML-DSA-65 verify | **0.565 ms** | 0.450 ms |
| ML-DSA-87 sign | **2.417 ms** | 2.232 ms |
| ML-DSA-87 verify | **0.903 ms** | 0.691 ms |

### Key agreement and KEMs

| | MSVC | GCC |
|---|---|---|
| X25519 keygen | **0.328 ms** | 0.284 ms |
| X25519 derive | **0.165 ms** | 0.156 ms |
| ECDH P-192 keygen | **1.722 ms** | 1.675 ms |
| ECDH P-192 derive | 0.796 ms | **0.805 ms** |
| ECDH P-224 keygen | 2.296 ms | **2.323 ms** |
| ECDH P-224 derive | 1.063 ms | **1.070 ms** |
| ECDH P-256 keygen | **3.066 ms** | 3.022 ms |
| ECDH P-256 derive | **1.390 ms** | 1.361 ms |
| ECDH P-384 keygen | 6.937 ms | **7.019 ms** |
| ECDH P-384 derive | 3.343 ms | **3.407 ms** |
| ECDH P-521 keygen | **16.959 ms** | 16.325 ms |
| ECDH P-521 derive | **8.059 ms** | 7.784 ms |
| ECDH secp256k1 keygen | **2.913 ms** | 2.892 ms |
| ECDH secp256k1 derive | 1.357 ms | **1.396 ms** |
| ECDH bp160r1 keygen | 1.253 ms | **1.320 ms** |
| ECDH bp160r1 derive | **0.596 ms** | 0.581 ms |
| ECDH bp192r1 keygen | 1.691 ms | **1.771 ms** |
| ECDH bp192r1 derive | **0.809 ms** | 0.793 ms |
| ECDH bp224r1 keygen | 2.255 ms | **2.426 ms** |
| ECDH bp224r1 derive | 1.096 ms | **1.182 ms** |
| ECDH bp256r1 keygen | 2.943 ms | **3.040 ms** |
| ECDH bp256r1 derive | 1.387 ms | **1.410 ms** |
| ECDH bp320r1 keygen | **5.773 ms** | 4.708 ms |
| ECDH bp320r1 derive | **2.610 ms** | 2.221 ms |
| ECDH bp384r1 keygen | 6.842 ms | **7.326 ms** |
| ECDH bp384r1 derive | 3.342 ms | **3.429 ms** |
| ECDH bp512r1 keygen | 14.789 ms | **16.070 ms** |
| ECDH bp512r1 derive | 6.868 ms | **7.252 ms** |
| ECDH bp160t1 keygen | **1.419 ms** | 1.370 ms |
| ECDH bp160t1 derive | **0.750 ms** | 0.586 ms |
| ECDH bp192t1 keygen | **2.450 ms** | 1.759 ms |
| ECDH bp192t1 derive | **0.834 ms** | 0.812 ms |
| ECDH bp224t1 keygen | **2.520 ms** | 2.411 ms |
| ECDH bp224t1 derive | 1.055 ms | **1.136 ms** |
| ECDH bp256t1 keygen | 2.973 ms | **3.108 ms** |
| ECDH bp256t1 derive | 1.374 ms | **1.438 ms** |
| ECDH bp320t1 keygen | 4.642 ms | **4.726 ms** |
| ECDH bp320t1 derive | 2.147 ms | **2.203 ms** |
| ECDH bp384t1 keygen | 6.873 ms | **7.339 ms** |
| ECDH bp384t1 derive | 3.308 ms | **3.449 ms** |
| ECDH bp512t1 keygen | 14.437 ms | **15.295 ms** |
| ECDH bp512t1 derive | 6.696 ms | **7.113 ms** |
| ECDH B-163 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-163 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-233 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-233 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-283 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-283 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-409 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-409 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-571 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-571 | (agreement unsupported) | (agreement unsupported) |
| ML-KEM-512 keygen | **0.124 ms** | 0.094 ms |
| ML-KEM-512 encapsulate | **0.101 ms** | 0.079 ms |
| ML-KEM-512 decapsulate | **0.114 ms** | 0.096 ms |
| ML-KEM-768 keygen | **0.194 ms** | 0.145 ms |
| ML-KEM-768 encapsulate | **0.158 ms** | 0.124 ms |
| ML-KEM-768 decapsulate | **0.183 ms** | 0.138 ms |
| ML-KEM-1024 keygen | **0.290 ms** | 0.216 ms |
| ML-KEM-1024 encapsulate | **0.236 ms** | 0.176 ms |
| ML-KEM-1024 decapsulate | **0.275 ms** | 0.190 ms |

### Hashing, 64 KiB

| | MSVC | GCC |
|---|---|---|
| MD4 | **788.4 MiB/s** | 722.5 MiB/s |
| MD5 | 572.5 MiB/s | **716.2 MiB/s** |
| SHA-1 | **1782.1 MiB/s** | 1768.9 MiB/s |
| SHA-224 | **1552.2 MiB/s** | 1544.4 MiB/s |
| SHA-256 | **1556.5 MiB/s** | 1438.9 MiB/s |
| SHA-384 | 349.2 MiB/s | **361.3 MiB/s** |
| SHA-512 | 352.2 MiB/s | **359.0 MiB/s** |
| SHA3-256 | 107.7 MiB/s | **309.4 MiB/s** |
| SHA3-512 | 57.0 MiB/s | **163.6 MiB/s** |
| SHAKE-128 | 132.9 MiB/s | **381.3 MiB/s** |
| SHAKE-256 | 104.6 MiB/s | **309.7 MiB/s** |
| BLAKE2s | 410.6 MiB/s | **417.1 MiB/s** |
| Streebog-256 | 74.7 MiB/s | **107.3 MiB/s** |
| Streebog-512 | 71.5 MiB/s | **108.3 MiB/s** |

### Block ciphers, CBC, 64 KiB

| | MSVC | GCC |
|---|---|---|
| AES-128-CBC | 1442.4 MiB/s | **1717.9 MiB/s** |
| AES-192-CBC | 1234.9 MiB/s | **1515.3 MiB/s** |
| AES-256-CBC | 1111.9 MiB/s | **1319.9 MiB/s** |
| DES-CBC | **9.1 MiB/s** | 5.1 MiB/s |
| 3DES-CBC | **3.0 MiB/s** | 1.7 MiB/s |
| ARIA-128-CBC | **58.1 MiB/s** | 38.3 MiB/s |
| ARIA-192-CBC | **51.8 MiB/s** | 33.1 MiB/s |
| ARIA-256-CBC | **45.3 MiB/s** | 28.4 MiB/s |

### AEAD seal, 64 KiB

| | MSVC | GCC | MSVC/GCC |
|---|---|---|---|
| ChaCha20-Poly1305 | **999 MiB/s** | 835 MiB/s | 1.20x |
| XChaCha20-Poly1305 | **1005 MiB/s** | 840 MiB/s | 1.20x |
| AES-256-GCM | **520 MiB/s** | 465 MiB/s | 1.12x |

### AEAD seal, 64 B, per record

| | MSVC | GCC | MSVC/GCC |
|---|---|---|---|
| ChaCha20-Poly1305 | **400 ns** | 330 ns | 1.21x |
| XChaCha20-Poly1305 | 400 ns | **450 ns** | 0.89x |
| AES-256-GCM | 215 ns | **235 ns** | 0.91x |


The GCC figures were measured **under WSL2** -- a real Linux kernel inside a VM, not bare metal
-- so that column reads as *this toolchain in this setup*, not as Linux performance in general; the
harness is single-threaded and CPU-bound, so the hypervisor's share ought to be small, but this run
did not quantify it either way. And "Release" is not one setting: CMake's defaults are `/O2` for
MSVC and `-O3` for GCC, so toolchain and optimization level are varied together.
