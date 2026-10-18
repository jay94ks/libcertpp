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

### Current AEAD comparison

The AEAD rows were refreshed on 2026-10-18 on the same i7-11370H host under Windows, using
Clang 22.1.8, Ninja, a Release build, and OpenSSL 3.6.4 from the same process. Poly1305 now
aggregates thirty-two blocks before reducing the AVX512-IFMA products into its scalar
accumulator. This halves the horizontal-reduction and accumulator-update frequency relative to
the previous sixteen-block path while retaining sixteen- and eight-block tails. Powers through
r^16 are prepared only for an eight-block group, and r^17 through r^32 only for a thirty-two-block
group, so the wider path does not add setup work to short or medium-sized records.

| Five-run paired median | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| ChaCha20-Poly1305 seal, 64 KiB | **3796 MiB/s** | 4129 MiB/s | **0.92x** |
| ChaCha20-Poly1305 seal, 64-byte record | 264 ns | 258 ns | **0.97x** |
| AES-256-GCM seal, 64 KiB | **10692 MiB/s** | 11800 MiB/s | **0.90x** |
| AES-256-GCM seal, 64-byte record | 83 ns | 75 ns | **0.93x** |

The five paired bulk ChaCha20-Poly1305 ratios were 0.92x, 0.92x, 0.87x, 0.92x, and 0.92x;
the median now exceeds the active threshold. Before the thirty-two-block Poly1305 aggregation,
three immediately preceding runs measured 0.84--0.87x. AES-GCM was remeasured without an
implementation change and remains close to the threshold. Published RFC vectors, long messages
through every wide Poly1305 boundary, streaming chunk boundaries, in-place operation, and
forgery rejection pass. XChaCha20-Poly1305 remains unavailable through the tested OpenSSL EVP
interface and retains the same internal accelerated path as its inner ChaCha20-Poly1305 operation.

### Ed25519 point arithmetic

Ed25519 now uses a masked signed-radix-16 fixed-base table, mixed cached/precomputed additions,
completed coordinates for public double-scalar multiplication, generated 55-product field
squaring, and one exponentiation for point recovery. The private key caches its RFC 8032 expansion;
the public key caches the odd multiples used by repeated verification. The current matched result
and its method are recorded in [Current Ed25519 comparison](#current-ed25519-comparison); the
step-by-step historical measurements live in [Ed25519 on Fe25519](../history/12-ed25519.md).

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

The 64 KiB AES-256-GCM row was refreshed after extending the earlier eight-counter and
four-block GHASH work to a sixteen-block fused kernel. Four 512-bit VAES chains encrypt sixteen
counters while GFNI/VPCLMULQDQ computes the preceding sixteen ciphertext blocks' GHASH products;
the independent instruction streams overlap before one field reduction. Counter blocks are
constructed in registers. Short records retain the five-way AES-NI path that encrypts the tag
mask and four payload counters together and avoids the long-message power-table setup.

| Matched comparison | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| Before, 64 KiB | 517 MiB/s | 11608 MiB/s | 0.04x |
| Earlier VAES/GHASH path, 64 KiB | **2953 MiB/s** | 10569 MiB/s | **0.28x** |
| Current five-run median, 64 KiB | **10692 MiB/s** | 11800 MiB/s | **0.90x** |
| Current five-run median, 64-byte record | 83 ns | 75 ns | **0.93x** |

Bulk certpp throughput is now about 20.7 times the initial implementation. The five current
paired bulk ratios are 0.90x, 0.91x, 0.93x, 0.90x, and 0.90x; the median meets the goal narrowly.
The accelerated path is checked against portable AES across all key sizes and a 32-bit counter
carry, and long GHASH input is compared with the serial path under different chunk boundaries.
Both accelerated and fully portable test builds pass.

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
The RSA and DSA rows were initially refreshed from eleven targeted `--classic-signatures` runs in a static Clang
22.1.8 Release build against OpenSSL 3.6.4, with the process pinned to one logical processor at high
priority. Each side still uses the same setup and warm-up rules. In that snapshot, displayed
latencies are the per-side medians, while the ratio is the median of the eleven paired run ratios;
randomized prime search makes the key-generation ratio differ from the quotient of the two
displayed medians. Both
directions verify across the implementation boundary and reject an altered digest before timing.
The packed Montgomery engine now dispatches 16- and 32-limb chains to separately compiled kernels,
letting Clang unroll the product/reduction loop by up to 32 without imposing either modulus
width on the generic fallback. A later fixed-count square dispatch reuses one input pointer for
both operands of the same CIOS body. Seven alternating WSL Clang 18 runs measured internal median
latencies changing from 0.829 to 0.797 ms for RSA signing, 0.025 to 0.024 ms for RSA verification,
0.447 to 0.436 ms for DSA signing, and 0.543 to 0.529 ms for DSA verification, improvements of
2.5--4.2%. A separate seven-run current-source comparison on that WSL build measured RSA
sign/verify ratios of 0.310/0.628. DSA contexts now prepare position-dependent four-bit Montgomery
tables for the bound generator and public key. Seven pinned runs measured DSA sign/verify medians
of 0.196/0.263 ms against OpenSSL's 0.330/0.289 ms. The paired median ratios are 1.667/1.103, with
per-run ranges of 1.603--1.726 and 1.083--1.143. Context binding builds 1,920 residues before the
timed repeated-operation rows; the table below retains the pinned Windows DSA key-generation row
because randomized prime search varied from 0.573 to 1.838 of OpenSSL in these seven runs and this
optimization does not change key generation. RSA prime generation now chooses one random seed and
walks nearby odd candidates while reusing the seed's grouped small-prime residues. It preserves the
existing 20 Miller--Rabin rounds. Against a separately built pre-change `HEAD`, 15 pinned WSL Clang
18 runs reduced certpp RSA-2048 key generation from a 63.937 ms median to 54.471 ms, a 14.8%
improvement. The current runs had a 1.824 median OpenSSL ratio, but the table retains the latest
internally consistent pinned Windows RSA snapshot until that configuration is remeasured; randomized
prime search makes cross-implementation key-generation ratios substantially noisier than the
within-implementation before/after result.
RSA CRT exponentiation now advances the two 1024-bit branches through one fixed five-bit schedule
and interleaves their independent CIOS carry chains on the same thread. Fifteen alternating pinned
WSL Clang 18 runs reduced the certpp RSA-2048 signing median from 0.811 to 0.772 ms, a 4.8%
latency reduction. The paired-run median OpenSSL ratio rose to 0.324. The pinned Windows table below
remains the last complete same-configuration snapshot until all three RSA rows are remeasured there.
The public-exponent path now combines its last odd-base multiply with the Montgomery-domain exit.
Eleven alternating pinned runs reduced verification from 0.024 to 0.023 ms and raised its median
OpenSSL ratio from 0.640 to 0.676; the private operation's re-encryption check gave signing a smaller
0.793 to 0.782 ms reduction. A separate seven-run current-source snapshot measured median RSA
sign/verify ratios of 0.328/0.673.

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
| RSA-2048 keygen | 58.127 ms | 21.197 ms | 0.393x |
| RSA-2048 sign | 0.805 ms | 0.255 ms | 0.316x |
| RSA-2048 verify | 0.025 ms | 0.016 ms | 0.668x |
| DSA-2048 keygen, including fresh parameters | 193.242 ms | 129.481 ms | 0.594x |
| DSA-2048 sign | 0.196 ms | 0.330 ms | 1.667x |
| DSA-2048 verify | 0.263 ms | 0.289 ms | 1.103x |
| GOST R 34.10-2012 |  | unavailable |  |
| Ed25519 sign, 32-byte message | 0.024 ms | 0.036 ms | 1.53x |
| Ed25519 verify, 32-byte message | 0.077 ms | 0.098 ms | 1.28x |
| ChaCha20-Poly1305 seal, 64 KiB | 3796 MiB/s | 4129 MiB/s | 0.92x |
| XChaCha20-Poly1305 seal, 64 KiB |  | unavailable |  |
| AES-256-GCM seal, 64 KiB | 10692 MiB/s | 11800 MiB/s | 0.90x |
| ChaCha20-Poly1305 seal, 64-byte record | 264 ns | 258 ns | 0.97x |
| XChaCha20-Poly1305 seal, 64-byte record |  | unavailable |  |
| AES-256-GCM seal, 64-byte record | 83 ns | 75 ns | 0.93x |
| X25519 keygen | 0.032 ms | 0.033 ms | 1.035x |
| X25519 derive | 0.032 ms | 0.029 ms | 0.909x |
| ML-KEM-512 keygen | 0.025 ms | 0.032 ms | 1.24x |
| ML-KEM-512 encapsulate | 0.019 ms | 0.022 ms | 1.15x |
| ML-KEM-512 decapsulate | 0.028 ms | 0.035 ms | 1.25x |
| ML-KEM-768 keygen | 0.042 ms | 0.046 ms | 1.11x |
| ML-KEM-768 encapsulate | 0.029 ms | 0.031 ms | 1.10x |
| ML-KEM-768 decapsulate | 0.040 ms | 0.048 ms | 1.18x |
| ML-KEM-1024 keygen | 0.064 ms | 0.072 ms | 1.13x |
| ML-KEM-1024 encapsulate | 0.039 ms | 0.043 ms | 1.07x |
| ML-KEM-1024 decapsulate | 0.053 ms | 0.064 ms | 1.19x |
| Ed448 sign, 32-byte message | 0.139 ms | 0.200 ms | 1.48x |
| Ed448 verify, 32-byte message | 0.191 ms | 0.188 ms | 0.99x |
| ML-DSA-44 sign, 32-byte message | 0.394 ms | 0.541 ms | 1.38x |
| ML-DSA-44 verify, 32-byte message | 0.090 ms | 0.118 ms | 1.31x |
| ML-DSA-65 sign, 32-byte message | 0.705 ms | 0.942 ms | 1.32x |
| ML-DSA-65 verify, 32-byte message | 0.145 ms | 0.182 ms | 1.26x |
| ML-DSA-87 sign, 32-byte message | 0.858 ms | 1.000 ms | 1.21x |
| ML-DSA-87 verify, 32-byte message | 0.253 ms | 0.301 ms | 1.17x |

The 20 prime-field curves and 10 binary-field curves were refreshed with five complete focused
runs after their respective field and point-arithmetic changes. The process was pinned to one
logical processor at high priority. This compact table reports the median `certpp / OpenSSL`
performance ratio; `examples/06_openssl_compare.cpp` prints both absolute latencies. Binary-curve
ECDH is unavailable because `CEcdsa2` implements signatures only.

| Curve | Keygen | ECDSA sign | ECDSA verify | ECDH derive |
|---|---:|---:|---:|---:|
| P-192 | 2.366x | 2.115x | 1.804x | 2.115x |
| P-224 | 2.006x | 1.794x | 1.663x | 2.057x |
| P-256 | 0.980x | 0.990x | 0.983x | 1.168x |
| P-384 | 1.803x | 1.734x | 1.457x | 1.690x |
| P-521 | 1.637x | 1.718x | 1.251x | 1.684x |
| secp256k1 | 2.088x | 2.184x | 1.784x | 2.276x |
| brainpoolP160r1 | 2.223x | 2.022x | 1.888x | 2.094x |
| brainpoolP192r1 | 2.250x | 2.000x | 1.830x | 2.174x |
| brainpoolP224r1 | 1.967x | 1.816x | 1.624x | 1.912x |
| brainpoolP256r1 | 2.073x | 1.816x | 1.708x | 1.866x |
| brainpoolP320r1 | 1.714x | 1.680x | 1.483x | 1.674x |
| brainpoolP384r1 | 1.710x | 1.595x | 1.417x | 1.663x |
| brainpoolP512r1 | 1.176x | 1.091x | 1.001x | 1.200x |
| brainpoolP160t1 | 2.182x | 1.915x | 1.879x | 2.072x |
| brainpoolP192t1 | 2.152x | 1.977x | 1.833x | 2.100x |
| brainpoolP224t1 | 2.041x | 1.930x | 1.636x | 2.050x |
| brainpoolP256t1 | 1.971x | 1.831x | 1.638x | 1.905x |
| brainpoolP320t1 | 1.803x | 1.756x | 1.441x | 1.713x |
| brainpoolP384t1 | 1.808x | 1.666x | 1.427x | 1.706x |
| brainpoolP512t1 | 1.278x | 1.199x | 1.012x | 1.288x |
| B-163 | 1.762x | 1.188x | 1.565x | unavailable |
| K-163 | 1.689x | 1.121x | 1.487x | unavailable |
| B-233 | 1.785x | 1.191x | 1.543x | unavailable |
| K-233 | 1.760x | 1.165x | 1.491x | unavailable |
| B-283 | 1.549x | 1.205x | 1.504x | unavailable |
| K-283 | 1.476x | 1.130x | 1.418x | unavailable |
| B-409 | 1.830x | 1.434x | 1.761x | unavailable |
| K-409 | 1.760x | 1.371x | 1.691x | unavailable |
| B-571 | 1.705x | 1.489x | 1.728x | unavailable |
| K-571 | 1.596x | 1.404x | 1.648x | unavailable |

ECDSA and GOST verification use one public-scalar `linearCombination()` instead of two
private-scalar ladders followed by an affine addition. The binary-field path now combines
fixed-count PCLMUL product and square kernels with a descending word reducer and mixed affine/
Lopez-Dahab addition. Key generation also avoids re-running public-key validation over a scalar and
point it just constructed. All 30 directly comparable binary-curve rows now clear the gate. The
five-run medians for B-163 keygen/sign/verify are 0.099/0.148/0.219 ms against OpenSSL's
0.176/0.175/0.343 ms; K-571 measures 0.876/1.057/1.764 ms against 1.398/1.484/2.885 ms.
Public verification remains deliberately variable-time because both verification scalars are
public; private scalar paths retain their existing control-flow policy.

The prime-field refresh first put 76 of 80 directly comparable operations at or above the 0.90
gate. A later 15-run, single-CPU, alternating comparison forced
the fixed-width field selector and sparse P-256 multiplication body into each point formula. The
certpp key-generation/signing/verification/ECDH medians fell from 0.037/0.047/0.149/0.141 ms to
0.032/0.043/0.141/0.134 ms, improvements of 15.6/9.3/5.7/5.2%. The paired OpenSSL ratios are now
0.797/0.477/0.406/0.322. The benchmark executable's text grew
by 81,060 bytes, or 7.6%, which is the measured code-size cost of exposing the field body to the
optimizer. P-256 also uses a compact 33-row signed radix-256 affine base table. Centered digits use
magnitudes at most 128, one extra row consumes the final carry, and masked Y negation handles their
sign. Every private lookup still scans all candidate magnitudes. P-256 verification
contexts now use position-dependent four-bit public-scalar combs: a process-wide 60 KiB base table
and one 60 KiB public-key table per context. Direct public lookup removes all 256 point doublings
and performs at most 128 mixed additions; private scalar paths retain full-scan selection. In 21
single-CPU alternating runs, verification fell from 0.142 to 0.058 ms, a 2.45x improvement, and
reached 0.999 of OpenSSL. The private P-256 comb now uses an AVX-512F selector when the CPU and
operating system expose the required state. Each table entry is exactly 64 bytes, so the selector
loads every entry in a row into one ZMM register and uses equality masks to retain the requested
point. The scalar full-scan selector remains the fallback. Against the immediately preceding
binary, 21 alternating pinned runs improved certpp key generation from 0.044 to 0.038 ms and
signing from 0.060 to 0.055 ms, or 15.8% and 8.3%, without changing verification or ECDH.

Replacing the preceding unsigned seven-bit comb with signed radix-256 reduced the table from about
296 KiB to 266 KiB, reduced the expected mixed additions from 36.7 to 32.4, and lowered the number
of scanned nonzero entries from 4,699 to 4,224. Seven alternating pinned before/after runs reduced
the certpp key-generation median from 0.027 to 0.025 ms and signing from 0.039 to 0.037 ms. Their
median OpenSSL ratios rose from 0.890 to 0.959 and from 0.514 to 0.535 respectively. Crafted scalar
tests cover the positive 128 boundary, carry propagation between every byte, and the final carry.

P-256 ECDH contexts now prepare a position-dependent four-bit comb for the current peer on first
use and retain its 60 KiB Montgomery-limb table while that peer remains selected. Private digits
scan all fifteen nonzero candidates in each row and select with masks. The repeated derive path
therefore performs 64 mixed additions and no point doublings; changing the peer rebuilds the table,
and unsupported curves retain the ordinary private window. Seven alternating pinned runs reduced
the repeated certpp derive median from 0.140 to 0.039 ms and raised its OpenSSL ratio from 0.315 to
1.164. The comparison performs peer binding and its interoperability check before the timed row, as
both implementations reuse a context already configured with that peer.

P-256 signing keeps the ordinary path for the first signature on a newly bound context. Later
signatures prepare eight independent random nonces at a time. Their projective `k*G` results share
one field inversion, and their `k^-1 mod n` values share one order inversion; the context retains
only each resulting public `r` and secret `k^-1`. Consuming an entry moves it out, while key reset
and context destruction securely clear every unused inverse. The full-scan signed radix-256 point
path and OS CSPRNG remain unchanged. Benchmark setup crosses a batch boundary and has OpenSSL verify
each resulting signature before timing. Seven alternating pinned runs reduced repeated certpp
signing from a 0.037 ms median to 0.020 ms and raised the OpenSSL ratio from 0.531 to 0.990. A refill
has higher latency, but its complete cost is included in the repeated-signing row; a one-shot
context does not build a batch.

The current P-256 row uses 1,000 operations per batch and seven complete single-CPU runs. Each
measurement warms both implementations and alternates which independent batch runs first, avoiding
the frequency bias observed when every certpp batch preceded every OpenSSL batch. Median
keygen/sign/verify/ECDH ratios are 0.980/0.990/0.983/1.168; their per-run ranges are
0.948--1.053, 0.931--1.027, 0.939--1.027, and 1.150--1.297 respectively. All 80 prime-field rows
now meet the gate. Key generation, signing, and verification remain close enough to require
remeasurement after related changes.
Other prime curves retain width-eight affine odd-multiple tables stored directly as Montgomery
limbs, so repeated verification does not reconstruct, normalize, or reconvert their coordinates.

Ed448 now uses fixed-width Fe448 arithmetic and 10-column comb tables for the base point and each
public key. The current matched result and its validation are recorded in
[Current Ed448 comparison](#current-ed448-comparison).

X25519 key generation no longer runs a second 255-step ladder to multiply its freshly derived
public value by the cofactor. The native radix-51 path now uses independent carry chains, a
ten-product squaring schedule, shorter ladder live ranges, and cached runtime dispatch to generic
AVX2/BMI2/ADX or exact Tiger Lake tuning. The generic gate reads CPUID and the OS-enabled XCR0
vector state directly, avoiding compiler-version-specific feature strings while retaining the
required AVX operating-system check. Private keys retain a clamped scalar and contexts retain
successfully checked bound keys. The portable radix-2^25.5 path remains available. Current matched
measurements and validation are recorded in
[Current X25519 comparison](#current-x25519-comparison).

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
exponents produced most of the reduction. The small-prime sieve now groups primes into products
that fit 32 bits, scans the candidate once per product, and tests the product remainder against
its factors. On a fixed 2048-bit composite whose first divisor in the sieve is 997, the nine-run
median fell from 86.687 to 16.790 microseconds per call, a 5.16x local before/after improvement.
The original eleven-run OpenSSL comparison and the current focused DSA refresh are reported above.
Key generation still varies with how quickly random prime candidates are found, while repeated
signing and verification are stable. DSA's repeated-operation rows now exceed the gate; its key
generation and the RSA rows remain tracked in
[the performance roadmap](../roadmap/performance.md#openssl-90-program).

### Current ML-KEM comparison

The ML-KEM rows were refreshed on 2026-10-18 on the Windows review host with Clang 22.1.8
targeting the MinGW64 ABI and OpenSSL 3.6.4. The focused `--mlkem` harness ran seven times.
Each run first imported raw public keys in both directions and checked
`certpp encapsulate -> OpenSSL decapsulate` plus the reverse, then timed each implementation
in its own warmed loop. Output buffers were allocated before both timed loops. The table reports
the median rounded latency and the median of the seven per-run performance ratios.

| Operation | certpp | OpenSSL EVP | certpp / OpenSSL performance |
|---|---:|---:|---:|
| ML-KEM-512 keygen | **0.025 ms** | 0.032 ms | **1.24x** |
| ML-KEM-512 encapsulate | **0.019 ms** | 0.022 ms | **1.15x** |
| ML-KEM-512 decapsulate | **0.028 ms** | 0.035 ms | **1.25x** |
| ML-KEM-768 keygen | **0.042 ms** | 0.046 ms | **1.11x** |
| ML-KEM-768 encapsulate | **0.029 ms** | 0.031 ms | **1.10x** |
| ML-KEM-768 decapsulate | **0.040 ms** | 0.048 ms | **1.18x** |
| ML-KEM-1024 keygen | **0.064 ms** | 0.072 ms | **1.13x** |
| ML-KEM-1024 encapsulate | **0.039 ms** | 0.043 ms | **1.07x** |
| ML-KEM-1024 decapsulate | **0.053 ms** | 0.064 ms | **1.19x** |

The implementation now parses coefficients with bit reservoirs, samples CBD coefficients in
fixed-width bit lanes, uses bounded Barrett reduction in the NTT, and expands a bound key's public
matrix and secret vector once when an `IKemContext` is reset. The raw `CMlKem` entry points
still prepare their supplied byte spans on every call. NIST ACVP vectors, modified-ciphertext
implicit rejection, canonical-key negatives, ring reference checks, and both interoperability
directions passed after the change. All nine directly comparable ML-KEM rows exceed the 0.90
threshold on this host.

### Current ML-DSA comparison

The ML-DSA rows were refreshed on 2026-10-18 in the same Windows Clang 22.1.8 and OpenSSL
3.6.4 environment as ML-KEM. The focused `--mldsa` harness ran seven times. Each run used a
bound certpp context and an OpenSSL key, warmed both sides independently, and took the fastest
of five 20-operation batches. Signing is rejection-sampled and therefore varies with the nonce;
the table reports the median rounded latency and the median of the seven paired performance
ratios rather than selecting one favorable run.

| Operation | certpp | OpenSSL EVP | certpp / OpenSSL performance |
|---|---:|---:|---:|
| ML-DSA-44 sign, 32-byte message | **0.394 ms** | 0.541 ms | **1.38x** |
| ML-DSA-44 verify, 32-byte message | **0.090 ms** | 0.118 ms | **1.31x** |
| ML-DSA-65 sign, 32-byte message | **0.705 ms** | 0.942 ms | **1.32x** |
| ML-DSA-65 verify, 32-byte message | **0.145 ms** | 0.182 ms | **1.26x** |
| ML-DSA-87 sign, 32-byte message | **0.858 ms** | 1.000 ms | **1.21x** |
| ML-DSA-87 verify, 32-byte message | **0.253 ms** | 0.301 ms | **1.17x** |

The NTT now uses fixed-modulus Montgomery products in its butterflies and pointwise
multiplication instead of a 64-bit division per coefficient. Bit packing uses a 64-bit
reservoir, and SHAKE rejection samplers consume complete rate blocks while preserving byte and
nibble order. The exact FIPS 204 Appendix B twiddle table remains exposed in normal form; a
separate multiplication form is derived once for the hot loops. Official signing and
verification vectors, ring reference products, codec boundaries, malformed signatures, and the
public wrapper all passed after the change. All six directly comparable ML-DSA rows exceed the
0.90 threshold on this host. This performance result does not make signing constant-time: the
standard rejection loop still has a nonce-dependent attempt count, which remains a separate
timing-review item.

### Current Ed25519 comparison

The Ed25519 row was refreshed on 2026-10-18 in WSL2 Ubuntu using GCC 13.3.0 and OpenSSL 3.0.13.
The Release build enabled the native radix-51 field path. Eleven focused `--ed25519` harness runs were made; each run
measured each side independently and took the fastest of five 200-operation batches. The table
reports the median rounded latency and the median of each run's reported performance ratio.

| Operation | certpp | OpenSSL EVP | certpp / OpenSSL performance |
|---|---:|---:|---:|
| Ed25519 sign, 32-byte message | **0.024 ms** | 0.036 ms | **1.53x** |
| Ed25519 verify, 32-byte message | **0.077 ms** | 0.098 ms | **1.28x** |

The eleven certpp/OpenSSL performance ratios had medians of 1.53 for signing and 1.28 for
verification. The implementation reaches those results by using affine precomputed fixed-base
points, loose additions consumed immediately by field multiplication, a generated squaring kernel,
a shared-doubling `S*B - k*A` verifier, and an odd-multiple table stored with each public key.
Verification still requires imported public keys to be in the prime-order subgroup. It omits a
separate `L*R` multiplication because the exact uncofactored equation, with `A` already in that
subgroup, can accept only an `R` in the same subgroup. Canonical decoding, on-curve recovery, and
identity rejection remain, and a dedicated order-two `R` negative test covers this boundary.

### Current X25519 comparison

The X25519 rows were refreshed on 2026-10-18 in a static Windows x86-64 Release build using Clang
22.1.8, the native radix-51 field path, and OpenSSL 3.6.4 from MSYS2 MinGW64. Fifteen focused
`--x25519` runs pinned the process to logical processor 0 at high priority and measured each
implementation independently. Each program row is the fastest of five 200-operation batches per
side; the table reports median rounded latency and the median of the 15 per-run performance
ratios.

| Operation | certpp | OpenSSL EVP | certpp / OpenSSL performance |
|---|---:|---:|---:|
| X25519 keygen | **0.032 ms** | 0.033 ms | **1.035x** |
| X25519 derive | 0.032 ms | **0.029 ms** | **0.909x** |

Relative to the earlier 0.139/0.136 ms portable measurements, radix-51 first reached
0.049/0.048 ms in WSL. Two-chain carry reduction and a dedicated square schedule then shortened
the field work; whole-ladder runtime dispatch selects a generic AVX2/BMI2/ADX body or an exact
Tiger Lake body, with a portable fallback. The generic decision uses CPUID plus OSXSAVE/XCR0, so
Clang releases that do not accept `adx` as a builtin feature string can still compile the path.
Key construction clamps once, and a context reuses its
validated bound private and peer key objects. The current keygen and derive medians both meet the
90% completion threshold. RFC 7748 known-answer and repeated-iteration vectors, exact-arithmetic
field checks, cross-implementation shared-secret checks, non-canonical-u handling, and low-order
peer rejection remain the acceptance boundary for later changes.

### Current Ed448 comparison

The Ed448 rows were refreshed on 2026-10-18 in WSL2 Ubuntu with GCC 13.3.0 and OpenSSL 3.0.13.
The Windows MinGW64 compiler installation could not start `cc1plus.exe` and exited with
`0xC0000139`, so both sides were built and measured in the same WSL environment instead. Eleven
focused `--ed448` runs were made; each side was measured independently and each run took the
fastest of five 20-operation batches. The table reports median rounded latency and the median of
the per-run performance ratios.

| Operation | certpp | OpenSSL EVP | certpp / OpenSSL performance |
|---|---:|---:|---:|
| Ed448 sign, 32-byte message | **0.139 ms** | 0.200 ms | **1.48x** |
| Ed448 verify, 32-byte message | 0.191 ms | **0.188 ms** | **0.99x** |

The field implementation uses eight radix-2^56 limbs where a native 128-bit product is available
and sixteen radix-2^28 limbs otherwise. Fixed exponent chains replace general big-number field
inversion and square roots. Mixed precomputed addition and 10-column comb tables reduce base-point
multiplication and joint `S*B - k*A` verification to 45 online doubling rows; the public-key table
is retained for repeated verification. Imported public keys still undergo the full subgroup check.
Signature `R` retains canonical, on-curve, and identity checks; the exact uncofactored equation
permits the redundant `L*R` multiplication to be omitted, with an order-two `R` negative test
covering that boundary. RFC 8032, malformed-input, altered-message/signature, wrong-key, and field
arithmetic tests pass on the native WSL layout and the 16-limb MSVC fallback. Comb lookup indices
depend on the scalar, so these measurements do not support a constant-time claim for signing.

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
