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

## Against OpenSSL

A number means nothing in isolation, so the same algorithms were measured against OpenSSL 3.0.13
on the same machine.

**Both sides are timed alone, in their own loops.** Interleaving the two implementations in one
loop -- the obvious way to keep them on equal footing -- turns out to corrupt both: certpp's
SHA-256 drops from 1523 to 765 MiB/s and OpenSSL's halves too, because alternating caches and
branch predictors penalises both. OpenSSL is called through EVP directly rather than through this
library's wrapper, which measures the cryptography rather than the per-call allocations a caller
through `certpp` would add. Both sides are warmed up first: OpenSSL resolves its constructors
lazily, and a cold first SHA-256 of 64 KiB costs 963 us against 38.9 us warm.

Each figure is the best of three runs of the harness on a quiet machine, so the spread between
runs is 1--3% for a side measured alone -- the ratios hold, but a single run's absolute value is
not the algorithm's speed.

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
| Ed25519 sign | 0.162 ms | 0.036 ms | 4.5x slower |

SHA-256 is at parity because both sides call SHA-NI for it; SHA-512 at 0.58x is the clearest row
where neither does. The gap narrowed from 0.51x after BMI2 RORX optimization (+7.5% SHA-512).

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
