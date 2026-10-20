# Performance

[한국어](performance.ko.md)

This page owns the current benchmark snapshot. Historical optimization results
and superseded measurements live in [History](../HISTORY.md); they are not mixed
into the current tables below.

## Measurement snapshot

The complete inventory was rebuilt and measured on 2026-10-20 from source
revision `2657b8c` after the secure allocator and secure-container migration.
The host was an Intel Core i7-11370H running Windows. Both benchmark programs
used Clang 22.1.8 targeting the MSYS2 MinGW64 ABI, OpenSSL 3.6.4, a CMake
Release shared-library build, radix-51 enabled, and the default secure-memory
mode. The build supplied `-lwinpthread` to both executable and shared-library
link steps because `SecurePool` uses `std::mutex`.

The source of the measurements is
[`examples/05_benchmark.cpp`](../../examples/05_benchmark.cpp) and
[`examples/06_openssl_compare.cpp`](../../examples/06_openssl_compare.cpp).
The process ran at high priority and was pinned to logical processor 0. Three
complete process runs were made for each program. Each harness row selects the
fastest of its internal batches; the tables report the median certpp value, the
median OpenSSL value, the median of the three paired performance ratios, and
the minimum-to-maximum paired ratio. Throughput ratios are `certpp / OpenSSL`;
latency ratios are `OpenSSL / certpp`, so a larger ratio is always better and
`1.000x` is parity.

After the optimization pass, the six rows that had been below the performance
gate were replaced with seven focused runs under the same priority, affinity,
build, and ratio rules. Rows from those focused runs use their seven-run
medians and ranges; the rest retain the complete three-run inventory snapshot.

The comparison harness checks interoperable results before timing: digests,
ciphertexts and tags, signatures, shared secrets, and KEM outputs must agree.
All three complete runs of both programs exited successfully with empty
standard error. Every algorithm exposed by the internal benchmark completed.

## Current result

Every directly comparable row now has a median of at least the active 0.900x
target. The focused seven-run medians for the former gaps are RSA-2048 key
generation/sign/verify at 1.150x/0.931x/0.942x, DSA-2048 key and parameter
generation at 1.387x, P-256 key generation at 0.986x, and ML-KEM-768 key
generation at 0.988x. RSA and DSA key generation include randomized prime
search and retain wide run-to-run ranges, so their ratios should be read as
distributions rather than deterministic operation costs.

OpenSSL's tested default and legacy providers do not expose Streebog, GOST R
34.10-2012, XChaCha20-Poly1305, or binary-curve ECDH matching the library's
surface. Their certpp-only measurements are recorded separately below.
Remaining work is tracked in the
[performance roadmap](../roadmap/performance.md#performance-work). Automatic
CI and a broader platform matrix remain separate future work in
[Plans](../PLANS.md#automated-ci-and-platform-matrix).

## Current OpenSSL comparison

### Hashing, 64 KiB

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| MD4 | 1565 MiB/s | 1362 MiB/s | 1.140x | 1.100–1.150x |
| MD5 | 756 MiB/s | 825 MiB/s | 0.920x | 0.920–0.920x |
| SHA-1 | 1760 MiB/s | 1835 MiB/s | 0.960x | 0.940–1.000x |
| SHA-224 | 1462 MiB/s | 1570 MiB/s | 0.970x | 0.930–0.970x |
| SHA-256 | 1518 MiB/s | 1558 MiB/s | 0.970x | 0.960–1.070x |
| SHA-384 | 649 MiB/s | 690 MiB/s | 0.960x | 0.940–0.980x |
| SHA-512 | 675 MiB/s | 698 MiB/s | 0.960x | 0.960–1.020x |
| SHA3-256 | 515 MiB/s | 418 MiB/s | 1.240x | 1.220–1.240x |
| SHA3-512 | 272 MiB/s | 227 MiB/s | 1.200x | 1.190–1.200x |
| SHAKE-128 | 636 MiB/s | 509 MiB/s | 1.230x | 1.210–1.250x |
| SHAKE-256 | 494 MiB/s | 411 MiB/s | 1.220x | 1.200–1.240x |
| BLAKE2s | 587 MiB/s | 556 MiB/s | 1.060x | 1.050–1.060x |
| Streebog-256 | — | unavailable | — | — |
| Streebog-512 | — | unavailable | — | — |

### Block cipher, 64 KiB

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| AES-128-CBC | 1789 MiB/s | 1851 MiB/s | 0.970x | 0.960–0.970x |
| AES-192-CBC | 1428 MiB/s | 1486 MiB/s | 0.980x | 0.960–0.990x |
| AES-256-CBC | 1265 MiB/s | 1322 MiB/s | 0.960x | 0.950–1.010x |
| DES-CBC | 74 MiB/s | 79 MiB/s | 1.080x | 0.900–1.090x |
| 3DES-CBC | 31 MiB/s | 30 MiB/s | 1.060x | 1.040–1.080x |
| ARIA-128-CBC | 173 MiB/s | 154 MiB/s | 1.120x | 1.080–1.130x |
| ARIA-192-CBC | 149 MiB/s | 132 MiB/s | 1.120x | 1.090–1.130x |
| ARIA-256-CBC | 129 MiB/s | 119 MiB/s | 1.090x | 1.060–1.110x |

### AEAD seal, 64 KiB

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| ChaCha20-Poly1305 | 3828 MiB/s | 4033 MiB/s | 0.950x | 0.940–0.950x |
| XChaCha20-Poly1305 | — | unavailable | — | — |
| AES-256-GCM | 10766 MiB/s | 11690 MiB/s | 0.920x | 0.910–0.920x |

### AEAD seal, 64-byte record

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| ChaCha20-Poly1305 | 257 ns | 264 ns | 1.030x | 0.990–1.130x |
| XChaCha20-Poly1305 | — | unavailable | — | — |
| AES-256-GCM | 81 ns | 79 ns | 0.970x | 0.910–1.150x |

### Key agreement

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| X25519 keygen | 0.032 ms | 0.034 ms | 1.060x | 1.059–1.093x |
| X25519 derive | 0.032 ms | 0.029 ms | 0.912x | 0.908–0.924x |

### Prime-curve signatures and agreement

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| P-192 keygen | 0.097 ms | 0.228 ms | 2.305x | 2.226–2.362x |
| P-192 ECDSA sign | 0.103 ms | 0.207 ms | 2.012x | 2.007–2.062x |
| P-192 ECDSA verify | 0.113 ms | 0.201 ms | 1.820x | 1.724–1.938x |
| P-192 ECDH derive | 0.095 ms | 0.195 ms | 2.149x | 2.046–2.190x |
| P-224 keygen | 0.152 ms | 0.305 ms | 2.036x | 1.989–2.076x |
| P-224 ECDSA sign | 0.164 ms | 0.308 ms | 1.889x | 1.858–1.901x |
| P-224 ECDSA verify | 0.168 ms | 0.283 ms | 1.630x | 1.600–1.687x |
| P-224 ECDH derive | 0.145 ms | 0.284 ms | 1.970x | 1.955–2.007x |
| P-256 keygen | 0.019 ms | 0.019 ms | 0.986x | 0.960–1.300x |
| P-256 ECDSA sign | 0.022 ms | 0.021 ms | 0.940x | 0.806–0.948x |
| P-256 ECDSA verify | 0.062 ms | 0.061 ms | 0.980x | 0.943–1.024x |
| P-256 ECDH derive | 0.038 ms | 0.046 ms | 1.214x | 1.172–1.243x |
| P-384 keygen | 0.433 ms | 0.823 ms | 1.859x | 1.849–1.901x |
| P-384 ECDSA sign | 0.464 ms | 0.819 ms | 1.787x | 1.764–1.792x |
| P-384 ECDSA verify | 0.457 ms | 0.708 ms | 1.475x | 1.433–1.548x |
| P-384 ECDH derive | 0.429 ms | 0.786 ms | 1.832x | 1.823–1.874x |
| P-521 keygen | 1.110 ms | 1.852 ms | 1.711x | 1.661–1.770x |
| P-521 ECDSA sign | 1.156 ms | 1.952 ms | 1.650x | 1.472–1.689x |
| P-521 ECDSA verify | 1.089 ms | 1.491 ms | 1.368x | 1.367–1.371x |
| P-521 ECDH derive | 1.079 ms | 1.806 ms | 1.693x | 1.674–1.708x |
| secp256k1 keygen | 0.172 ms | 0.375 ms | 2.171x | 2.077–2.187x |
| secp256k1 ECDSA sign | 0.182 ms | 0.370 ms | 2.002x | 1.995–2.036x |
| secp256k1 ECDSA verify | 0.197 ms | 0.340 ms | 1.758x | 1.722–1.857x |
| secp256k1 ECDH derive | 0.167 ms | 0.350 ms | 2.070x | 2.056–2.101x |
| brainpoolP160r1 keygen | 0.080 ms | 0.179 ms | 2.223x | 2.219–2.228x |
| brainpoolP160r1 ECDSA sign | 0.088 ms | 0.175 ms | 1.974x | 1.900–1.994x |
| brainpoolP160r1 ECDSA verify | 0.095 ms | 0.174 ms | 1.872x | 1.799–1.881x |
| brainpoolP160r1 ECDH derive | 0.078 ms | 0.162 ms | 2.072x | 2.058–2.080x |
| brainpoolP192r1 keygen | 0.094 ms | 0.210 ms | 2.231x | 2.227–2.254x |
| brainpoolP192r1 ECDSA sign | 0.106 ms | 0.207 ms | 1.980x | 1.952–2.005x |
| brainpoolP192r1 ECDSA verify | 0.110 ms | 0.215 ms | 1.903x | 1.800–1.950x |
| brainpoolP192r1 ECDH derive | 0.092 ms | 0.199 ms | 2.154x | 2.100–2.183x |
| brainpoolP224r1 keygen | 0.152 ms | 0.305 ms | 2.013x | 2.002–2.107x |
| brainpoolP224r1 ECDSA sign | 0.164 ms | 0.309 ms | 1.892x | 1.840–1.917x |
| brainpoolP224r1 ECDSA verify | 0.176 ms | 0.297 ms | 1.691x | 1.616–1.763x |
| brainpoolP224r1 ECDH derive | 0.147 ms | 0.295 ms | 2.016x | 1.925–2.053x |
| brainpoolP256r1 keygen | 0.174 ms | 0.342 ms | 2.010x | 1.934–2.018x |
| brainpoolP256r1 ECDSA sign | 0.182 ms | 0.334 ms | 1.852x | 1.830–1.868x |
| brainpoolP256r1 ECDSA verify | 0.192 ms | 0.328 ms | 1.683x | 1.673–1.742x |
| brainpoolP256r1 ECDH derive | 0.165 ms | 0.316 ms | 1.928x | 1.908–1.970x |
| brainpoolP320r1 keygen | 0.286 ms | 0.533 ms | 1.870x | 1.840–1.939x |
| brainpoolP320r1 ECDSA sign | 0.311 ms | 0.544 ms | 1.757x | 1.732–1.819x |
| brainpoolP320r1 ECDSA verify | 0.317 ms | 0.504 ms | 1.586x | 1.568–1.609x |
| brainpoolP320r1 ECDH derive | 0.290 ms | 0.535 ms | 1.828x | 1.792–1.847x |
| brainpoolP384r1 keygen | 0.456 ms | 0.805 ms | 1.779x | 1.754–1.826x |
| brainpoolP384r1 ECDSA sign | 0.480 ms | 0.835 ms | 1.730x | 1.657–1.747x |
| brainpoolP384r1 ECDSA verify | 0.490 ms | 0.717 ms | 1.483x | 1.464–1.510x |
| brainpoolP384r1 ECDH derive | 0.468 ms | 0.790 ms | 1.688x | 1.666–1.751x |
| brainpoolP512r1 keygen | 0.915 ms | 1.157 ms | 1.250x | 1.208–1.265x |
| brainpoolP512r1 ECDSA sign | 0.992 ms | 1.172 ms | 1.182x | 1.179–1.193x |
| brainpoolP512r1 ECDSA verify | 0.990 ms | 1.022 ms | 1.032x | 1.017–1.071x |
| brainpoolP512r1 ECDH derive | 0.923 ms | 1.118 ms | 1.210x | 1.201–1.257x |
| brainpoolP160t1 keygen | 0.080 ms | 0.176 ms | 2.199x | 2.163–2.447x |
| brainpoolP160t1 ECDSA sign | 0.089 ms | 0.170 ms | 1.917x | 1.783–1.920x |
| brainpoolP160t1 ECDSA verify | 0.093 ms | 0.169 ms | 1.813x | 1.808–1.910x |
| brainpoolP160t1 ECDH derive | 0.081 ms | 0.161 ms | 2.000x | 1.901–2.038x |
| brainpoolP192t1 keygen | 0.095 ms | 0.207 ms | 2.167x | 2.166–2.175x |
| brainpoolP192t1 ECDSA sign | 0.104 ms | 0.201 ms | 1.950x | 1.930–2.129x |
| brainpoolP192t1 ECDSA verify | 0.113 ms | 0.205 ms | 1.811x | 1.808–1.923x |
| brainpoolP192t1 ECDH derive | 0.092 ms | 0.193 ms | 2.069x | 1.884–2.104x |
| brainpoolP224t1 keygen | 0.151 ms | 0.312 ms | 2.015x | 2.003–2.085x |
| brainpoolP224t1 ECDSA sign | 0.165 ms | 0.308 ms | 1.875x | 1.866–1.903x |
| brainpoolP224t1 ECDSA verify | 0.166 ms | 0.274 ms | 1.654x | 1.617–1.662x |
| brainpoolP224t1 ECDH derive | 0.145 ms | 0.303 ms | 1.978x | 1.971–2.087x |
| brainpoolP256t1 keygen | 0.169 ms | 0.342 ms | 2.061x | 2.003–2.125x |
| brainpoolP256t1 ECDSA sign | 0.179 ms | 0.340 ms | 1.879x | 1.861–1.898x |
| brainpoolP256t1 ECDSA verify | 0.186 ms | 0.306 ms | 1.633x | 1.626–1.645x |
| brainpoolP256t1 ECDH derive | 0.163 ms | 0.328 ms | 1.946x | 1.937–2.020x |
| brainpoolP320t1 keygen | 0.274 ms | 0.544 ms | 1.934x | 1.894–1.998x |
| brainpoolP320t1 ECDSA sign | 0.296 ms | 0.546 ms | 1.843x | 1.801–1.845x |
| brainpoolP320t1 ECDSA verify | 0.299 ms | 0.463 ms | 1.552x | 1.550–1.633x |
| brainpoolP320t1 ECDH derive | 0.272 ms | 0.511 ms | 1.886x | 1.880–1.901x |
| brainpoolP384t1 keygen | 0.425 ms | 0.797 ms | 1.857x | 1.857–1.874x |
| brainpoolP384t1 ECDSA sign | 0.478 ms | 0.822 ms | 1.730x | 1.718–1.773x |
| brainpoolP384t1 ECDSA verify | 0.464 ms | 0.699 ms | 1.478x | 1.406–1.507x |
| brainpoolP384t1 ECDH derive | 0.438 ms | 0.811 ms | 1.821x | 1.807–1.850x |
| brainpoolP512t1 keygen | 0.880 ms | 1.127 ms | 1.281x | 1.243–1.338x |
| brainpoolP512t1 ECDSA sign | 0.928 ms | 1.155 ms | 1.239x | 1.223–1.245x |
| brainpoolP512t1 ECDSA verify | 0.889 ms | 0.906 ms | 1.039x | 1.016–1.058x |
| brainpoolP512t1 ECDH derive | 0.851 ms | 1.094 ms | 1.282x | 1.276–1.286x |

### Binary-curve signatures (ECDH unsupported by certpp)

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| B-163 keygen | 0.100 ms | 0.176 ms | 1.763x | 1.684–1.773x |
| B-163 ECDSA sign | 0.152 ms | 0.177 ms | 1.165x | 1.164–1.176x |
| B-163 ECDSA verify | 0.217 ms | 0.341 ms | 1.574x | 1.569–1.611x |
| K-163 keygen | 0.101 ms | 0.168 ms | 1.690x | 1.663–1.716x |
| K-163 ECDSA sign | 0.150 ms | 0.172 ms | 1.146x | 1.134–1.150x |
| K-163 ECDSA verify | 0.220 ms | 0.330 ms | 1.478x | 1.434–1.509x |
| B-233 keygen | 0.132 ms | 0.231 ms | 1.764x | 1.743–1.862x |
| B-233 ECDSA sign | 0.201 ms | 0.237 ms | 1.198x | 1.182–1.222x |
| B-233 ECDSA verify | 0.311 ms | 0.463 ms | 1.540x | 1.490–1.564x |
| K-233 keygen | 0.132 ms | 0.225 ms | 1.746x | 1.697–1.820x |
| K-233 ECDSA sign | 0.198 ms | 0.234 ms | 1.184x | 1.157–1.186x |
| K-233 ECDSA verify | 0.300 ms | 0.460 ms | 1.534x | 1.515–1.569x |
| B-283 keygen | 0.274 ms | 0.418 ms | 1.536x | 1.529–1.558x |
| B-283 ECDSA sign | 0.350 ms | 0.435 ms | 1.194x | 1.178–1.250x |
| B-283 ECDSA verify | 0.549 ms | 0.834 ms | 1.513x | 1.485–1.518x |
| K-283 keygen | 0.266 ms | 0.385 ms | 1.465x | 1.444–1.550x |
| K-283 ECDSA sign | 0.349 ms | 0.430 ms | 1.138x | 1.132–1.248x |
| K-283 ECDSA verify | 0.560 ms | 0.792 ms | 1.406x | 1.385–1.496x |
| B-409 keygen | 0.373 ms | 0.654 ms | 1.788x | 1.752–1.867x |
| B-409 ECDSA sign | 0.500 ms | 0.704 ms | 1.395x | 1.384–1.445x |
| B-409 ECDSA verify | 0.776 ms | 1.364 ms | 1.742x | 1.612–1.791x |
| K-409 keygen | 0.370 ms | 0.622 ms | 1.743x | 1.669–1.759x |
| K-409 ECDSA sign | 0.497 ms | 0.670 ms | 1.356x | 1.334–1.419x |
| K-409 ECDSA verify | 0.770 ms | 1.286 ms | 1.655x | 1.595–1.683x |
| B-571 keygen | 0.903 ms | 1.505 ms | 1.703x | 1.627–1.709x |
| B-571 ECDSA sign | 1.098 ms | 1.574 ms | 1.443x | 1.433–1.444x |
| B-571 ECDSA verify | 1.763 ms | 3.091 ms | 1.753x | 1.662–1.758x |
| K-571 keygen | 0.896 ms | 1.389 ms | 1.604x | 1.543–1.621x |
| K-571 ECDSA sign | 1.078 ms | 1.508 ms | 1.425x | 1.370–1.436x |
| K-571 ECDSA verify | 1.788 ms | 2.924 ms | 1.668x | 1.611–1.680x |

### Key encapsulation

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| ML-KEM-512 keygen | 0.030 ms | 0.032 ms | 1.025x | 0.974–1.042x |
| ML-KEM-512 encapsulate | 0.021 ms | 0.023 ms | 1.085x | 1.085–1.141x |
| ML-KEM-512 decapsulate | 0.028 ms | 0.035 ms | 1.214x | 1.111–1.248x |
| ML-KEM-768 keygen | 0.047 ms | 0.046 ms | 0.988x | 0.938–1.019x |
| ML-KEM-768 encapsulate | 0.028 ms | 0.031 ms | 1.074x | 1.069–1.088x |
| ML-KEM-768 decapsulate | 0.041 ms | 0.049 ms | 1.186x | 1.182–1.202x |
| ML-KEM-1024 keygen | 0.076 ms | 0.071 ms | 0.937x | 0.927–0.938x |
| ML-KEM-1024 encapsulate | 0.040 ms | 0.043 ms | 1.068x | 1.055–1.142x |
| ML-KEM-1024 decapsulate | 0.054 ms | 0.063 ms | 1.165x | 1.158–1.183x |

### Signatures

| Operation | certpp median | OpenSSL median | Median ratio | Ratio range |
|---|---:|---:|---:|---:|
| RSA-2048 keygen | 26.272 ms | 32.302 ms | 1.150x | 0.854–1.845x |
| RSA-2048 sign | 0.292 ms | 0.273 ms | 0.931x | 0.875–0.959x |
| RSA-2048 verify | 0.017 ms | 0.016 ms | 0.942x | 0.930–0.953x |
| DSA-2048 keygen | 110.171 ms | 132.826 ms | 1.387x | 0.759–1.800x |
| DSA-2048 sign | 0.265 ms | 0.349 ms | 1.306x | 0.962–1.458x |
| DSA-2048 verify | 0.307 ms | 0.300 ms | 0.997x | 0.943–1.034x |
| GOST R 34.10-2012 | — | unavailable | — | — |
| Ed25519 sign | 0.018 ms | 0.034 ms | 1.890x | 1.750–1.920x |
| Ed25519 verify | 0.051 ms | 0.097 ms | 1.910x | 1.890–1.970x |
| Ed448 sign | 0.151 ms | 0.187 ms | 1.240x | 1.240–1.250x |
| Ed448 verify | 0.201 ms | 0.184 ms | 0.930x | 0.910–0.940x |
| ML-DSA-44 sign | 0.482 ms | 0.554 ms | 1.160x | 0.910–1.170x |
| ML-DSA-44 verify | 0.091 ms | 0.117 ms | 1.290x | 1.290–1.300x |
| ML-DSA-65 sign | 0.728 ms | 0.894 ms | 1.200x | 1.120–1.340x |
| ML-DSA-65 verify | 0.152 ms | 0.183 ms | 1.240x | 1.190–1.250x |
| ML-DSA-87 sign | 0.923 ms | 0.985 ms | 1.180x | 1.070–1.190x |
| ML-DSA-87 verify | 0.234 ms | 0.306 ms | 1.300x | 1.280–1.310x |

## OpenSSL-unavailable operations

These rows use the same Clang Release build and three pinned runs of the
internal benchmark. The range is the minimum and maximum observed absolute
value. Binary-field ECDH has no number because the current binary-curve API
implements ECDSA only.

### Hashing, 64 KiB buffer

| Operation | Median | Range |
|---|---:|---:|
| Streebog-256 | 83 MiB/s | 83 MiB/s–84 MiB/s |
| Streebog-512 | 84 MiB/s | 83 MiB/s–84 MiB/s |

### AEAD seal, 64 KiB

| Operation | Median | Range |
|---|---:|---:|
| XChaCha20-Poly1305 | 3802 MiB/s | 3775 MiB/s–3802 MiB/s |

### AEAD seal, 64 B, per record

| Operation | Median | Range |
|---|---:|---:|
| XChaCha20-Poly1305 | 370 ns | 370 ns–375 ns |

### Signatures

| Operation | Median | Range |
|---|---:|---:|
| GOST-256 Test sign | 0.169 ms | 0.169 ms–0.170 ms |
| GOST-256 Test verify | 0.291 ms | 0.285 ms–0.292 ms |
| GOST-256 A sign | 0.170 ms | 0.170 ms–0.171 ms |
| GOST-256 A verify | 0.294 ms | 0.291 ms–0.299 ms |
| GOST-256 B sign | 0.169 ms | 0.169 ms–0.189 ms |
| GOST-256 B verify | 0.291 ms | 0.288 ms–0.291 ms |
| GOST-256 C sign | 0.167 ms | 0.166 ms–0.169 ms |
| GOST-256 C verify | 0.282 ms | 0.282 ms–0.283 ms |
| GOST-256 D sign | 0.169 ms | 0.168 ms–0.179 ms |
| GOST-256 D verify | 0.289 ms | 0.288 ms–0.424 ms |
| GOST-512 Test sign | 0.933 ms | 0.913 ms–1.092 ms |
| GOST-512 Test verify | 1.284 ms | 1.237 ms–1.291 ms |
| GOST-512 A sign | 0.861 ms | 0.861 ms–0.862 ms |
| GOST-512 A verify | 1.190 ms | 1.181 ms–1.265 ms |
| GOST-512 B sign | 0.853 ms | 0.847 ms–0.868 ms |
| GOST-512 B verify | 1.150 ms | 1.139 ms–1.246 ms |
| GOST-512 C sign | 0.928 ms | 0.927 ms–0.929 ms |
| GOST-512 C verify | 1.232 ms | 1.221 ms–1.261 ms |

## Interpretation limits

These numbers describe one compiler, processor, operating system, provider
configuration, and source revision. They are useful for detecting large
regressions and prioritizing work, but they are not universal performance
claims. Short operations and randomized signing or key generation can vary
materially even with processor affinity. Rerun the complete paired inventory
after changes to allocators, dispatch, key or context construction, arithmetic
kernels, or compiler settings.

Timing measurements do not establish constant-time behavior. The security
boundaries and variable-time exceptions remain those documented in the public
headers and [Pitfalls](../../specs/pitfalls.md).
