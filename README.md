# libcertpp

[한국어](README.ko.md)

![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![CMake 3.15+](https://img.shields.io/badge/CMake-3.15%2B-064F8C)
![Windows | Linux](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-success)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15193/badge)](https://www.bestpractices.dev/projects/15193)

**X.509, ASN.1 and cryptography in C++17, implemented from scratch.**

Its own DER codec, its own big-number and binary-field arithmetic, its own
hashes, symmetric ciphers, AEADs, signature schemes and post-quantum
algorithms, and an X.509 layer on top of all of it. There is no third-party
cryptography anywhere in the library — the only vendored dependency,
[doctest](https://github.com/doctest/doctest), is used by the test suite and
is not linked into `certpp` itself.

```cpp
#include <certpp.hpp>

using namespace certpp;
using namespace certpp::x509;

// Parse a certificate, read it, and check who signed it.
CCert leaf;
if (leaf.importDer(leafDer) == ERET_OK) {
    CName cn;
    leaf.subject().tryGet(ENAME_CN, cn);

    // One link: this checks the signature, and nothing else.
    const bool signedByIssuer = (leaf.verifyBy(issuer) == ERET_OK);
}
```

```cpp
using namespace certpp::crypto;

// Encrypt a record in place, authenticated. `out` may alias `in`.
CChaCha20Poly1305 aead;
aead.reset(key);

uint8_t tag[16];
aead.seal(nonce, aad,
          SReadOnlyByteSpan(record, length),
          SByteSpan(record, length),
          SByteSpan(tag, sizeof(tag)));
```

More in [`specs/recipes.md`](specs/recipes.md) and, compiled as part of the
build, [`examples/`](examples/).

## What's in it

**Certificates** — parse and build DER/PEM `Certificate` (`CCert`,
`CCertBuilder`), CRLs, and OCSP request/response (RFC 6960), with ten concrete
extension types. Signature verification covers PKCS#1 v1.5, RSASSA-PSS
(RFC 4055, reading the real parameters rather than assuming the DER defaults),
ECDSA, EdDSA and ML-DSA. Fourteen X.520 name attribute types, including
`organizationIdentifier` and `domainComponent`. PKCS#10 certification requests
(`CCertRequest`, `CCertRequestBuilder`, RFC 2986) in both directions, including
the PKCS#9 `extensionRequest` attribute, with the self-signature checked at
import rather than merely offered as a method to call.

**Chains and containers** — `CCertCollection` holds a set of certificates and
orders them by who issued whom (`buildChain()`), and `verifyLinks()` checks
each link's signature. Two container formats over a collection: PEM, pairing
private keys to their certificates cryptographically rather than by position,
and PKCS#12/PFX (RFC 7292) over PBES2/AES-256-CBC with the MAC verified before
anything is decrypted. **There is no path validation**: validity periods,
`basicConstraints`, `keyUsage`, name constraints, policies and revocation are
not checked, and nothing here decides whether a root is one you trust. An
ordered chain out of this library is a validator's input, not its verdict.

**Hashing** — MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512,
SHAKE128/256, BLAKE2s (RFC 7693), GOST R 34.11-2012 "Streebog" (RFC 6986) at
both digest lengths.

**MACs and KDFs** — HMAC (RFC 2104) over any of those, HKDF (RFC 5869),
PBKDF2 (RFC 8018) for the password-based case, Poly1305 (RFC 8439), BLAKE2s's
native keyed MAC, SipHash-2-4 (RFC 9018).

**Symmetric and AEAD** — AES, DES, TripleDES (CBC, PKCS#7-padded or unpadded),
ChaCha20. Three AEADs: ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305
(192-bit nonce), AES-GCM (SP 800-38D). All three work in place, allocate
nothing per record for a reused context, and verify the tag in constant time
before writing any plaintext.

**Asymmetric** — RSA (PKCS#1 v1.5 and RSASSA-PSS sign/verify, v1.5
encrypt/decrypt), DSA, ECDSA over NIST P-192…P-521, secp256k1 and the 14
Brainpool curves, ECDSA over the 10 NIST binary/Koblitz curves, Ed25519/Ed448
(RFC 8032), X25519 (RFC 7748), ECDH over the prime curves (RFC 5903), and
GOST R 34.10-2012 over nine named parameter sets.

**Post-quantum** — ML-KEM (FIPS 203) and ML-DSA (FIPS 204), all parameter sets,
validated against NIST's ACVP vectors. A real third-party ML-DSA certificate
verifies end to end in the test suite.

**DNSSEC** — DNSKEY/RRSIG/DS conversion (RFC 4034): canonical wire-format
names, RDATA, key tags, DS digests, and the re-encoding between DNSSEC's wire
formats and this library's keys and signatures.

**JSON and BSON** — parse and serialize JSON values (`CJson`, `parseJson()`),
and encode/decode BSON documents, including nested arrays/objects and escaped
Unicode strings. BSON maps integer values to the library's `double` number
type and rejects BSON types without a JSON equivalent. Disable the utility at
configure time with `-DCERTPP_WITHOUT_JSON=ON`.

**Hardware acceleration** — ADX/BMI2 for big-number arithmetic, PCLMULQDQ for
binary fields and GHASH, SHA-NI, AES-NI, and a four-block SSE2 ChaCha20
keystream. Each has a portable fallback expected to produce byte-identical
results, a CMake switch to force it, and a runtime CPUID check where the
instruction set is not baseline.

[`docs/architecture.md`](docs/architecture.md) has the full breakdown, file by
file.

## Building

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Shared library by default; `-DCERTPP_BUILD_SHARED=OFF` for static. Requires
CMake 3.15+ and a C++17 compiler; built with MSVC and GCC.
[`docs/build.md`](docs/build.md) has the full option list.

## Using it from CMake

```sh
cmake --install build --prefix <prefix>
```

```cmake
find_package(certpp REQUIRED)
target_link_libraries(myapp PRIVATE certpp::certpp)
```

Add `-DCMAKE_PREFIX_PATH=<prefix>` if the prefix is not already searched. Note
that a *static* `certpp` must be consumed with a matching MSVC runtime.

## Documentation

**Using the library:**

- [`specs/`](specs/) — reference material aimed at agents and newcomers:
  an [API map](specs/api-map.md), [recipes](specs/recipes.md), and
  [pitfalls](specs/pitfalls.md) — the ways this library can be called wrongly
  and still appear to work.
- [`examples/`](examples/) — a compiled CA-hierarchy walkthrough, plus a
  compiled example for every public type.
- The [**wiki**](../../wiki) — one reference page per public class, struct and
  enum, generated from the headers' own doc comments, each stamped with the
  commit it came from. Also the integration guide, FAQ and troubleshooting.

**Working on the library:**

- [`docs/architecture.md`](docs/architecture.md) — module responsibilities, file by file.
- [`docs/coding-conventions.md`](docs/coding-conventions.md) — naming, guards, formatting, buffer handling.
- [`docs/build.md`](docs/build.md) — full CMake build/install reference.
- [`docs/changelog.md`](docs/changelog.md) — why things are the way they are, and the bugs found and fixed.
- [`docs/pqc-review.md`](docs/pqc-review.md) — post-quantum review and phasing.
- [`docs/roadmap.md`](docs/roadmap.md) — what is asked for and not built yet.

Every document has a Korean translation beside it, named `<name>.ko.md`.

## Testing

Every algorithm is checked against published vectors rather than only against
itself — NIST ACVP for ML-KEM and ML-DSA, the relevant RFC's own test vectors
elsewhere, and real commercially-issued certificates on disk under
`tests/x509/certs/`. New units additionally get a *negative control*: an
invariant is deliberately broken to confirm the tests actually fail, because a
suite that passes against broken code measures nothing. See
[`docs/changelog.md`](docs/changelog.md) for cases where that caught something
the published vectors could not.

## Performance

Measured by [`examples/05_benchmark.cpp`](examples/05_benchmark.cpp), so these
are reproducible rather than claimed: build it and run it on your own hardware.
Two toolchains, both Release, both measured in one session on a single
4-core i7-11370H (3.30 GHz base, around 3.92 GHz sustained under this load):
MSVC 19.36 (VS 2022 17.6) on Windows, and GCC 13.3
on Ubuntu 24.04 **under WSL2**. Each figure is the fastest of three batches of
20 iterations, best of three runs, and the two were run one after the other
rather than at once so neither could end up measuring the other's compiler.
The run-to-run spread is 20--30%, so nothing smaller than that is a result.
Bold is the faster entry in its row.

The tables cover every algorithm the library implements: 14 hashers, 8
block-cipher configurations, 3 KEM parameter sets, and 34 signature and
key-agreement schemes. No row in the harness's own output reports
"(unavailable)", which was the point of covering all of them.

GF(2^m) curves appear under signatures but not under key agreement because
that is what they implement: they do ECDSA and not ECDH.

#### Signatures

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

#### Key agreement and KEMs

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

#### Hashing, 64 KiB

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

#### Block ciphers, CBC, 64 KiB

| | MSVC | GCC |
|---|---|---|
| AES-128-CBC | 735.9 MiB/s | **843.9 MiB/s** |
| AES-192-CBC | 680.8 MiB/s | **760.6 MiB/s** |
| AES-256-CBC | 644.0 MiB/s | **727.1 MiB/s** |
| DES-CBC | **9.1 MiB/s** | 5.1 MiB/s |
| 3DES-CBC | **3.0 MiB/s** | 1.7 MiB/s |
| ARIA-128-CBC | **58.1 MiB/s** | 38.3 MiB/s |
| ARIA-192-CBC | **51.8 MiB/s** | 33.1 MiB/s |
| ARIA-256-CBC | **45.3 MiB/s** | 28.4 MiB/s |

#### AEAD seal, 64 KiB

| | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305 | 751.0 MiB/s | **841.2 MiB/s** |
| XChaCha20-Poly1305 | 749.2 MiB/s | **841.5 MiB/s** |
| AES-256-GCM | 371.6 MiB/s | **465.3 MiB/s** |

#### AEAD seal, 64 B, per record

| | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305 | **410 ns** | 338 ns |
| XChaCha20-Poly1305 | **545 ns** | 446 ns |
| AES-256-GCM | 220 ns | **234 ns** |

### Two cross-toolchain gaps that P1 and P7 did not close

RSA and MD5 were the two documented gaps, and both are gone: RSA-2048 signing
took 8.06 ms against 19.1 ms until `CMontgomery` was routed underneath it
(now 5.62 against 5.25 ms), and MD5's 23% deficit closed with the P7 round
unrolling (now **719.7 MiB/s** on GCC against 571.7 on MSVC -- GCC now leads).
Covering every algorithm surfaced two more that were never written down:

- **DSA-2048 is 2.7x slower to sign on GCC** -- 7.29 ms against 2.70 ms, and
  18.1 ms against 6.6 ms to verify. That is a wider gap than RSA's ever was,
  and it is the only remaining one large enough to read as a codegen defect
  rather than as noise. The backend is the same `CBigNum` RSA uses, so the
  cause is presumably the same shape of thing `CMontgomery` fixed there --
  but the profile has not been taken, so that is a hypothesis and nothing more.
- **Every GF(2^m) curve is 1.2--2.1x slower on GCC.** B-571 verify is 19.9 ms
  against 7.6 ms. Ten curves, all moving the same way, which argues for a
  shared cause in `CGf2m` rather than ten coincidences.

Both belong in [`docs/roadmap.md`](docs/roadmap.md) as items, not in a README
footnote; they are recorded here so the measurements are not lost, and neither
has been investigated.

### What the slower rows are telling you

- **DES and 3DES are 1000x slower than AES**, which is the cipher itself being
  slow, not the library: 3DES runs three DES operations per block and DES has
  no acceleration on any x86.
- **ARIA runs 20--25x slower than AES**, for the opposite reason: AES-NI is a
  hardware instruction and ARIA has none, so the portable rounds are the whole
  implementation. There is nothing to remove without new hardware.
- **Signing beats verification on the prime curves** -- P-256 signs in 0.91 ms
  and verifies in 2.43 ms -- because signing multiplies the *fixed* base point
  and uses a precomputed window table, while verification multiplies a
  caller-supplied point and cannot.
- **RSA-2048 is lopsided by design**: `e = 65537` makes verification three
  multiplies, while signing is a full CRT exponentiation.
- **AES-256-GCM sits below ChaCha20-Poly1305 despite AES-NI**, because GHASH
  rather than the cipher is the bottleneck and an AEAD composes as
  `1/total = 1/cipher + 1/mac`.
- **The 64 B AEAD rows invert the 64 KiB ones.** AES-256-GCM is *faster* per
  record (220 ns against 410 ns) and *slower* in bulk (371 against 751 MiB/s),
  because AES-GCM encrypts one block where ChaCha20 encrypts two and a small
  record cannot amortize the difference. A bulk sender and a per-record caller
  are looking at different winners.

Nanosecond figures are the noisiest in the section -- treat a gap under ~30%
between two AEADs as unsettled.

### WSL2, and what the GCC column is not

The GCC figures were measured **under WSL2** -- a real Linux kernel inside a
VM, not a bare-metal Linux install on this CPU -- and that warrants a record of
its own rather than a clause in the conditions above. The harness is
single-threaded, CPU-bound cryptography, so the hypervisor's share of each
measurement ought to be small. But that is an argument that it ought to be, not
a measurement showing that it is: this run did not quantify the overhead in
either direction.

The column therefore reads as *this toolchain in this setup*, not as Linux
performance in general. That matters most for the DSA and GF(2^m) gaps above,
which are the only differences left large enough to read as compiler defects
and therefore exactly the ones that should not be called that before being
re-measured on bare metal.

Two smaller limits apply to both columns. "Release" is not one setting:
CMake's defaults are `/O2` for MSVC and `-O3` for GCC, so toolchain and
optimization level are varied together.

[`docs/roadmap.md`](docs/roadmap.md) has the targets, what is already done, and
what each remaining gap actually needs.

## Status

Early-stage and under active development; interfaces may still change. **Not
audited by a third party.** Parts are constant-time by construction and say so
in their doc comments; parts explicitly are not, including `CBigNum` and
therefore prime-curve ECDSA/ECDH. [`specs/pitfalls.md`](specs/pitfalls.md) is
the honest list. Weigh that before using it where timing is an adversary's
input.

Licensed under the [MIT License](LICENSE). The vendored
[doctest](third-party/doctest/) is MIT-licensed too and is used only by the
test suite; `certpp` itself links nothing third-party.
