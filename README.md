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
`organizationIdentifier` and `domainComponent`.

**Hashing** — MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512,
SHAKE128/256, BLAKE2s (RFC 7693), GOST R 34.11-2012 "Streebog" (RFC 6986) at
both digest lengths.

**MACs and KDFs** — HMAC (RFC 2104) over any of those, HKDF (RFC 5869),
Poly1305 (RFC 8439), BLAKE2s's native keyed MAC, SipHash-2-4 (RFC 9018).

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
- [`examples/`](examples/) — a compiled CA-hierarchy walkthrough.

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
