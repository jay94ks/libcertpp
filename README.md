# libcertpp

[한국어](README.ko.md)

`libcertpp` is an early-stage, from-scratch C++17 library for X.509
certificate handling, built from the ground up: its own ASN.1/DER codec,
its own big-number and binary-field math, its own hashing/symmetric/
asymmetric cryptography, and an X.509 layer built on top of all of it.
There is no third-party cryptography dependency anywhere in the library
itself (the only vendored dependency, [doctest](https://github.com/doctest/doctest),
is used by the test suite only).

## What's in it

- **`utils`** -- `CBigNum` (arbitrary-precision integer), `CGf2m`
  (binary-field GF(2^m) element), `CHex`, a DJB hash utility.
- **`io`** -- spans, a growable array (`TArray`), a resizable working byte
  buffer (`CBuffer`), a fixed-size owning one for finished results
  (`COctet`), base64 (`CBase64`), and a stream abstraction (`IStream`).
- **`asn1`** -- tag encode/decode, a TLV decoder/encoder, sequential
  reader/writer wrappers, and `CDer`'s arbitrary-precision `INTEGER`/
  `SEQUENCE` DER helpers.
- **`crypto`**:
  - Hashing: MD5, SHA-1, SHA-224/256/384/512, SHA3-256, SHA3-512,
    SHAKE128, SHAKE256 -- all from scratch.
  - A CSPRNG (`CRng`), backed directly by the OS (`BCryptGenRandom` on
    Windows, `getrandom(2)`/`/dev/urandom` on Linux, `/dev/urandom` on
    other POSIX platforms).
  - Asymmetric algorithms: RSA (PKCS#1 v1.5 and RSASSA-PSS sign/verify,
    PKCS#1 v1.5 encrypt/decrypt), DSA, ECDSA over NIST P-192 .. P-521,
    secp256k1, and the 14 Brainpool curves, ECDSA over the 10 NIST binary/
    Koblitz curves, Ed25519/Ed448 (EdDSA, RFC 8032), and X25519
    (Diffie-Hellman key agreement, RFC 7748).
  - Symmetric algorithms: AES, DES, TripleDES (CBC/PKCS#7), and the
    ChaCha20 stream cipher.
  - Runtime-detected hardware acceleration where available (x86-64):
    ADX/BMI2 for big-number math, PCLMULQDQ for binary-field math, SHA-NI
    for SHA-1/SHA-256, AES-NI for AES -- each with a portable fallback and
    a CMake option to force the portable path.
  - Post-quantum cryptography: ML-KEM (FIPS 203) for all three parameter
    sets -- `CMlKem` in `crypto/pq/mlkem.hpp`, validated against NIST's
    ACVP vectors. The `IKem`/`IKemContext` interface it will be exposed
    through is drafted but not yet wired up, so ML-KEM is reachable only
    through its own raw-span API for now. See
    [`docs/pqc-review.md`](docs/pqc-review.md) for the plan and its state.
- **`x509`** -- parses and builds/self-signs a DER X.509 `Certificate`
  (`CCert`/`CCertBuilder`), parses/builds a `CertificateList`/CRL, and
  parses/builds OCSP request/response (RFC 6960), including ten concrete
  extension types (BasicConstraints, KeyUsage, ExtendedKeyUsage,
  SubjectAlternativeName, SubjectKeyIdentifier, AuthorityKeyIdentifier,
  CRLDistributionPoints, AuthorityInformationAccess, CertificatePolicies,
  NameConstraints).

See [`docs/architecture.md`](docs/architecture.md) for the full module
breakdown, file by file.

## Building

Requires CMake 3.15+ and a C++17 compiler.

```sh
cmake -S . -B build
cmake --build build --config Debug
```

Builds a shared library by default; pass `-DCERTPP_BUILD_SHARED=OFF` to
build static instead. See [`docs/build.md`](docs/build.md) for the full
CMake option list (hardware-acceleration toggles, RNG fallback, install
layout).

## Testing

Tests use [doctest](https://github.com/doctest/doctest) and are registered
with CTest automatically:

```sh
ctest --test-dir build -C Debug --output-on-failure
```

## Examples

[`examples/`](examples/) has a small CA-hierarchy walkthrough (issue a
root, an intermediate, a leaf, then sign/verify data with the leaf's key)
-- see [`examples/README.md`](examples/README.md).

## Documentation

- [`docs/architecture.md`](docs/architecture.md) -- module responsibilities
  and how the pieces fit together.
- [`docs/coding-conventions.md`](docs/coding-conventions.md) -- naming,
  header-guard, formatting, and doc-comment conventions.
- [`docs/build.md`](docs/build.md) -- full CMake build/install reference.
- [`docs/changelog.md`](docs/changelog.md) -- chronological record of what
  was built and fixed, covering the work that predates this repository's
  git history.
- [`docs/pqc-review.md`](docs/pqc-review.md) -- post-quantum cryptography
  review and roadmap.

## Status

Early-stage and under active development -- interfaces may still change.
Not yet audited by a third party; use accordingly.
