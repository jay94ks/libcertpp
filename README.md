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
  - Hashing: MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256, SHA3-512,
    SHAKE128, SHAKE256, BLAKE2s (RFC 7693), and GOST R 34.11-2012
    ("Streebog", RFC 6986) at both digest lengths -- all from scratch.
  - MACs and key derivation: HMAC (RFC 2104) over any of those hashes,
    HKDF (RFC 5869), Poly1305 (RFC 8439), BLAKE2s's native keyed MAC, and
    SipHash-2-4 (RFC 9018's DNS server-cookie PRF).
  - A CSPRNG (`CRng`), backed directly by the OS (`BCryptGenRandom` on
    Windows, `getrandom(2)`/`/dev/urandom` on Linux, `/dev/urandom` on
    other POSIX platforms).
  - Asymmetric algorithms: RSA (PKCS#1 v1.5 and RSASSA-PSS sign/verify,
    PKCS#1 v1.5 encrypt/decrypt), DSA, ECDSA over NIST P-192 .. P-521,
    secp256k1, and the 14 Brainpool curves, ECDSA over the 10 NIST binary/
    Koblitz curves, Ed25519/Ed448 (EdDSA, RFC 8032), X25519
    (Diffie-Hellman key agreement, RFC 7748), ECDH over the prime curves
    (RFC 5903), and GOST R 34.10-2012 (RFC 7091) over its nine named
    parameter sets.
  - Symmetric algorithms: AES, DES, TripleDES (CBC, PKCS#7-padded or
    unpadded), and the ChaCha20 stream cipher.
  - AEADs: ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305
    (draft-irtf-cfrg-xchacha, with its 192-bit nonce), and AES-GCM
    (NIST SP 800-38D). All three operate in place -- the output may alias
    the input -- allocate nothing per call for a reused context, and
    compare tags in constant time without writing plaintext before the tag
    verifies.
  - Hardware acceleration where available (x86-64), each with a portable
    fallback and a CMake option to force it: ADX/BMI2 for big-number math,
    PCLMULQDQ for binary-field math and GHASH, SHA-NI for SHA-1/SHA-256,
    AES-NI for AES, and a four-block SSE2 ChaCha20 keystream. All but the
    last are chosen by a runtime CPUID check; SSE2 needs none, being part
    of the x86-64 ABI.
  - Post-quantum cryptography: ML-KEM (FIPS 203) for all three parameter
    sets, validated against NIST's ACVP vectors -- reachable either as
    `IKem::builtIn(EKEM_MLKEM768)` like every other algorithm here, or as
    the raw-span `CMlKem` (which also exposes K-PKE and the samplers). See
    [`docs/pqc-review.md`](docs/pqc-review.md) for what is planned next.
- **`x509`** -- parses and builds/self-signs a DER X.509 `Certificate`
  (`CCert`/`CCertBuilder`), parses/builds a `CertificateList`/CRL, and
  parses/builds OCSP request/response (RFC 6960), including ten concrete
  extension types (BasicConstraints, KeyUsage, ExtendedKeyUsage,
  SubjectAlternativeName, SubjectKeyIdentifier, AuthorityKeyIdentifier,
  CRLDistributionPoints, AuthorityInformationAccess, CertificatePolicies,
  NameConstraints).
  Certificate signatures verify for PKCS#1 v1.5 and for RSASSA-PSS
  (RFC 4055), reading the hash, MGF1 hash and salt length out of the
  `AlgorithmIdentifier`'s parameters rather than assuming the DEFAULTs --
  and failing closed where a parameter combination is encodable but
  unsupported, since approximating one rejects every valid signature in a
  way a caller cannot tell from a forgery. Distinguished names cover
  fourteen X.520 attribute types, including the `organizationIdentifier`
  that EU-regulated certificates carry and `domainComponent`.
- **`dnssec`** -- DNSKEY/RRSIG/DS conversion (RFC 4034): canonical
  wire-format names, the RDATA of each record, the Appendix B key tag, the
  DS digest, and the re-encoding between DNSSEC's wire formats and this
  library's keys and signatures (RFC 3110/5702 for RSA, 6605 for ECDSA,
  8080 for EdDSA). DNSSEC reuses none of X.509's encodings, which is why
  this is its own module rather than a corner of `x509`.

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
- [`docs/roadmap.md`](docs/roadmap.md) -- what has been asked for and is
  not implemented yet, plus the outstanding constant-time and performance
  work.

Every document has a Korean translation beside it, named `<name>.ko.md`.

## Status

Early-stage and under active development -- interfaces may still change.
Not yet audited by a third party; use accordingly.
