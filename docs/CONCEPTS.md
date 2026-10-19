# Architecture and concepts

[한국어](CONCEPTS.ko.md)

## Overview

`libcertpp` is a C++17 library, still early-stage but past its initial
scaffolding: a `common` foundation, a `version` module, a `utils` module
(a DJB hash utility, `CHex` hex decoding, `CBase64` base64, `CBigNum` an
arbitrary-precision integer, `CGf2m` a binary-field (GF(2^m)) element, and
`CJson` JSON parsing/serialization),
an `io` layer (spans, a growable array, a resizable working byte buffer
(`CBuffer`), a fixed-size owning one (`COctet`), and a stream
abstraction), an
`asn1` module (tag encode/decode, a TLV decoder/encoder,
sequential reader/writer wrappers, and `CDer`'s arbitrary-precision-
`INTEGER`/`SEQUENCE` DER helpers), a `crypto` module, an `x509` module, and a
`dnssec` module.

`crypto` has: an `IHasher` interface with from-scratch MD4/MD5/SHA-1/SHA-224/
SHA-256/SHA-384/SHA-512/SHA3-256/SHA3-512/SHAKE128/SHAKE256/BLAKE2s/
Streebog-256/Streebog-512 implementations; a pluggable random-generator
interface (`IRng`) with an OS-backed implementation (`CRng`); an
`IAsymmetric` interface with nine concrete implementations
(RSA -- PKCS#1 v1.5 and RSASSA-PSS sign/verify, PKCS#1 v1.5 encrypt/
decrypt; DSA; `CEcdsa`, ECDSA over any of NIST P-192/P-224/P-256/P-384/
P-521, secp256k1, or the 14 Brainpool curves (RFC 5639), plus ECDH key
agreement over the same curves (RFC 5903 / SP 800-56A); `CEcdsa2`, ECDSA
over the 10 NIST binary/Koblitz curves B-163/K-163 .. B-571/K-571;
`Ed25519`/`Ed448`, EdDSA (RFC 8032); `X25519`, Diffie-Hellman key
agreement (RFC 7748); and `CGost3410`, GOST R 34.10-2012 (RFC 7091) over
any of its nine parameter sets; and `CMlDsa`, ML-DSA-44/65/87 signatures
(FIPS 204)); a parallel `IKem` interface with ML-KEM-512/768/1024 (FIPS 203);
an `ISymmetric` interface with five
concrete implementations (`AES`, `ARIA`, `DES`, `TripleDES` -- all CBC,
PKCS#7-padded or unpadded -- and the `ChaCha20` stream cipher); and three
AEADs outside that interface, `CChaCha20Poly1305` (RFC 8439 2.8),
`CXChaCha20Poly1305` (draft-irtf-cfrg-xchacha) and `CAesGcm` (NIST SP
800-38D) -- all from scratch, no third-party dependency.

`x509` parses and builds/self-signs DER-encoded `Certificate`
(`CCert`/`CCertBuilder`) and PKCS#10 `CertificationRequest`
(`CCertRequest`/`CCertRequestBuilder`), and parses/builds `CertificateList`/CRL
(`CCrlReader`/`CCrlWriter`), and OCSP request/response (RFC 6960;
`COcspRequest`/`COcspRequestBuilder`, `COcspResponse`/
`COcspResponseBuilder`), plus ten concrete `IExtension` types under
`x509/exts/` (BasicConstraints, KeyUsage, ExtendedKeyUsage,
SubjectAlternativeName, SubjectKeyIdentifier, AuthorityKeyIdentifier,
CRLDistributionPoints, AuthorityInformationAccess, CertificatePolicies,
NameConstraints). Single-link signature verification exists for all three
(`CCert::verifyBy(issuer)`, `CCrlReader::verifyBy(issuer)`,
`COcspRequest`/`COcspResponse::verifySignature()`). `CCertCollection::buildChain()`
orders certificates by issuer/subject names and `verifyLinks()` checks link
signatures. `CPathValidator` adds explicit trust anchors and typed
diagnostics, and enforces time validity, issuer names, signatures,
BasicConstraints, path length, KeyUsage, ExtendedKeyUsage, supported
NameConstraints, and unknown critical-extension rejection. Revocation and
full certificate-policy processing are explicit unavailable policy
capabilities and are not implied by a successful core result. See
[Extension points and scope](concepts/scope.md#extension-points-and-scope).

The integration surface also includes RFC 9215 GOST 2012 certificate and CSR
key/signature encodings, RFC 9558 DNSSEC algorithm 23, and
`CKemSubjectPublicKeyInfo` for RFC 9935 ML-KEM public-key import/export. Common
hash, signature, and KEM outputs have allocation-owning `COctet` overloads;
`CAlgorithmPolicy` classifies algorithms for new generation without disabling
legacy parsing.

Certificates and their keys can be carried as a container: `x509/chain.hpp`'s
`CCertCollection` holds them with the PKCS#9 attributes that pair them and
orders them by issuer linkage (which, again, is not validation), and
`IChainFormat` reads and writes that collection as a file.
`x509/chain/pfx.hpp` implements PKCS#12/PFX over PBES2 and a `MacData` HMAC.

The public API surface is header-based under
[`include/certpp/`](../include/certpp), re-exported through the umbrella
header [`include/certpp.hpp`](../include/certpp.hpp) — every usable public API
header is included there, so consumers can `#include <certpp.hpp>` alone.
Implementation files live under [`src/`](../src) and mirror the header
they implement (e.g. `include/certpp/version.hpp` <-> `src/version.cpp`).

## Detailed concept pages

- [Project structure](concepts/structure.md)
- [Development model](concepts/development.md)
- [Core and utilities](concepts/foundations.md)
- [I/O and ASN.1](concepts/data-encoding.md)
- [Hashing and symmetric cryptography](concepts/symmetric.md)
- [MAC, KDF, AEAD, and randomness](concepts/protocols.md)
- [Classical asymmetric cryptography](concepts/classical.md)
- [Asymmetric interfaces and modern curves](concepts/asymmetric.md)
- [Post-quantum cryptography internals](concepts/post-quantum.md)
- [Certificates and containers](concepts/certificates.md)
- [Extensions and revocation](concepts/validation.md)
- [Scope, integration, and DNSSEC](concepts/scope.md)
- [Performance](concepts/performance.md)
