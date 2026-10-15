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
64 KiB records versus 494.8 MiB/s with both AVX-512 tiers disabled. Test
processes now route assertions and crashes to console diagnostics without
Windows error dialogs. Automated CI and the platform
matrix intentionally remain in [the roadmap](PLANS.md).

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
