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
4-core i7-11370H @ 3.30 GHz: MSVC 19.36 (VS 2022 17.6) on Windows, and GCC 13.3
on Ubuntu 24.04 **under WSL2**. Each figure is the fastest of three batches of
20 iterations, best of three runs, and the two were run one after the other
rather than at once so neither could end up measuring the other's compiler.
The run-to-run spread is 20--30%, so nothing smaller than that is a result.
Bold is the fastest entry in its column.

| Signature | MSVC sign | MSVC verify | GCC sign | GCC verify |
|---|---|---|---|---|
| Ed25519 | **0.20 ms** | **0.87 ms** | **0.16 ms** | **0.71 ms** |
| ML-DSA-65 | 1.67 ms | 0.56 ms | 1.56 ms | 0.45 ms |
| ECDSA P-256 | 0.92 ms | 2.44 ms | 0.86 ms | 2.31 ms |
| ECDSA P-384 | 2.10 ms | 5.52 ms | 1.99 ms | 5.50 ms |
| ECDSA P-521 | 4.64 ms | 13.4 ms | 4.50 ms | 12.4 ms |
| Ed448 | 2.47 ms | 10.6 ms | 2.46 ms | 10.4 ms |
| RSA-2048 | 8.06 ms | 0.145 ms | 19.1 ms | 0.392 ms |

| Key agreement / KEM | MSVC keygen | GCC keygen | MSVC operation | GCC operation |
|---|---|---|---|---|
| X25519 | 0.33 ms | 0.280 ms | 0.164 ms derive | 0.140 ms derive |
| ML-KEM-768 | — | — | 0.169 / 0.185 ms encap/decap | 0.117 / 0.130 ms encap/decap |
| ECDH P-256 | 3.15 ms | 2.98 ms | 1.40 ms derive | 1.39 ms derive |

Hashing and AEAD sealing, 64 KiB:

| Hash | MSVC | GCC |
|---|---|---|
| SHA-256 | **1534 MiB/s** | **1552 MiB/s** |
| MD5 | **593 MiB/s** | 455 MiB/s |
| BLAKE2s | 412 MiB/s | 401 MiB/s |
| SHA-512 | 353 MiB/s | 364 MiB/s |
| SHA3-256 | 108 MiB/s | 308 MiB/s |
| Streebog-256 | 75 MiB/s | 106 MiB/s |

| AEAD seal, 64 KiB | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305 | 578 MiB/s | **650 MiB/s** |
| XChaCha20-Poly1305 | 577 MiB/s | 648 MiB/s |
| AES-256-GCM | 370 MiB/s | 475 MiB/s |

Two caveats bound how far the GCC column travels. It was measured **under
WSL2**, which is a VM and not bare metal: the harness is single-threaded
CPU-bound cryptography, so the hypervisor's share of each measurement ought to
be small, but that is an argument that it ought to be and not a measurement
showing that it is. Read the column as "this toolchain in this setup" rather
than as Linux performance in general. And "both Release" is not "the same
settings": CMake's Release defaults are `/O2` for MSVC and `-O3` for GCC, so
what is compared here is toolchain *plus* optimization level, not toolchain
alone.

The MSVC column replaces an earlier set published for the same CPU, whose own
text described it as measured under load. Every row here came in equal or
faster, most by 10--20%; the largest movement is ECDSA P-256 verify, 3.53 ms
to 2.44 ms, just outside the spread quoted above -- which is why the conditions
are stated here rather than left implied.

Five things in there are worth explaining, because each is a property of the
implementation rather than noise:

- **Ed25519 is an order of magnitude off an optimized implementation** (which
  verifies in 50--100 µs), and everything else is further off than that. It is
  the one curve on a dedicated constant-time field (`Fe25519`); the prime
  curves still run on the general-purpose `CBigNum` with Montgomery reduction.
- **Signing beats verification on the prime curves** — P-256 signs in 0.92 ms
  and verifies in 2.44 ms — because signing multiplies the *fixed* base point
  and uses a precomputed window table, while verification multiplies a
  caller-supplied point and cannot.
- **RSA-2048 is lopsided by design**: `e = 65537` makes verification three
  multiplies, while signing is a full CRT exponentiation on a schoolbook
  big-number backend.
- **AES-256-GCM sits below ChaCha20-Poly1305 despite AES-NI**, because GHASH
  rather than the cipher is the bottleneck and an AEAD composes as
  `1/total = 1/cipher + 1/mac`. Both toolchains reproduce this, though GCC's
  margin over ChaCha20-Poly1305 is the wider of the two.
- **The two toolchains disagree by up to 2.4x, and RSA is where it matters.**
  GCC is equal or faster on almost everything — SHA3-256 by 2.8x, Streebog by
  42%, ML-KEM by 30%, AES-256-GCM by 28% — but RSA-2048 signing takes 19.1 ms
  against MSVC's 8.06 ms, and verification is 2.7x slower too. Note what this
  is *not*: both toolchains reach `CBigNum::mulAccelerated()`, so GCC is not
  falling back to the portable multiply, and the prime curves running *faster*
  on GCC says the backend is not slow in general. RSA is where the backend's
  cost dominates enough for the difference to show, and why the two codegens
  differ that much there is not diagnosed. MD5 is the other direction, 23%
  down. Both are open work in [`docs/roadmap.md`](docs/roadmap.md).

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
