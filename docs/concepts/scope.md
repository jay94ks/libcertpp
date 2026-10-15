# Scope, integration, and DNSSEC

[한국어](scope.ko.md)

## Extension points and scope

← [Concepts](../CONCEPTS.md)

`third-party/` now vendors its first dependency: `doctest` (single header,
under `third-party/doctest/`), used only by `tests/`. Its
`third-party/CMakeLists.txt` exposes each vendored dependency as its own
CMake target (`doctest` today); the root `CMakeLists.txt` only
`add_subdirectory(third-party)`s when `CERTPP_BUILD_TESTS=ON`, since
nothing outside `tests/` needs it. Everything the library itself does is
implemented from scratch and needs no dependency at all: the hashers,
the symmetric ciphers, the asymmetric algorithms, and the big-number and
binary-field arithmetic under them. There is consequently no non-test
dependency yet and no concrete candidate for one; if a future piece of work
ever genuinely needs one, it follows the same pattern -- vendor it under its
own `third-party/<name>/` directory and add a matching target in
`third-party/CMakeLists.txt`, linked from `certpp` itself rather than gated
behind `CERTPP_BUILD_TESTS`.

The concrete `IAsymmetric` implementations -- RSA, DSA, ECDSA over the prime,
Brainpool, and binary/Koblitz curves, Ed25519, Ed448, X25519, GOST R 34.10-2012,
and ML-DSA -- live under `include/certpp/crypto/asyms/` and `src/crypto/asyms/`,
mirroring how the concrete `IHasher` implementations
live under `crypto/hashers/` rather than next to `hasher.hpp` itself: the
singular `asym.hpp`/`hasher.hpp` file defines the interface, the plural
`asyms/`/`hashers/` directory holds one file per concrete algorithm. Tests
for a new `asyms/` implementation follow the same mirrored path under
`tests/crypto/asyms/`, exactly as `tests/crypto/hashers/` does today.
`IAsymmetric::builtIn()` (`src/crypto/asym.cpp`) dispatches each
`EAsymmetrics` value to its concrete class; a new algorithm adds one
`case` there, and its enumerator goes **immediately before `EASYM_MAX`,
never inserted in the middle**: the enum crosses an ABI boundary (this
library ships as a shared object and is consumed as an installed package),
so renumbering it leaves a caller compiled against the old header silently
selecting a different algorithm, with nothing to diagnose it. Then check
every exhaustive switch over the enum, and `CCert`'s `KEY_ALGOS`/`SIG_ALGOS`
tables and `signsMessageDirectly()` if the algorithm appears in a
certificate. RSA's key/signature DER encoding, and every future `asyms/`
implementation's, goes through `asn1::CDer` (`asn1/der.hpp`) for the
arbitrary-precision `INTEGER`s `CEncoder`/`CDecoder` don't handle -- see
its own doc comment. A future genuinely non-library-providable dependency
(there isn't one yet: RSA needed only `CBigNum`, itself built from scratch)
would follow the vendor-and-expose-a-target pattern above, instead.

`x509/` both parses and generates: `CCert`/`CCertBuilder` read and build
(and sign) a `Certificate`, `CCrlReader`/`CCrlWriter` a `CertificateList`,
`COcspRequest`/`COcspResponse` plus their builders an OCSP exchange, and
`CCertRequest`/`CCertRequestBuilder` a PKCS#10 `CertificationRequest`, all
ten extensions have a parse/build pair, and PEM as well as DER is handled
(`ECertFormat`, `importPem()`/`exportPem()`, both of which delegate to
`CPemChainFormat` -- see `x509/chain/pem.hpp` below). A new extension type follows
`x509/exts/`'s established shape (a concrete `IExtension` subclass with its
own `OID`, added to `ext.cpp`'s dispatch table, plus the matching
`IExtensionBuilder`) and, if it needs to hold a GeneralName-shaped or
list-of-value-object-shaped field, reuses
`x509/generalname.hpp`/`access.hpp`/`policy.hpp` rather than redefining
those shapes locally.

Single-link signature verification is in place: `CCert::verifyBy(issuer)`,
`CCrlReader::verifyBy(issuer)`, `CCertRequest::verify()` and OCSP's own
`verifySignature()` each answer "did this key sign this?" against the original
signed bytes (`CCert::tbsCertificate()`/`CCrlReader::tbsCertList()`/
`CCertRequest::certificationRequestInfo()` expose those bytes for a caller
that wants to do it by hand). `CCertCollection::buildChain()` orders a set by
issuer/subject names and `verifyLinks()` applies those single-link checks.
`CPathValidator` is the policy-aware entry point: it builds a leaf-first path
to an explicit `CTrustStore`, then checks validity windows, signatures,
`BasicConstraints`, `KeyUsage`, an optional EKU, supported `NameConstraints`,
path length, and unknown critical extensions. Its diagnostic result identifies
both the reason and the certificate index. Revocation and RFC 5280 policy-tree
processing are not claimed; requesting either returns an explicit unavailable
status. On the CA side of PKCS#10, `CCertBuilder::subjectFrom()` hands over a
verified request's subject and key, while deciding whether that name and the
requested extensions should be certified remains application policy.

## Umbrella header and test integration

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`certpp.hpp`** is the single include point for consumers; as new public
  headers are added under `include/certpp/`, add their `#include` here. The
  optional `utils/json.hpp` include is guarded by `CERTPP_WITHOUT_JSON`, which
  CMake propagates to consumers when the JSON utility is disabled. The empty
  compatibility placeholder `io/base64.hpp` is not included (`CBase64` lives
  in `utils/base64.hpp`), and `arch.hpp` is an implementation feature-gate
  header rather than a consumer API.
- **`tests/`** holds every test case, built via `CERTPP_BUILD_TESTS`
  (default `ON`) as one executable per source file and registered with
  CTest. See [RULES.md](../rules/maintenance.md#tests) for the
  file-layout/naming convention and [BUILDING.md](../building/verification.md#tests) for how to
  build and run them; both cover the vendored `doctest` framework these
  files use.

## DNSSEC

← [Modules](../CONCEPTS.md#detailed-concept-pages)

#### `dnssec`

A separate module rather than part of `x509`, because DNSSEC shares none of
X.509's encodings. Where a certificate carries a public key as a
`SubjectPublicKeyInfo` and an ECDSA signature as a DER `SEQUENCE { r, s }`,
DNSSEC writes the bare key material and the bare concatenation `r | s`. So a
DNSKEY cannot be handed to `IAsymmetric::createPublicKey()` and an RRSIG
signature cannot be handed to `verify()`; something has to re-encode in
between, and that is the whole purpose of this module.

- **`dnssec/name.hpp` / `src/dnssec/name.cpp`** define `CDnsName`.
  `toWire()` always folds ASCII uppercase to lowercase, and the API
  deliberately gives the caller no choice about it: a DS digest is taken over
  the owner name followed by the DNSKEY RDATA, so a name reaching the digest
  unfolded produces a DS that disagrees with every published one, and an
  option to skip the folding would only make that reachable by accident.
  Compression pointers (RFC 1035 4.1.4) are rejected rather than resolved,
  since DNSSEC forbids them in signed names and a name carrying one cannot be
  canonicalised without the rest of the message. `fromWirePrefix()` exists for
  RRSIG RDATA, where the signer's name is followed immediately by the
  signature with nothing to separate them.
- **`dnssec/records.hpp` / `src/dnssec/records.cpp`** define `SDnskey`,
  `SDsRecord` and `SRrsig`. The key tag is derived on demand rather than
  stored, because it is a checksum over the whole RDATA rather than an
  identifier: holding it as a field would let it disagree with the key it
  names. `SRrsig::toSignedPrefix()` emits the RDATA with the signature field
  omitted, which is the first thing fed to the hash (RFC 4034 3.1.8.1);
  assembling the canonical RRset that follows it is left to the caller, since
  this library does not model DNS RRsets. The public key stays in its DNS
  encoding here and is converted only by `CDnssecKeys`, because the two can
  fail independently -- RDATA can be perfectly well-formed and still hold a
  key for an algorithm this library has no implementation of, while the key
  tag and the DS digest are computed over the raw RDATA either way.
- **`dnssec/keys.hpp` / `src/dnssec/keys.cpp`** define `CDnssecKeys`, which is
  the re-encoding layer. RSA (RFC 3110) writes an exponent length, the
  exponent, then the modulus, where this library wants a DER
  `SEQUENCE { INTEGER modulus, INTEGER exponent }` -- note that the two
  operands even appear in opposite order. ECDSA (RFC 6605) writes `x | y`,
  which is the SEC1 uncompressed point less its `0x04` prefix. GOST 2012
  (RFC 9558 algorithm 23) fixes the 256-bit parameter set A and carries the
  little-endian `x | y` key and `r | s` signature forms directly. EdDSA
  (RFC 8080) is already in the right form, and is handled by an explicit case
  rather than a default, so that an algorithm nobody has implemented is
  rejected instead of silently treated as raw. Signatures go the same way,
  and the ECDSA direction is the one that has to be careful: a DER `INTEGER`
  carries no leading zero octets, so writing `r` and `s` back out without
  left-padding each to the curve's field size would shift `s` by however many
  octets `r` was short, and RFC 6605 2 requires a fixed width.

`fromPublicKey()` has to be told the DNSSEC algorithm number rather than
inferring it, because several numbers share one key type: RSA/SHA-1,
RSA/SHA-256 and RSA/SHA-512 all carry the same RSA key and differ only in the
hash. `hasherOf()` reports `EHASH_UNKNOWN` for Ed25519 and Ed448 while still
returning true, since those hash internally as part of the signature scheme
and so have no external hash for a caller to apply first.

What this module does *not* do is verify an RRset. It converts records and
keys, computes key tags and DS digests, and hands the caller the signed
prefix; canonical RRset construction and the verification call itself are
outside it.
