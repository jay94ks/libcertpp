# Changelog

[한국어](changelog.ko.md)

This repository's git history starts late: everything up to and including
the initial source commit was developed as uncommitted working-tree state,
so `git log` says nothing about how any of it came to be. This file is that
record instead, and stays the place to look for the reasoning behind work
that predates the history (and for anything a commit message states too
briefly). Entries are grouped by topic rather than by date; within a topic,
oldest first. See [`docs/architecture.md`](architecture.md) for what the
library looks like *now* — this file is about how it got there.

## `crypto/syms`: AES, DES, 3DES, ChaCha20

Added a symmetric-crypto module from scratch, parallel to the existing
`IHasher`/`IAsymmetric` interfaces:

- `ISymmetric`/`ISymmetricContext`/`ISymmetricKey`/`ISymmetricTransformer`
  (`include/certpp/crypto/sym.hpp`, `include/certpp/crypto/transform.hpp`):
  the shared interface surface, plus `ISymmetric::builtIn(ESymmetrics)` as
  the construction entry point.
- `AES` (FIPS-197; non-equivalent-inverse cipher, own S-box/InvS-box/Rcon
  tables), `DES`/`TripleDES` (FIPS 46-3; full Feistel network, shared
  `DesCore` between the two, 3DES as Encrypt-Decrypt-Encrypt with 2- or
  3-key schedules), and `ChaCha20` (RFC 8439; 256-bit key, 96-bit nonce,
  32-bit counter) under `include/certpp/crypto/syms/` + `src/crypto/syms/`.
- AES/DES/3DES share a single `CbcTransformer` (`src/crypto/syms/
  cbctransformer.hpp/.cpp`) implementing CBC mode with PKCS#7 padding
  (RFC 5652 6.3), parameterized by a block function and block size.
- Every algorithm is verified against its own published known-answer
  vectors: NIST SP 800-38A (AES), the classic FIPS-46 vector (DES), a
  DES-composition cross-check (3DES), RFC 8439 Appendix A.1 (ChaCha20),
  plus CBC round-trip/tamper/error-path tests. See
  `tests/crypto/syms/{aes,des,des3,chacha20}.cpp`.
- Bug caught during this work: `CbcTransformer`'s decrypt path originally
  computed how many whole blocks to emit as `final ? fullBlocks :
  fullBlocks - 1`, which emitted the final ciphertext block as if it were
  ordinary plaintext instead of holding it back for padding removal. Fixed
  to unconditionally hold back the last completed block
  (`src/crypto/syms/cbctransformer.cpp`), caught by the CBC round-trip
  tests failing on `transformFinal`.
- Later hardened for constant-time padding validation — see "Security
  audit" below.

## Security audit (CVE-driven)

A full security audit was run against 11 named CVEs (POODLE, Logjam,
CurveBall, Heartbleed, two libksba CVEs, Psychic Signatures, a SECT-curve
subgroup-validation CVE, an ECDSA nonce-bias CVE, an OpenSSL RNG CVE, and
a GnuTLS length-handling CVE), classifying each as directly applicable,
indirectly applicable, not applicable, or unknown rather than guessing
from the CVE name alone. Three real vulnerabilities were found and fixed;
see `docs/architecture.md`'s `CEcCurve`/`CEc2Curve`/`Ed25519`/`Ed448`
sections for the resulting design notes. Going forward, a bare "보안
테스트" request on this project defaults to this same workflow (CVE
research → applicability classification → adversarial test → root-cause
fix → report).

### EC/EC2 point-decoding gaps (SECT-curve-class, CWE-345)

`CEcCurve::decodePoint()` (prime/short-Weierstrass curves) and
`CEc2Curve::decodePoint()` (binary/Lopez-Dahab curves) both accepted the
point-at-infinity encoding as a valid "public key," and neither performed
a subgroup-order check. For `CEc2Curve` specifically this is directly
exploitable: its binary curves have cofactor 2 or 4, so a small-subgroup
point genuinely exists on-curve outside the main subgroup — proven
concretely in `tests/crypto/ec2curve.cpp` by constructing `(0, sqrt(b))`
(always on-curve, since `x=0` collapses the curve equation to `y^2=b`,
and always order exactly 2, since char-2 negation is `-P=(x,x+y)` so
`x=0` points are self-negating) and showing it passes `isOnCurve()` but
fails a subgroup check. `CEcCurve`'s prime curves all have cofactor 1, so
the subgroup check there is mathematically redundant but was added anyway
for defense-in-depth and consistency. Fixed in `src/crypto/eccurve.cpp`
and `src/crypto/ec2curve.cpp`: `decodePoint()` now rejects infinity, adds
a field-range check (`x,y < p`, `CEcCurve` only — binary-field elements
have no analogous range issue), and rejects any point whose subgroup-order
scalar multiple isn't infinity.

### Ed25519/Ed448 universal signature forgery (Psychic-Signatures-class)

The most serious finding. Both `Ed25519`/`Ed448`'s shared `decodePoint()`
helper — used both to import an untrusted public key via
`createPublicKey()` and to decode a signature's own `R` component in
`verify()` — failed to reject the identity point or other low-order
points. This allowed a universal forgery: register a public key encoded
as the identity point, then submit a signature `(R=identity, S=0)` against
*any* message, since the verification equation `S*B == R + k*A` reduces
to `O == O + k*O == O` regardless of the per-message hash `k`. Fixed in
`src/crypto/asyms/ed25519.cpp`/`ed448.cpp` with two checks (mirroring
logic already present and correct in `checkPrivateKey()`): reject the
identity point outright (its order is 1, which trivially "divides" the
group order, so a subgroup check alone can't catch it), and reject any
point whose subgroup-order scalar multiple isn't the identity. Regression
tests in `tests/crypto/asyms/ed25519.cpp`/`ed448.cpp` cover both
`createPublicKey` rejecting the identity point and `verify` rejecting a
forged `(R=identity, S=0)` signature against a real key.

### CBC padding timing (POODLE/Lucky13-class)

`CbcTransformer`'s PKCS#7 padding check (decrypt path) was rewritten to be
constant-time: it scans every byte of the final block unconditionally
every call and combines the results with bitwise ops instead of branching
or early-exiting on the first mismatch, which is the textbook structure a
Vaudenay-style CBC padding oracle exploits. See the "Constant-time PKCS#7
validation" comment in `src/crypto/syms/cbctransformer.cpp`.

### Fixed: RSA PKCS#1 v1.5 decrypt timing (Bleichenbacher-class)

`src/crypto/asyms/rsa.cpp::decryptBlock()`'s padding-removal scan had the
textbook Bleichenbacher-oracle shape: a data-dependent-length loop
(stopping at the first `0x00` separator byte) plus early-return branches
on the lead bytes and the separator's position/minimum offset. Every
failure path already returned a uniform `ERET_BADREQ`, but the *time
taken* to reach it still leaked which check failed and where. Rewritten to
scan the entire block unconditionally (always `keyBytes - 2` iterations)
and fold every check -- lead bytes, separator found, minimum 8-byte
padding length -- into a single bitmask via bitwise AND/OR instead of a
chain of branches, the same discipline `CbcTransformer`'s PKCS#7 check
already applies. This does not make the surrounding `modExp`/CRT path
itself constant-time -- that remains this project's accepted
correctness-over-timing-hardening stance for big-number math (see
`CEcCurve`'s doc comments) and was never in scope here -- only the
padding-removal scan's own data-dependent branching, which was the part
actually exploitable as a decryption-timing oracle. Verified against
`tests/crypto/asyms/rsa.cpp`'s existing encrypt/decrypt round-trip and
malformed-padding tests.

### Fixed: DSA fixed-base signing speedup

`DsaContext::sign()`'s `g^k mod p` term now goes through
`DsaPrivateKey::fixedBaseModExpG()`, a left-to-right windowed
exponentiation over a lazily-built, per-key-cached table of `g^0..g^15 mod
p` -- the same 16-entry-window technique `CEcCurve::scalarMulBase()`
already uses for fixed-base EC signing, adapted from point
addition/doubling to modular multiplication/squaring. Purely an internal
performance change (no interface/ABI impact, no security-requirement
change): the per-signature nonce `k` still varies every call, but `g`/`p`
are fixed for a given key, so the table is built once and reused across
every `sign()` call (and retry attempt) that key ever makes. Verified
against `tests/crypto/asyms/dsa.cpp`'s existing sign/verify suite.

### Other hardening from the same pass

- `IExtension` gained a `critical()` flag (`include/certpp/x509/ext.hpp`).
  `CCert::parseExtensions()` (`src/x509/cert.cpp`) was already parsing
  `Extension.critical` from DER but discarding it — now records it.
  Separately, `CCertBuilder::build()` was found to never emit the
  `critical` BOOLEAN TLV at all when building a certificate; fixed to
  conditionally emit it (DER-canonically omitted when false) between the
  `extnID` and `extnValue` TLVs.
- RFC 5280 4.2's "MUST NOT include more than one instance of a particular
  extension" is now enforced: `parseExtensions()` skips any extension OID
  that duplicates one already collected, keeping only the first
  occurrence.
- Verified via a full ASan-instrumented Debug build and test run
  (`/fsanitize=address /EHsc`) — 80/80 tests passed, zero findings.

## Project-wide refactor: no free functions in `src/`

Every file-scope or anonymous-namespace free function across the codebase
(roughly 20 files) was converted to either a private static method of the
class that owns it, or — for logic genuinely shared across translation
units with no single natural owner — a plain `PascalCase` (no type-prefix)
private class under `src/`, header+cpp pair local to that directory.
Notable instances: `RsaContext`'s PKCS1/PSS helpers; `Edwards25519`/
`Edwards448`/`Curve25519`'s curve-math blocks consolidated into classes;
`MD5`/`SHA1`/`SHAKE256`'s transform routines; `Sha2_32Core`/`Sha2_64Core`
shared between the two SHA-2 bit-widths; `CBigNum`/`CGf2m`'s hwaccel/limb
helpers; `CHex`; `SDateTime`'s C-library-wrapping helpers; `CEncoder`/
`CDecoder`'s fixed-digit date helpers; `DSA`'s domain-parameter
generation; `CRng`'s fallback fill; and the NameConstraints extension's
subtree codec. No behavioral change — verified by a full test-suite pass
(80/80) after the sweep, with a final grep confirming zero remaining
free functions in `src/`.

## Documentation

- `docs/architecture.md`'s `IExtension` and `_extensions` sections updated
  for `critical()` and duplicate-OID skipping; a new section added
  documenting the entire `crypto/syms` module (including the
  constant-time-padding rationale, explicitly contrasted with
  `CEcCurve`'s/`CBigNum`'s own non-constant-time-by-design stance); two
  stale comments describing `Sha2_32Transform`/`Sha2_64Transform` as free
  functions corrected to their current class-method names; the top-level
  Overview paragraph (previously describing only `common`/`version`/
  `utils`/`io`/`asn1`/`crypto`, omitting `x509` and `crypto/syms` entirely)
  rewritten to cover the library as it now stands.
- This file added as the project's work-history record, since there's no
  git history yet to serve that purpose.

## `CRng` on Linux: `getrandom(2)`

`CRng::fill()`'s Linux branch now calls the `getrandom(2)` syscall directly
(looping past `EINTR` and short reads) instead of going straight to
`/dev/urandom`, falling back to `/dev/urandom` only if the syscall itself
fails outright (`ENOSYS`, `EPERM`/a seccomp block), and from there to the
existing `fillFallback()`/`std::random_device` path behind
`CERTPP_RNG_FALLBACK`. `docs/architecture.md`'s `CRng` section and
`docs/build.md`'s `CERTPP_RNG_FALLBACK` row updated to describe the
three-tier chain.

## RSA: CRT-accelerated private-key operations

`RsaContext::privateExp()` now uses CRT (Garner's formula: `m1 = x^dp mod
p`, `m2 = x^dq mod q`, combined via `qInv`) instead of a single
full-modulus `modExp(x, d, n)` whenever a key carries its `p`/`q`/`dp`/
`dq`/`qInv` parameters — roughly 4x faster, since each of the two
exponentiations runs over a modulus about half the bit width of `n`.
Guarded by a mandatory re-encrypt check (`modExp(m, e, n) == x`), which
doubles as both the standard Lenstra/Bellcore fault-attack countermeasure
and a correctness fallback for an imported key whose CRT parameters were
never validated via `checkPrivateKey()` — any mismatch, or a missing CRT
parameter, falls back to plain `modExp`. Wired into `sign()`, `signPss()`,
and `decryptBlock()`. See `docs/architecture.md`'s `crypto/asyms/rsa.hpp`
section for the full writeup.

## AES: hardware acceleration (AES-NI)

`AesCore` gained an x86-64 AES-NI path (`AESENC`/`AESENCLAST`/`AESDEC`/
`AESDECLAST`/`AESIMC` intrinsics), the same runtime-CPUID-dispatch shape
already used for SHA-1/SHA-256 (`hasAesNi()`, leaf 1, ECX bit 25,
`encryptBlockAccelerated`/`decryptBlockAccelerated` vs.
`encryptBlockPortable`/`decryptBlockPortable`). Decryption uses the
Equivalent Inverse Cipher construction so the existing forward round-key
schedule can be reused unchanged. Gated by the new `CERTPP_DISABLE_HWACCEL_AES`
CMake option (`OFF` by default), documented in `docs/build.md`. Verified
against the module's existing SP 800-38A known-answer vectors, which
exercise the accelerated path automatically on AES-NI-capable hardware.

## Post-quantum cryptography: pre-review and KEM interface design

- [`docs/pqc-review.md`](pqc-review.md) added: a pre-implementation review
  of the standardized PQC algorithms (ML-KEM/FIPS 203, ML-DSA/FIPS 204,
  SLH-DSA/FIPS 205, plus FN-DSA/HQC's less-settled status), how each fits
  (or doesn't) this library's existing `IAsymmetric`-shaped interfaces, what
  substrate already exists vs. needs building, and a suggested order of
  work starting with `SHAKE128` and the `IKem` interface design.
- `IKem`/`IKemContext` (`include/certpp/crypto/kem.hpp`, new) and a third
  KEM key family (`EKems`/`IKemKeyBase`/`IKemPublicKey`/`IKemPrivateKey`/
  `SKemKeyPair`, added to `include/certpp/crypto/keys.hpp`) designed,
  mirroring `IAsymmetric`/`IAsymmetricContext`'s shape except for
  `encapsulate()`/`decapsulate()` replacing `sign()`/`verify()` /
  `createEncrypter()`/`createDecrypter()`, since a KEM produces its shared
  secret together with the ciphertext rather than encrypting caller-given
  plaintext. Header-only by design at this stage — no `.cpp`, not wired
  into the umbrella header, no concrete algorithm yet. See
  `docs/architecture.md`'s `crypto/keys.hpp`/`crypto/kem.hpp` sections.
- `SHAKE128` (`include/certpp/crypto/hashers/shake128.hpp` /
  `src/crypto/hashers/shake128.cpp`, `EHASH_SHAKE128`) added as the first
  concrete PQC-groundwork step, needed by both FIPS 203/204 for
  matrix/vector expansion. The Keccak-f[1600] permutation and sponge logic
  previously private to `SHAKE256` were extracted into a shared
  `KeccakCore` (`src/crypto/hashers/keccakcore.hpp`/`.cpp`) so `SHAKE128`
  (rate 168) and `SHAKE256` (rate 136) share one implementation instead of
  duplicating it. Verified against Python-`hashlib`-generated vectors
  (including rate-boundary cases) plus one NIST CSRC-published
  (`SHAKE128_Msg0.pdf`) empty-message vector, cross-checked against
  `hashlib.shake_128` to rule out a PDF-transcription error.

## Project-wide refactor: buffer bulk operations (`memcpy`/`memmove`/`memset`)

Every element-wise fill or copy loop over a `TArray`/`CBuffer`/raw-array
byte range across `src/` (originally found via `rsa.cpp`'s PSS/PKCS1
pipeline, then swept project-wide across ASN.1, DSA/ECDSA, symmetric
ciphers, curve-math/utils, and x509 in five parallel passes, plus two
further targeted regex sweeps that caught `.data[i]`-style field-access
copies the first pass's pattern missed) was replaced with a raw-pointer
`std::memset`/`std::memcpy`/`std::memmove` call, and any `TArray<uint8_t>`
being used in a buffer role (rather than as a sequence of distinct
elements) was retyped to `CBuffer`. Deliberately left untouched: constant-
time/branch-free code (`CbcTransformer`'s padding check, the EC/EdDSA
scalar ladders), reversals and in-place swaps (`CBigNum::reverseBytesInPlace`,
DES/3DES's decrypt-side key-schedule reversal — neither is expressible as
an order-preserving `memcpy`/`memmove`), conditional/filtered copies
(`CRng::fillNonZero`'s reject-zero-byte loop), and any `TArray<uint8_t>&`
parameter required by an existing public-header function signature
(`CEcCurve::encodePoint`, `CGf2m::toBigEndian`, `CHex::decode`). Now
documented as a standing project convention in
[`docs/coding-conventions.md`](coding-conventions.md)'s "Buffer handling"
section. No behavioral change anywhere — verified by a full 81/81
test-suite pass after every round.

## Project-wide audit: memory safety, DER strictness, signature verification

A five-part read-only audit (utils/io/asn1, hashers/RNG/symmetric,
asymmetric/curves, x509/examples, and the docs against the code) produced the
fixes below. Two slices independently reported the same two defects — the
digest-truncation bug and the non-minimal INTEGER acceptance — which is part of
why both are described here in detail.

### Memory safety

- `TString`'s destructor called only `clear()`, which preserves capacity by
  contract, so it never freed `_data`: every `CString`/`CWideString` that had
  ever allocated leaked its buffer, including on every certificate parse. Now
  pairs `clear()` with `trimExcess()`, as `~TArray()` already did. The
  destructor's own doc comment had claimed it "releases any allocated memory"
  the whole time. MSVC's ASan has no leak detector, which is why the earlier
  ASan run reported zero findings.
- `MemStream::seek()` clamped only `ESEEK_END`, so `ESEEK_SET`/forward
  `ESEEK_CUR` could park `_pos` past the end. `read()`/`write()` then computed
  their available room as `_span.size - _pos` / `_cap - _pos` — unsigned
  subtractions that underflow to a huge value from there, skipping `write()`'s
  `reserve()` and taking both `memcpy`s out of bounds. Fixed in all three
  places: `seek()` clamps, and both accessors compare rather than subtract.
- `MemStream::length()` growing the visible length published bytes `reserve()`
  had never initialized — raw `new uint8_t[]` contents readable by the next
  `read()`. Zeroed now.
- `TString`'s three assignment operators returned `SelfType` **by value**, so
  every assignment copy-constructed (and, before the destructor fix, leaked) a
  throwaway string; the move assignment did so even after correctly swapping.
  `TArray` had the right signatures all along.

### DER strictness at the untrusted boundary

- `CDer::readBigInteger()` accepted non-minimal INTEGERs: it stripped one
  leading `0x00` and let `fromBigEndian` absorb the rest, so `02 02 00 05` and
  `02 03 00 00 05` both decoded to 5. Every DER signature and key this library
  parses therefore had extra valid encodings — signature malleability.
  `CDecoder::decodeInteger()` had implemented X.690 8.3.2's rule correctly all
  along; this path simply never got it.
- `CDer::readOuterSequence()` computed `bytesRead` and discarded it, so
  trailing bytes after the SEQUENCE were accepted: junk could be appended to a
  valid signature and it still verified.
- Both tightenings were validated against `tests/x509/realcerts.cpp`'s real
  commercially-issued certificates, which still parse — i.e. the stricter rules
  reject malleable encodings without rejecting anything real.

### Signature verification

- `COcspRequest`/`COcspResponse::verifySignature()` treated
  `_sigHashAlgo == EHASH_UNKNOWN` as "EdDSA, verify the raw bytes". But
  `CCert::resolveSigAlgo()` is `void` and leaves that value untouched for any
  OID outside `SIG_ALGOS` (id-RSASSA-PSS, the SHA-3 family, anything
  malformed), making "unrecognized" indistinguishable from EdDSA's legitimate
  "no separate hash". An unknown algorithm therefore handed unhashed
  `tbsRequest`/`tbsResponseData` to an ECDSA/DSA verify, which truncates it to
  the subgroup order's bit length — so the signature covered a prefix of the
  plaintext instead of a collision-resistant hash of the message. Both sites
  now decide from the verifying key's own `EAsymmetrics` and fail closed with
  `ERET_NOTSUP` otherwise. `CCert` had always failed closed here; only OCSP
  inverted it.
- FIPS 186-4 §6.4 asks for the leftmost `min(N, outlen)` **bits** of the
  digest; `CBigNum::fromBigEndianTruncated()` kept `ceil(N/8)` **bytes** and
  never shifted, contradicting its own doc comment. For the eight binary
  curves whose subgroup order is not byte-aligned, ECDSA therefore produced
  signatures that verify against this library and against nothing else — 16
  curve/hash combinations, e.g. K-163 with SHA-256 shifting 88 bits where FIPS
  wants 93. Sign and verify agreed with each other, so the suite passed
  throughout; the per-curve tests only ever verify their own output, which is
  exactly the blind spot. DSA and all 20 prime curves are unaffected: their
  `N` is byte-aligned, and P-521 never truncates because no digest is long
  enough.
- RSA `decryptBlock()` accepted `c >= n`, which RFC 8017 5.1.2 forbids and
  which is also a timing distinguisher — the CRT re-encrypt check can never
  match for such a ciphertext, so every one of them silently took the slow
  full-modulus fallback. It also lacked `encryptBlock()`'s `keyBytes >= 11`
  guard, without which an imported key small enough to give `keyBytes < 2` made
  the lead-byte read run past the buffer.
- DSA's `createPrivateKey()` validated only the version field, so a zero
  modulus or an out-of-range `x` reached `sign()` and divided by zero;
  `createPublicKey()` rejected `p`/`q`/`g` but not `y`. Both now apply the
  cheap structural checks at the import boundary, still leaving the full
  validation to `checkPrivateKey()`.

### Other correctness

- `SHAKE128`/`SHAKE256::finish()` squeezed from the live sponge state, so for
  any output longer than one rate block a second call returned the
  *continuation* of the output stream instead of the same bytes again. Now
  squeezes from a copy, matching how MD5/SHA-1/SHA-2 finalize a temporary.
  Output at or below the rate never permutes, which is why the shipped lengths
  (32/64, and Ed448's 114) never exposed it.
- MSVC's `hasSha()` (twice) and `hasAdxBmi2()` read CPUID leaf 7 without first
  checking leaf 0's maximum. CPUID answers an out-of-range leaf with the
  *highest supported* leaf's data rather than zeroes, so on a CPU whose maximum
  is below 7 these could report SHA-NI or BMI2/ADX support that isn't there and
  then execute an invalid instruction. The GCC/Clang path was always safe —
  `__get_cpuid_count()` makes the check internally. `hasAesNi()`/`hasPclmul()`
  use leaf 1 and were never affected.
- `src/utils/djb.cpp` included `<certpp/utils/Djb.hpp>`; the file is
  `djb.hpp`, so the build only ever worked on a case-insensitive filesystem.
  A sweep confirmed it was the only such include in the tree.
- `CDistributionPoint::encode()` re-emitted `nameRelativeToCRLIssuer` as
  primitive `81`. It is `[1] IMPLICIT RelativeDistinguishedName`, a SET, and
  IMPLICIT tagging preserves the constructed bit (X.690 8.14), so the wire form
  is `A1` — and since `decode()` accepts either, valid input was being rebuilt
  as invalid output. Its `decode()` also set `_hasReasons` before validating
  the BIT STRING, reporting reasons the DER never carried; it now decodes once
  up front, which also drops eight redundant re-validations.
- `DsaPrivateKey`'s fixed-base window table was a `mutable` member filled from
  a `const` method — a data race as soon as two threads signed with the same
  key object. Built in the constructor instead (15 modular multiplications,
  less than the DER parse that produced the key).

## Documentation pass

Audited every claim in the docs against the code and corrected what had
drifted, which was concentrated at the newest edge of the library:

- **Seven extension class names in `architecture.md` did not exist** (16
  occurrences) — `CSubjectAlternativeNameExtension` and friends, where the code
  has the short `CSanExtension`/`CSkiExtension`/`CAkiExtension`/`CCdpExtension`/
  `CAiaExtension`/`CPoliciesExtension`/`CEkuExtension`.
- **"No encoding side exists yet"** was false: all ten extensions have had a
  `C<Name>ExtensionBuilder` and `IExtension::encodeValue()` for some time.
- **"Where this will grow"** still described `x509/` as parse-only, which the
  document's own Overview already contradicted. Rewritten around what is
  genuinely missing: certificate/CRL signature verification (`CCert` parses the
  signature and exposes neither it nor the TBS range — `tests/x509/cert.cpp`
  has to re-walk the DER by hand to get at them), chain building and path
  validation, and CSR support. The stale third-party paragraph claiming a
  future dependency would be "asymmetric crypto once certificate generation is
  implemented" went too.
- `CCert::import()` renamed throughout to `importDer()`/`importPem()`/
  `importFrom()`; `EREG_AGAIN` (4 occurrences, a name that exists nowhere)
  corrected to `ERET_AGAIN`; `Sha2_32Transform()`/`Sha2_64Transform()`
  corrected to `Sha2_32Core::transform()`/`Sha2_64Core::transform()` — a
  rename this file had already claimed was done.
- `COctet`'s move assignment was described as emptying the source; it swaps,
  per the project convention, and the same document said so correctly
  elsewhere. Hardware acceleration was described as "two independent build
  options" with `CERTPP_DISABLE_HWACCEL_AES` missing. SHAKE128 was absent from
  the "no accelerated path" lists.
- `build.md` gained the missing `CERTPP_BUILD_EXAMPLES` row, an Examples
  section (including `CERTPP_EXAMPLE_OUTPUT_DIR` and why the examples are
  deliberately not CTest cases), and the AddressSanitizer recipe that
  `build-asan/` implied but nothing documented.
- `coding-conventions.md`'s buffer-handling rule now separates its two halves:
  the bulk-call half has exceptions, the raw-pointer half applies even to code
  that must stay a loop. `CbcTransformer` is the worked example.
- Both READMEs called `CBuffer` "a fixed-size owning byte buffer" — it is the
  resizable working buffer, `COctet` is the fixed-size one — and omitted
  `COctet`/`CBase64` entirely. The "no git history yet" premise in
  `changelog.md` and both READMEs is now true-as-of-then rather than false.
- `CLAUDE.md` claimed `x509` "parses (not yet generates)", listed neither the
  symmetric ciphers nor CRL/OCSP, and linked three of the five docs.

## Post-quantum: review tidied, implementation plan added

`docs/pqc-review.md` was written before any PQ code existed and had gone stale
on its own first step. Reconciled against the tree and extended:

- Added a status table. SHAKE128 and the shared `KeccakCore` are **done** (the
  review described them as future work); `IKem`/`IKemContext` plus the KEM key
  family are **declared only**.
- Corrected the interface section: the built `encapsulate()` takes no
  public-key parameter (it acts on the bound key, like `sign()`/`verify()`),
  and KEM keys are their own family (`EKems`/`IKemKeyBase`/`IKemPublicKey`/
  `IKemPrivateKey`/`SKemKeyPair`) rather than reuses of `IPublicKey`.
- Recorded a constraint found while fixing the SHAKE idempotency bug above:
  both XOFs expose one fixed output length per instance, so FIPS 203/204's
  unbounded rejection-sampling stream needs an incremental squeeze that does
  not exist yet. It is now Phase 2, and blocking.
- Re-examined the ML-KEM-first ordering. Two of its three original reasons have
  weakened — the KEM interface now exists, and the TLS-hybrid argument is about
  the industry rather than this library, which has no TLS stack and so no
  in-tree consumer for a KEM. Against that,
  `tests/x509/certs/unimplemented/identrust-mldsa-root.der` is a real,
  currently-valid ML-DSA root that `CCert` already parses completely except for
  its algorithm. The recommendation is left as "keep ML-KEM first, but treat
  the order as genuinely open at Phase 4", since Phases 2-3 are shared either
  way.
- Added a seven-phase implementation plan, with the acceptance test stated
  concretely: that IdenTrust fixture moving from `certs/unimplemented/` to
  `certs/implemented/`.
- `src/crypto/kem.cpp` added, so `IKem::builtIn()` has a definition at all — it
  was declared with no implementation anywhere, which made calling it a link
  error rather than a null return, and left `kem.hpp` as the one non-template
  public header without the matching `.cpp` the conventions require.

## Signature verification, external KAT vectors, and x509 parser hardening

The audit above left four things open that needed a decision rather than a
patch. All four were taken, in this order — tests first, because they are what
makes the rest safe to change.

### External known-answer vectors (and what they immediately proved)

The suite had no external vectors for RSA, DSA or any of the 36 curves: every
per-curve test signed a message and then verified its own output, which is
precisely why the FIPS 186-4 digest-truncation bug above survived a green
suite for as long as it existed. Added, under `tests/crypto/asyms/`:

- `kat_ecdsa.cpp` — 28 NIST CAVP 186-4 `SigVer` records (7 positive, 21
  negative) over K-163/SHA-256, B-163/SHA-256, K-163/SHA-512, B-233/SHA-256,
  K-283/SHA-384, B-283/SHA-384 and P-256/SHA-256 as a control.
- `kat_dsa.cpp` — 4 CAVP 186-3 `SigVer` records (L=1024/N=160, L=2048/N=256).
- `kat_rsa.cpp` — 2 CAVP 186-3 `SigVer15` records (2048-bit, SHA-256).

Verification vectors rather than signing vectors, deliberately: this library
draws a random `k`, so a signing vector's expected `(r, s)` is unreproducible,
while a verification vector exercises the whole truncate-and-verify path
against an external oracle — which is the path that was broken.

**The headline result: all 34 records pass, including every non-byte-aligned
binary curve.** The vectors were also shown to have discriminating power — rerun
against the old whole-byte truncation, all six non-byte-aligned positives fail.
So the truncation fix is now externally confirmed rather than merely
argued-from-arithmetic, and the five affected curves verify CAVP signatures
correctly. Transcription was cross-checked against an independent from-scratch
Python implementation, which caught one bad order literal in the vectors
themselves before they were committed.

### Adversarial DER tests

There had not been a single malformed-DER test in the x509 suite, and the
ASN.1 decoder's DER-strictness gates were almost entirely unexercised — the one
long-form length test used BER, so every DER-specific gate was untested. Added
`tests/asn1/malformed.cpp` (23 cases) and `tests/x509/malformed.cpp` (15
cases), feeding the parsers bytes they must reject.

The ASN.1 layer came out of this well: the `0xFF` reserved length count,
non-minimal and over-long long-form lengths, long form for a value under 128,
octet counts exceeding `sizeof(size_t)`, truncated headers, lengths running
past the buffer, indefinite form under DER (nested as well as top level), the
64-deep nesting guard, non-minimal high-tag-number form, BIT STRING unused-bit
rules, INTEGER redundant-leading-octet rules in *both* integer parsers, OID
minimality, and the whole UTCTime/GeneralizedTime validity and pivot-year table
are all already enforced correctly.

The x509 layer did not, and the gaps are below. Tests that document a gap still
open are named `known gap:` and assert with `WARN`, so the suite stays green
while reporting them on every run; three remain (an empty `Extensions`
SEQUENCE, `pathLenConstraint` surviving with `cA` FALSE, and an empty
`RDNSequence` accepted as an issuer name).

### x509 parser hardening

Each of these was accepted before and is rejected now, with the corresponding
test promoted from `WARN` to `CHECK`:

- **Trailing bytes after the outer SEQUENCE** — certificate, CRL, and all four
  OCSP decoders. The worst of the set: `importDer()` keeps its input verbatim
  as `_rawData`, so a suffix gave one certificate unlimited distinct
  `thumbprint()` values — sidestepping any blocklist, revocation record or
  dedupe cache keyed on it, without touching a signed field — and `exportDer()`
  replayed the non-DER suffix to whatever peer it serialized to.
- **A malformed `extensions [3]` wrapper silently dropped every extension.**
  The tag comparison required `isConstructed()`, but a non-match was treated as
  "no extensions present", and `parseExtensions()` returns `void` so it could
  not fail the import. A single cleared bit (`0xA3` → `0x83`) therefore turned a
  certificate carrying BasicConstraints, KeyUsage, EKU and NameConstraints into
  one carrying none, still importing `ERET_OK` and indistinguishable from a
  certificate that genuinely has no extensions. The over-long-`[3]`-length
  variant reached the same branch, because "nothing left to read" and "the next
  element does not parse" were conflated — `readNextElement()` reports both as
  false. Now separated by checking `atEnd()` first, so a parse failure fails the
  import.
- **`TBSCertificate.signature` was never compared to
  `Certificate.signatureAlgorithm`** (RFC 5280 4.1.1.2). The inner copy is
  inside the signed bytes; the outer one is not — yet the outer is what
  `signAlgo()`/`createHasher()`/`verifyBy()` act on, so an unauthenticated field
  chose the digest used to verify the authenticated ones. Only the OID is
  compared, not the parameters, since real-world issuers do differ between the
  two copies on absent-vs-NULL for the same algorithm.
- **`signatureValue`'s BIT STRING unused-bit count was read and discarded** in
  the certificate, CRL and both OCSP paths, giving every signature up to eight
  extra encodings. The `SubjectPublicKeyInfo` BIT STRING forty lines earlier had
  always been checked, which is what made this look like an oversight rather
  than a decision.
- **A negative `pathLenConstraint`** (`INTEGER (0..MAX)`, RFC 5280 4.2.1.9) is
  no longer reported as a usable constraint.

`tests/x509/realcerts.cpp`'s real commercially-issued certificates still parse
under every one of these rules, which is the check that matters: the
tightenings reject malleable encodings without rejecting anything real.

### Certificate and CRL signature verification

`CCert` parsed `_signature` and nothing ever read it; there was no accessor for
it and none for the TBS byte range, so nothing could check a certificate
against its issuer. The proof was in the suite itself — `tests/x509/cert.cpp`
hand-rolled a ~50-line DER re-walk to recover those bytes. Added:

- `CCert::signature()`, `CCert::tbsCertificate()`, `CCert::verifyBy(issuer)`.
- `CCrlReader::signature()`, `CCrlReader::tbsCertList()`,
  `CCrlReader::verifyBy(issuer)` — the CRL previously discarded both fields, so
  `decode()` now retains the signature and resolves its algorithm.

`tbsCertificate()`/`tbsCertList()` return the *original* TBS TLV from
`rawData()` rather than a re-encoding of the parsed fields: the signature
covers the issuer's bytes, and re-encoding would silently repair any quirk they
contain. The length comes from `readEncodedValue()`'s own `bytesRead` rather
than pointer arithmetic over the content span, because `TSpan::slice()` returns
`{nullptr, 0}` once it reaches the end — a sharp edge worth knowing about
elsewhere too.

Both `verifyBy()` implementations decide hash-versus-raw from the *issuer key's*
own algorithm, never from `_sigHashAlgo == EHASH_UNKNOWN` — the same ambiguity
that produced the OCSP bug above. They are single-link checks by design: no
name chaining, no validity window, no constraint enforcement. See
`tests/x509/verify.cpp`, which covers genuine self-signatures across
RSA/ECDSA/Ed25519/Ed448, a CA-issued leaf against its real issuer and against a
stranger's key, and a tampered signed byte.

## Performance: Knuth-D division and word-level GF(2^m) reduction

Two systemic choices in the arithmetic layer were each costing roughly an
order of magnitude. Both were bit-serial algorithms sitting underneath
everything else, and both were replaceable without touching a single
interface.

**The result, measured on the full test suite: 1243s to 140s, an 8.9x
speedup overall.** Individually, `crypto_asyms_rsa` went 85.7s to 6.1s
(~14x), `crypto_asyms_x25519` 445.6s to 39.5s (~11x), and
`crypto_asyms_dsa` 64.4s to 8.5s (~7.5x). All 88 tests still pass.

### `CBigNum::divMod()` — Knuth's Algorithm D

The old implementation was a bit-serial restoring division: one shift, one
compare and one conditional subtract across the *whole divisor buffer*, per
bit of the dividend. Since `modExp()` performs thousands of reductions and
every asymmetric algorithm in the library runs through `modExp()`, this one
routine was the dominant cost in RSA, DSA and ECDSA alike — a single
2048-bit `mod` was measured at around 50x the cost of the multiplication it
follows.

Replaced with Algorithm D (TAOCP vol. 2, 4.3.1) in base 2^32, which produces
one quotient *limb* at a time instead of one bit: normalize the divisor so
its top limb has its high bit set, estimate each quotient limb from the top
two limbs of the running remainder, correct the estimate down, and add the
divisor back on the rare occasion it was still one too high. Single-limb
divisors take a separate plain long-division path, where the estimate is
exact and none of the correction machinery applies.

The verification is the interesting part, because Algorithm D has two places
that ordinary use never reaches:

- The C++ was first ported limb-for-limb to Python and fuzzed against exact
  integer arithmetic — 8,686 then a further 80,000 pairs, zero mismatches,
  covering exhaustive small values, limb boundaries, `2^k - d` divisors and
  realistic 2048-bit-modulus shapes. Doing this *before* compiling meant the
  algorithm was known-good before transcription was even attempted.
- That sweep showed the **D5/D6 add-back branch fired zero times in 72,695
  multi-limb divisions**, which matches theory (about 2/2^32 per quotient
  limb) and means random testing can never cover it. It also turned out to be
  *impossible* for a two-limb divisor: the two-limb estimate test then
  examines the entire divisor, so the estimate is exact and the branch is
  unreachable. Three limbs or more is required.
- So its inputs were constructed rather than sampled. The branch was
  exercised exhaustively in a 4-bit-limb model of the same algorithm (53,587
  triggers, zero disagreements with exact arithmetic), and the triggering
  limb patterns were scaled into the top nibble of each 32-bit limb — which
  preserves every ratio the estimate and its refinement depend on. Seven
  confirmed base-2^32 triggers are now in the test suite.

`tests/utils/divmod.cpp` carries all of this: it does not assert expected
values but compares against an independent, deliberately naive bit-serial
reference written with nothing but `CBigNum`'s public operations (the
algorithm this change replaced), and additionally checks
`quotient * divisor + remainder == dividend` with `remainder < divisor` —
which holds for correct division regardless of how either implementation got
there.

### `CGf2m::reduceWide()` — word-level polynomial reduction

The same shape of problem one layer over. Reduction walked the product's bits
from `2m-2` down to `m`, and for each set bit toggled `1 + termCount` bits
individually, each toggle paying its own divide and modulo to find its limb.
For B-571 that is ~570 iterations and thousands of toggles. It had been
measured at 95-98% of a multiplication's total cost, which meant the
PCLMULQDQ-accelerated carry-less product above it was buying almost nothing.

The fix follows from the identity itself: `x^m == x^terms[0] + ... + 1`
displaces *every* excess bit by the same amount, so the whole excess folds in
one step — take `hi = wide >> m`, clear everything from bit `m` up, then XOR
`hi` back in at offset 0 and at each term offset. Folding can leave bits at
or above `m` again, so it repeats; for all five fields this library ships it
converges in exactly two folds, though it is written as a loop so it stays
correct for any reduction polynomial.

Validated the same way, before compiling: the word-level fold was compared
against the existing bit-serial implementation over 20,030 random products
across all five fields (163/233/283/409/571) plus each field's extremes, with
zero mismatches, and the two-fold convergence confirmed per field rather than
assumed.

Neither change touches a public signature, and the hardware-accelerated
multiply paths above both are untouched.

## Post-quantum groundwork: ML-KEM's substrate, and SHA-3

Phases 1-3 of [`pqc-review.md`](pqc-review.md)'s plan, plus one prerequisite
the plan had missed.

### Incremental SHAKE squeezing (Phase 2)

`SHAKE128`/`SHAKE256` could only produce the one fixed `byteWidth()` an
instance was constructed with, but FIPS 203's `SampleNTT` and FIPS 204's
challenge/mask expansion rejection-sample from a SHAKE stream until enough
candidates are accepted, with no length known in advance. Both now have
`squeeze()`, which returns successive chunks and advances the sponge;
`finish()` stays the fixed-length, repeatable view, squeezing from a copy. The
test asserts chunk-invariance across every chunk size from one byte up,
including splits landing exactly on, just before and just after each rate
boundary — the only place the sponge permutes, and so the only place a cursor
off-by-one would show. A bug turned up while writing it: the guards ordered
`if (out.empty()) return true;` ahead of the null check, and `TSpan::empty()`
is true for a null pointer as well as a zero size, so a caller asking for
bytes with nowhere to put them got a cheerful success.

### SHA3-256 and SHA3-512 — a missed prerequisite

ML-KEM needs `H = SHA3-256` and `G = SHA3-512`, and this library had SHAKE but
no fixed-output SHA-3 at all. The plan hadn't recorded that, so it surfaced
only when Phase 4 was about to start.

Both are now `EHashers` members. SHA-3 is the same sponge as SHAKE, so they
reuse `KeccakCore` and share a new private `Sha3Core` with each other — the
arrangement `Sha2_32Core` already has between SHA-224 and SHA-256, written as
operations over raw arrays so each public header declares its own context
without depending on anything under `src/`. The only differences from SHAKE
are the rate (`200 - 2*digestWidth`) and a `0x06` domain byte where SHAKE uses
`0x1F` — one byte, and the entire distinction between a SHA-3 digest and a
SHAKE output of the same length over an identical sponge, which is why the
tests assert the two genuinely differ rather than only checking vectors.
`finish()` follows the SHA-2 convention: a query that leaves the sponge alone,
so it repeats and absorption continues afterwards.

### ML-KEM ring arithmetic, samplers and wire encoding (Phase 3)

A new set of private units holds `MlKemRing` (R_q = Z_q[X]/(X^256+1), q=3329: NTT,
inverse NTT, base-case multiply, plus a schoolbook negacyclic multiply that
exists only to check the others), `MlKemCodec` (ByteEncode/ByteDecode,
Compress/Decompress) and `MlKemSampler` (SampleNTT, SamplePolyCBD). Private to
the PQ work, so no `CERTPP_API` and no type prefix.

FIPS 203 fixes the NTT's exact *representation*, not just its behaviour — an
encapsulation key is a ByteEncode of NTT-domain coefficients, so those values
go on the wire. A transform that round-trips correctly but orders its twiddles
differently is self-consistent and interoperates with nothing, which is
precisely the failure mode that hid the byte-granular ECDSA digest truncation
recorded above. So the tests deliberately don't rest on round trips: every
twiddle is re-derived from `17^BitRev7(i)` independently of how the
implementation builds it, the NTT-domain multiply is checked against the
schoolbook convolution, `X^256 == -1` is asserted directly, and 256-coefficient
arrays are pinned by checksum plus endpoints so a transposition anywhere fails.

Two things worth recording from the process:

- Every algorithm here was validated in Python against the specification text
  *before* any C++ was written. That is also how the resulting zeta and gamma
  tables came to be cross-confirmed against FIPS 203 Appendix A by a separate
  path.
- The compression rounding settled a detail worth not guessing at. q is odd,
  so the usual `(x*2^d + q/2)/q` truncates `q/2` and leaves the round-half-up
  tie rule to luck. Checking both that form and the provably-correct
  `(2*x*2^d + q)/(2*q)` against the exact rational definition for every
  coefficient in `[0, q)` at every width showed they agree everywhere — but
  only one is right by construction, and that is the one implemented.

`MlKemSampler::sampleNtt()` is the first real consumer of `squeeze()` and
justifies it concretely: it consumes 453-498 bytes of stream depending on the
seed. Its index bytes are appended in the order given, and a test asserts that
swapping them changes the result, because FIPS 203's matrix expansion
deliberately passes them transposed and a transposed call would otherwise be
undetectable.

`CMakeLists.txt` compiles those private units directly into the tests that
exercise them, since that code is deliberately not exported and linking
cannot reach it. Scoped to that one directory: everything else is still tested
through the public surface, as `DesCore` and `KeccakCore` are.

### Corrections to the plan itself

Three preparation tasks ran against the specs and the standardization record,
and found the plan wrong in several places:

- Its Phase 3 gate said to assert the NTT against "the standard's worked
  example". **FIPS 203 contains no worked examples and no intermediate values
  at all** — its appendices are the zeta table, SampleNTT's loop bounds, and
  the differences from CRYSTALS-KYBER — and NIST publishes no example-values
  page for ML-KEM. FIPS 204 is the same, though its Appendix B does print the
  full zetas table. The gate now states what is actually achievable.
- The X.509 profiles are **published**, not "beginning to standardize": RFC
  9881 (ML-DSA), RFC 9909 (SLH-DSA), RFC 9935 (ML-KEM). So the OIDs are
  settled, and `2.16.840.1.101.3.4.3.19` — the in-tree IdenTrust fixture's OID
  — is specifically **ML-DSA-87**, which determines which parameter set flips
  that fixture to `certs/implemented/`.
- The 2030/2035 deprecation dates are **NIST IR 8547**, not SP 800-131A, and
  both documents are still drafts.
- ML-DSA's largest signature is **4627** bytes, not 4595 (that was the IPD
  figure).
- FIPS 206 has no public draft 25 months after FIPS 204; HQC is planned as
  FIPS 207 and still pre-draft. SP 800-227 (KEM recommendations) went final and
  is normative for `IKem`.
- Hedged ML-DSA signatures are byte-reproducible after all, since ACVP's prompt
  supplies `rnd` — so Phase 5's gate covers all 24 sigGen groups rather than
  only the twelve deterministic ones.

The ACVP vectors for both algorithms are located, pinned to a revision and
validated ahead of the code, with provenance recorded in the plan — including
that ML-KEM's implicit-rejection cases are a genuine Fujisaki-Okamoto oracle
(all 45 satisfy `k == SHAKE256(z||c, 32)` and no valid case does) and that the
ML-DSA vectors reproduce byte-exactly under an independent implementation. The
spec traps worth knowing before writing either algorithm — ML-KEM's `G(d||k)`
parameter byte and transposed `SampleNTT` indices, ML-DSA's hint-decode
rejection conditions and Appendix C loop bounds — are written into their
phases rather than left to be rediscovered.

## Post-quantum: ML-KEM itself (FIPS 203)

The first half of [`pqc-review.md`](pqc-review.md)'s Phase 4 — the algorithm,
validated against NIST's vectors. The `IKem` wrapper that makes it reachable
through the library's own interface vocabulary is the other half, still to do.

`crypto/kems/mlkem.hpp` publishes `CMlKem` (K-PKE, Algorithms 13–15, and the
Fujisaki-Okamoto transform over it, Algorithms 16–18), `SMlKemParams`,
`CMlKemSampler` and `SMlKemPoly`. The samplers and the parameter/polynomial
types were private under `src/` while they were only substrate; they moved to
a public header because the raw-span form turns out to be the useful one on
its own — it can be driven straight from a test vector, which the
`IKem`-shaped API cannot, and it is what a caller who already owns its buffers
or wants K-PKE rather than the KEM would reach for.

`decapsulate()` is where all the subtlety sits. It re-encrypts what it
decrypted and compares against the ciphertext it was handed; on a mismatch it
returns `J(z || c)`, derived from the private key's own rejection seed, rather
than an error. So a malformed ciphertext produces a well-formed but unrelated
shared secret and the caller cannot tell the two cases apart. Reporting failure
there, or skipping the re-encryption, would hand back exactly the decryption
oracle the transform exists to deny — which is why the function has no failure
mode for a bad ciphertext at all, only for a structurally wrong-sized one.
ACVP publishes an expected shared secret for its `modified ciphertext` records
for the same reason: implicit rejection is a defined output, not an error path.

### A hole the promotion opened

Making `SMlKemParams` public made it a caller-supplied value, and `CMlKem`
sizes its fixed-capacity buffers from `MAX_K` and `maxCiphertextBytes()`. A
hand-built `SMlKemParams{9, …}` would therefore have overflowed every one of
them. While the struct lived under `src/` this was fine — only the library's
own code constructed it — and nothing about moving the header changes the
arithmetic, which is exactly why it was easy to miss.

`SMlKemParams::isValid()` now reports whether a set is one of FIPS 203's three,
and all eight `CMlKem` entry points call it before deriving anything at all
from `params`. Restricting to the three published sets rather than
range-checking each field is both safer and more honest: there is no fourth
set, and `k ≤ 4` alone would still admit `du`/`dv` wide enough to overrun the
ciphertext buffer. The test case sizes every span correctly *for the bogus set*
so the length checks cannot be what rejects them, and `maxCiphertextBytes()` is
derived from `mlKem1024()` rather than written as 1568, which also removed the
last two hand-written sizes from the implementation.

### Testing

`tests/crypto/kems/kat_mlkem.cpp` embeds ACVP keyGen, encapsulation and
decapsulation records for all three parameter sets, plus the
`encapsulationKeyCheck` ("noisy linear system values too large") and
`decapsulationKeyCheck` ("modified H") negative records. FIPS 203 publishes no
worked examples and no intermediate values, so these vectors are the only
external oracle that exists — and ML-KEM needs one badly, because at least
three of its details (the `k` byte in `G(d || k)`, the transposed indices in
`SampleNTT(ρ || j || i)`, `ByteDecode_12`'s reduction mod q) yield a scheme
that is perfectly self-consistent when implemented wrongly and interoperates
with nothing. No round-trip test can see any of them.

FIPS 203 Table 2's sizes are pinned with `static_assert` rather than run-time
checks, since `SMlKemParams` derives all of them at compile time. The keyGen
vectors do double duty as K-PKE.KeyGen vectors: ML-KEM's key generation is
K-PKE's with `H(ek)` and `z` appended, so the same record pins both.

The whole thing was validated the way the ring arithmetic was — a standalone
Python implementation written from the specification text first, which matched
all 180 ACVP vectors byte-exactly before any C++ existed. As a negative
control afterwards, changing `G(d || k)`'s domain-separation byte by one broke
12 assertions across two test cases, confirming the vectors actually bite on
the detail they exist to catch.

### Noted but not fixed

FIPS 203 requires the implicit-reject flag and the values around it to be
destroyed before `Decaps_internal` returns. They are not: this library has no
zeroization primitive at all, and no RSA, DSA or EC private-key operation
scrubs its intermediates either. ML-KEM is therefore consistent with the rest
of the codebase rather than newly deficient — but that is a real gap in all of
them, and the fix belongs in one shared `utils/` secure-zero rather than
hand-rolled here. Recorded in the plan.

## Post-quantum: ML-KEM as an `IKem`

The other half of Phase 4, which completes it. `crypto/kem.hpp` had been
designed and committed ahead of any lattice crypto, with `EKems` empty and
`IKem::builtIn()` returning null for everything; it now has ML-KEM behind it
and joins the umbrella header.

`MLKEM` (`crypto/kems/mlkem.hpp`) serves all three parameter sets from one
class with the set as constructor state — the arrangement `CEcdsa` already has
across its curves. It implements nothing cryptographic: `CMlKem` is the
algorithm, and this is the key objects, the size bookkeeping `IKemContext`
exposes, and the CSPRNG draws around it.

Two decisions worth recording.

`keySizes()` accepts the parameter set's own number — 512, 768 or 1024 — and
not a modulus width or a claimed security strength. Every other algorithm in
the library has a natural size parameter (RSA's modulus, X25519's 256-bit key)
and ML-KEM has none: the three sets differ in the module rank `k` and four
other parameters, and those numbers are names. Using the name keeps
`generateKeyPair(keySize, …)` usable the way every other algorithm's is,
without inventing a figure that reads as though it meant something. The
alternative — 128/192/256 for the NIST security categories — would have looked
more principled and been more misleading, since nothing in the implementation
is parameterized by it.

`MLKEM` is also the only layer in the ML-KEM implementation that touches the
CSPRNG, and that is the point of the split. `CMlKem::generateKeyPair()` and
`encapsulate()` take their seeds and message as parameters, which is exactly
what let them be validated against ACVP; `IKemContext::encapsulate()` has no
such parameter, so the wrapper fills them from `CRng`. The cost is that no
known-answer test is possible at this layer, so `tests/crypto/kems/mlkem.cpp`
tests what the wrapper adds instead: that `encapsulate()` called four times
against one public key gives four different ciphertexts and four different
secrets (a secret that was a function of the key alone would be reused every
session, and each one still decapsulates correctly), that a ciphertext for one
key opens under another only as a *different secret* rather than an error, and
that a tampered ciphertext returns `ERET_OK` — the Fujisaki-Okamoto
requirement, now checked at the interface boundary as well as inside `CMlKem`.

A decapsulation key embeds its own encapsulation key, so
`IKemPrivateKey::publicKey()` reads it out at offset `dkPkeBytes()` rather
than recomputing it. `checkPrivateKey()` and `createPrivateKey()` then verify
that the embedded `H(ek)` agrees with that `ek`, that the linked public key is
byte-for-byte the embedded one, and that the `ek` is canonical — rather than
trusting any of the three, since a key reaching `createPrivateKey()` came from
outside. Keys carry no ASN.1 wrapping at all; the SubjectPublicKeyInfo form a
certificate needs is Phase 6.

## `CSecure`: zeroization and constant-time compare/select

Added `utils/secure.hpp` — `CSecure::zero()`, `equalsMask()`, `select()` — and
used it to close two gaps in ML-KEM, one of which was worse than the one
originally recorded.

### The real finding: `memcmp` in the FO check

The previous entry noted ML-KEM's missing zeroization as a known gap. Looking
at `decapsulate()` again to fix that turned up something more serious a few
lines away:

```cpp
const bool matches = std::memcmp(reencrypted, ciphertext.data, ciphertext.size) == 0;
std::memcpy(sharedSecret.data, matches ? candidateSecret : rejectionSecret, 32);
```

`memcmp` stops at the first differing byte, so its running time reveals **how
long a prefix of the re-encrypted ciphertext matched** — far more information
than the single bit the Fujisaki-Okamoto transform exists to hide, and the
shape of the KyberSlash family of attacks. The ternary then branches on the
verdict, which *is* that single bit; FIPS 203 requires the implicit-reject
flag never be exposed "in any form", and a branch exposes it.

Both are now `CSecure::equalsMask` followed by `CSecure::select`: the
comparison reads every byte whatever the outcome and yields `0xFF`/`0x00`, and
the mask drives a byte-wise select, so nothing branches on anything secret.
The ACVP decapsulation vectors — including all the `modified ciphertext`
records, which are precisely the rejecting path — still pass byte-for-byte,
which is what confirms the rewrite preserved the output on both paths.

`equalsMask` returns a full mask rather than a bool on purpose, and the test
asserts the value is `0xFF` rather than merely truthy: `select` ANDs with it,
so a mask of `1` would silently keep only the low bit of each selected byte.
It also folds its accumulated difference to a mask arithmetically instead of
writing `diff == 0`, so correctness doesn't depend on the compiler choosing a
flag set over a branch there.

### Zeroization that survives the optimizer

`CSecure::zero()` routes `memset` through a volatile function pointer. This was
verified rather than assumed, by reading MSVC's `/O2` output for two otherwise
identical functions: in the one using a plain `std::memset` the clear was
**deleted entirely** — no store, no call — while the `CSecure::zero` call
survived, and inside `zero` the compiler loads the pointer from memory and
tail-jumps through it rather than folding it back to a direct `memset`.

`decapsulate()` was restructured to a single exit so the clearing cannot be
skipped by an error path, since that one is a normative FIPS 203 requirement.
`kpkeKeyGen()`, `kpkeDecrypt()`, `encapsulate()` and `MLKEM`'s CSPRNG draws
clear at their success exit without being restructured — their early returns
all need a hasher or sampler to fail at a fixed, correct size, so none is
reachable, and threading a status through those loops would cost more clarity
than it buys. The difference is deliberate and noted in the code.

### What this deliberately does not touch

The inline mask arithmetic in RSA's EME-PKCS1-v1_5 unpadding and
`CbcTransformer`'s PKCS#7 padding check stays as it is. Neither is "compare
two buffers" or "choose between two buffers" — both interleave masking with a
scan over the padding — so there is nothing in `CSecure` for them to call, and
rewriting working, tested constant-time code for the appearance of
consolidation would be a poor trade.

Still outstanding: no RSA, DSA or EC private-key operation scrubs its
intermediates. The primitive is now there for it.

## Scrubbing private-key intermediates

`CSecure` existed but was only used by ML-KEM. This applies it across the
pre-quantum algorithms, and adds the big-number counterpart it needed to be
able to.

### `CBigNum::secureClear()`, and why the destructor doesn't do it

Private keys and signing nonces are `CBigNum` values, so clearing stack
buffers alone would have missed everything that matters. `secureClear()` wipes
the limb allocation — its whole capacity, so limbs above a trimmed length go
too — and resets the value to zero.

Making `~CBigNum()` do it unconditionally would be far more robust, so the
question was what it costs. Measured rather than guessed, and the guess was
wrong: I estimated 1–3% and it was **+22% across the asymmetric test suites,
+32% on X25519 alone**. A scalar multiplication creates a great many
short-lived temporaries, nearly all of them holding public intermediates, and
each clear is a non-inlinable indirect call. So it stayed opt-in. Applying it
only to named secrets is unmeasurable by comparison — the build without the
clears actually timed *faster* on one run than the build with them, which is
how far below the noise floor it sits.

That buys a real limitation, stated in the header rather than left implicit:
`secureClear()` reaches only the values a caller names. A temporary created
inside an expression, or inside `modExp()`/`modInverse()`, is freed uncleaned.
This narrows the window a secret sits in freed memory; it does not close it.

### What got cleared, and why those

The criterion was "exposure is catastrophic", not "is secret":

- **ECDSA/ECDSA2/DSA signing**: the nonce `k`, and the `d*r`/`x*r` product
  beside it. Either one yields the private key outright from a published
  signature — `d = (s*k - z)/r mod n`, or `d = dr/r mod n`. Cleared on every
  path out of the retry loop, including the retry paths themselves, which need
  a zero `r` or a non-invertible `k` and so are unreachable short of a broken
  CSPRNG. Three lines each; worth it for not having to reason about it again.
- **Ed25519/Ed448 signing**: the nonce, and the expanded seed behind it. EdDSA
  publishes `S = r + k*s mod L` with `k` public, so learning `r` for one
  signature recovers `s` — the nonce is exactly as sensitive as the key, which
  makes `prefix` and `rHash` the same secret since they determine it. Also the
  `k*s` product, which hands over `s` because `k` is public. Each is cleared
  where it stops being needed, which leaves exactly one exit with anything
  live.
- **X25519**: the clamped scalar (the private key in all but encoding,
  recomputed on every scalar multiplication) and the shared secret.
- **RSA**: the CRT intermediates. These are *more* sensitive than the value
  being computed, not less: `m1` is `m mod p`, so `m - m1` is a multiple of `p`
  and `gcd(m - m1, n)` is `p` exactly — and when signing, `m` is the published
  signature. Also the padded plaintext buffer in `decryptBlock`, on all three
  of its exits, which keeps the paths doing the same work rather than adding a
  distinguisher to the constant-time unpadding above it.

### Evidence it didn't break anything

The deterministic known-answer tests are the check that matters here: an
over-eager clear would corrupt a value still in use, and RFC 8032's EdDSA
vectors, CAVP's ECDSA/DSA vectors and the RSA KAT all reproduce exact expected
bytes. All of them still pass, along with the rest of the 95-test suite in
both Debug and Release.

## Post-quantum: ML-DSA's ring arithmetic

The start of Phase 5. `src/crypto/asyms/mldsaring.hpp`/`.cpp` hold `MlDsaRing`:
R_q = Z_q[X]/(X^256 + 1) with q = 8380417, the NTT over it, and the two
coefficient operations ML-DSA's signing loop depends on.

It is a separate unit from `MlKemRing`, not a parameterization of it, and the
reasons go deeper than the constants:

- **`int64_t` throughout.** q = 2^23 − 2^13 + 1, so a product of two
  coefficients reaches about 7.0e13 — four orders of magnitude past
  `int32_t`. In ML-KEM's ring the same product fits in `int32_t` comfortably,
  so carrying that habit across would be a silent wraparound rather than a
  style difference. It bites the twiddle-table builder too, where `ZETA * acc`
  reaches ~1.5e10; `MlKemRing`'s equivalent uses `int32_t` there quite safely,
  and copying it would have been wrong.
- **The NTT is complete.** ζ = 1753 has order exactly **512**, not 256, so
  X^256 + 1 splits all the way into 256 linear factors: eight layers, 256
  independent evaluation points. ML-KEM's transform stops one layer short,
  leaving 128 degree-1 blocks that need a base-case multiply and a second
  twiddle table. So `multiplyNtt()` here is plain pointwise multiplication and
  there is no `gammas()` at all.
- **`bitRev8`, not `bitRev7`.**

Also `centered()` (FIPS 204's `mod±`, the representative in (−q/2, q/2]) and
`infinityNorm()`. The norm belongs to the ring rather than to a caller because
ML-DSA's signing loop rejects on exactly that quantity — and it has to be
taken over *centered* representatives, so an implementation that skipped the
centering would see q−1 where the answer is 3, and would then either reject
everything or reject nothing.

### Validated before any C++ was written

Same discipline as ML-KEM's ring, and it paid off the same way — the
implementation was correct on its first run. A Python reference built from the
specification text established, ahead of time:

- ζ = 1753 has order exactly 512 and ζ^256 = −1 (so the transform runs to
  completion);
- all 255 of FIPS 204 Appendix B's printed zetas match ζ^BitRev8(k) mod q
  — the table was extracted from the publication itself rather than
  transcribed;
- Algorithm 42's constant 8347681 is simply 256⁻¹ mod q, derived rather than
  copied;
- the NTT round-trips and its pointwise product agrees with a schoolbook
  negacyclic convolution, over 200 random polynomial pairs;
- and the transform agrees with dilithium-py 1.4.0 on 50 random polynomials.

### The tests deliberately don't rest on round trips

FIPS 204 fixes the NTT's exact representation, not just its end-to-end
behaviour, so a transform that inverts itself while permuting coefficients
differently from the standard is self-consistent and interoperates with
nothing. The suite checks the table against Appendix B's printed values *and*
re-derives it by square-and-multiply (where the implementation uses repeated
multiplication), asserts X^256 = −1 directly, and checks the NTT-domain
multiply against the schoolbook convolution.

Two negative controls confirm it bites, since a test suite that cannot fail is
worth little:

- Making the transform **7 layers instead of 8** — ML-KEM's shape, which still
  round-trips perfectly — fails 4 assertions across 4 test cases.
- Storing the zetas **in Montgomery form**, which is what FIPS 204 Appendix A
  warns implementations usually do, fails 5.

13 test cases, 108,974 assertions.

## Consolidating ML-KEM into `crypto/kems`, and ML-DSA into `crypto/asyms`

A layout change, no behaviour change. `crypto/pq/` is gone.

`include/certpp/crypto/pq/mlkem.hpp` merged into
`include/certpp/crypto/kems/mlkem.hpp`, so one public header now declares
`SMlKemPoly`, `SMlKemParams`, `CMlKemSampler`, `CMlKem` and `MLKEM` — the
algorithm and its `IKem` form together. The two `.cpp` files merged to match,
since the convention is one `.cpp` per public header; `src/crypto/kems/mlkem.cpp`
is now ~1050 lines, split by a banner comment between the algorithm and the
wrapper. `mlkemsampler.cpp`, `mlkemring.*` and `mlkemcodec.*` moved alongside
it under `src/crypto/kems/`.

**ML-DSA went to `crypto/asyms/` rather than `crypto/kems/`.** The instruction
was to move everything out of `src/crypto/pq/`, and filing `mldsaring` under
`kems/` would have named a *signature* algorithm's ring after key
encapsulation — so it went where Phase 5's `mldsa.hpp` is headed, which
empties `crypto/pq/` just the same.

Knock-on changes:

- Private header guards renamed to match their new paths
  (`__SRC_CRYPTO_KEMS_MLKEMRING_HPP__`, `__SRC_CRYPTO_ASYMS_MLDSARING_HPP__`).
- Tests moved to mirror: `tests/crypto/kems/{mlkemring,mlkemcodec}.cpp` and
  `tests/crypto/asyms/mldsaring.cpp`. The ACVP vector test collided with the
  existing `IKem` test's name, so it became
  `tests/crypto/kems/kat_mlkem.cpp` — matching the `kat_rsa`/`kat_dsa`/
  `kat_ecdsa` naming already in `crypto/asyms/`.
- `CMakeLists.txt`'s private-test-sources rule no longer works off one
  directory, since those units now live in two. It builds a list from two
  conditions instead: anything under `tests/crypto/kems/` gets ML-KEM's ring
  and codec, and `crypto/asyms/mldsaring` alone gets ML-DSA's ring — scoped to
  that one test rather than to `crypto/asyms/`, which holds two dozen others
  that have no business compiling it in.

Verified by assertion count rather than just a green tick, since a silently
skipped test would also be green: all five affected executables report exactly
the totals they did before the move (kat_mlkem 2464, mlkem 232, mlkemring
1566, mlkemcodec 104056, mldsaring 108974), and the suite is 96/96.

## Post-quantum: ML-DSA's rounding and hint machinery

FIPS 204 7.4, as `MlDsaRounding` (`src/crypto/asyms/mldsarounding.hpp`):
`power2Round`, `decompose`, `highBits`/`lowBits`, `makeHint` and `useHint`,
scalar and per-polynomial. Private to `src/`, like the ring beside it.

The hint mechanism is the reason any of it exists. A signature carries one bit
per coefficient rather than w1 itself, and the verifier reconstructs
`HighBits(w − c·s2 + c·t0)` from its own approximation plus those bits — which
works only if `useHint()` inverts `makeHint()` exactly, and only while the
perturbation stays within γ₂, a bound the signing loop has to enforce before
calling it. The Python pass confirmed the bound is load-bearing rather than
decorative: outside it, the identity fails about two thirds of the time.

### A wrong assumption the validation caught

I had written, in a comment, that `decompose()`'s `(q−1)` carve-out "bites
nowhere else" than `r == q − 1`. The data said otherwise, and this is worth
recording because the mistake is an inviting one.

FIPS 204 Algorithm 36 branches on `r+ − r0 == q − 1`. That reads like a test
for the single value `q − 1`, and simplifying it to `r == q − 1` is the obvious
tidy-up. It is wrong: the condition holds across the whole top band of width
γ₂ — **95,232 values (1.14% of q)** at γ₂ = (q−1)/88, and **261,888 (3.1%)** at
(q−1)/32. Every coefficient in that band must land in bucket 0; the point
comparison would put 95,231 of them one bucket too high. Nothing but an
external vector or a bucket-range assertion would notice, since the result
stays self-consistent.

A second trap, documented in the header: `mod±` here is **not**
`MlDsaRing::centered()`. That one reduces modulo q, which is odd, so its split
sits at (q−1)/2. These reduce modulo 2^d and 2γ₂, both even, where the range is
(−m/2, m/2] and m/2 itself stays positive. Same definition (FIPS 204 2.3),
different modulus, different edge — so the unit carries its own `modPm()`
rather than reaching for the ring's. An off-by-one there misfiles one
coefficient value in every 2γ₂.

### Validated first, then tested against the traps

All five operations agreed with dilithium-py 1.4.0 over 100,000 values per
parameter set, and the inversion identity over 200,000 random (r, z) pairs per
set, before any C++ was written — which is again why it was right on the first
run.

The test does not rely on random sampling for the fragile cases. It enumerates
every bucket boundary against z = ±γ₂ and ±1, walks the carve-out band, and
checks the `r0 == 0` tie explicitly (it counts as "not positive", so a set hint
steps *down*; splitting it the other way breaks exactly the coefficients
sitting on a boundary). Two negative controls confirm the suite bites:

- Simplifying the carve-out to `rp == q − 1` fails 4 assertions across 4 cases.
- Flipping the `r0 == 0` tie to step up fails 5 across 2.

9 test cases, 1,849,585 assertions.

## Post-quantum: ML-DSA's bit packing and hint encoding

FIPS 204 7.1–7.2, as `MlDsaCodec` (`src/crypto/asyms/mldsacodec.hpp`):
`simpleBitPack`/`simpleBitUnpack` for coefficients in [0, b],
`bitPack`/`bitUnpack` for [−a, b] (encoding `b − w_i`, which is what lets an
unsigned bit field carry a signed range), and `hintBitPack`/`hintBitUnpack`.

### Decoding does not imply the range

FIPS 204 warns about this itself, in prose directly under Algorithm 17: for
some (a, b) there exist byte strings that decode to coefficients outside the
nominal range, and that is a concern for input from an untrusted source. The
Python pass worked out exactly which of ML-DSA's uses are affected, because
the answer decides where a caller must check:

| field | (a, b) | width | decodes to | safe? |
|---|---|---|---|---|
| `t1` | b = 2¹⁰−1 | 10 | [0, 1023] | yes |
| `t0` | 2¹²−1, 2¹² | 13 | [−4095, 4096] | yes |
| `z` | γ₁−1, γ₁ | 18 or 20 | exact | yes |
| `s1`/`s2`, η=2 | 2, 2 | 3 | down to **−5** | **no** |
| `s1`/`s2`, η=4 | 4, 4 | 4 | down to **−11** | **no** |
| `w1`, γ₂=(q−1)/88 | b = 43 | 6 | up to **63** | **no**, but never decoded |

So `skDecode` must range-check s1/s2 — which is why FIPS 204's own version
does — while t0/t1/z need no check at all, and w1 only ever gets encoded (it
feeds the hash; it never arrives from a peer). `inRange()` exists for the
cases that need it. Same shape of hazard as ML-KEM's `ByteDecode_12`.

### The hint decoder, and why it has three separate rejections

`hintBitUnpack` is the sharpest decode trap in the standard. It must reject on
three *distinct* conditions, each of which exists to keep the encoding
injective — and an encoding that is not injective is a signature that can be
modified without being invalidated:

1. a cumulative index that moves backwards or exceeds ω;
2. positions not strictly increasing **within one polynomial** (equal counts as
   not increasing, or one coefficient could be named twice);
3. any non-zero byte left over in the first ω after the last position read —
   without this, arbitrary data can be stuffed into the unused tail.

The scope of (2) cuts both ways, which is the part worth internalising: the
comparison resets at each polynomial boundary, so positions legitimately
*decrease* from the end of `h[i]` to the start of `h[i+1]`. An implementation
that checks monotonicity across the whole array looks stricter and is simply
broken — it rejects valid signatures.

Four negative controls, each disabling one behaviour:

| change | result |
|---|---|
| (1) cumulative-index check removed | 1 assertion fails |
| (2) strictly-increasing check removed | 2 fail |
| (3) leftover-byte check removed | 4 fail |
| (2b) monotonicity across the whole array | 2 fail, and only 6339 of 14629 assertions pass — it rejects valid input |

A rejected decode also leaves the caller's polynomials untouched rather than
half-written, since the caller is about to treat `false` as "this signature is
invalid" and a partially filled hint vector is the kind of thing that later
gets used by accident.

### Validation

Written in Python against the specification text first and cross-checked
against dilithium-py 1.4.0: packing agreed on 2400 polynomials across every
(a, b) ML-DSA uses, unpacking on 1500, and the hint round trip over 6000
random hint vectors spanning all three parameter sets' (k, ω). The byte layout
is additionally pinned in the C++ tests against hand-computed bytes, including
a 10-bit coefficient straddling a byte boundary — packing the bits big-endian
within each byte would still round-trip and interoperate with nothing.

9 test cases, 14,629 assertions; 98/98 in Debug and Release.

## Post-quantum: ML-DSA's rejection samplers

FIPS 204 7.3, as `MlDsaSampler`: `SampleInBall`, `RejNTTPoly`,
`RejBoundedPoly`, and the `ExpandA`/`ExpandS`/`ExpandMask` procedures built on
them, plus the two coefficient extractors from 7.1.

All three samplers consume a seed-dependent amount of XOF stream — that is
what rejection sampling means — so they read through `squeeze()` rather than
asking `finish()` for a fixed length. This is the second concrete consumer of
incremental squeezing, after ML-KEM's `SampleNTT`.

Three details that are invisible without an external vector:

- **The XOFs are not interchangeable.** `RejNTTPoly` and `ExpandA` use
  SHAKE128 (the standard's `G`); `SampleInBall`, `RejBoundedPoly`, `ExpandS`
  and `ExpandMask` use SHAKE256 (`H`).
- **`ExpandA`'s seed is transposed**: `rho || s || r` for `A[r][s]` — the
  *column* byte before the row byte, exactly as ML-KEM's
  `SampleNTT(rho || j || i)` is. Getting it backwards transposes the matrix
  and changes every key byte.
- **`CoeffFromHalfByte`'s two cases are not symmetric.** At η = 2 it is
  `2 − (b mod 5)` for b < 15 — fifteen inputs onto five outputs, three each —
  and at η = 4 it is `4 − b` for b < 9. Reading the first as "b < 5" would
  reject two thirds of valid inputs.

Pinned against known answers generated by a Python reference that was itself
cross-checked against dilithium-py 1.4.0, which agreed on SampleInBall, the
full ExpandA matrix and both ExpandS vectors for all three parameter sets. The
test also proves the ExpandA byte order directly rather than only through a
fingerprint, and checks that `s2[0]` differs from `s1[0]` — if ExpandS
restarted its index counter instead of continuing at `r + l`, those two would
be identical.

9 test cases, 8004 assertions.

## Portability: building on Linux/GCC, and `find_package` support

Reported from downstream — cppskit's libcskcwk consumes libcertpp as an
installed static package for P2P node-certificate authentication, and could
not build on Ubuntu 24.04 with GCC 13.3. Four distinct problems, all of which
MSVC had been hiding.

### 1. Missing `template` on a dependent member template

`TString`'s converting constructor and its cross-type `append()` both call
`cStr.convertTo<T>()` where the object's type depends on a template
parameter. Standard C++ needs `cStr.template convertTo<T>()`; without it the
`<` parses as less-than. MSVC accepts the bare form, GCC and Clang reject it,
and since `string.hpp` is included almost everywhere this failed most
translation units. The report named one site; there were two.

### 2. Temporaries bound to `SByteSpan&` (13 call sites)

`hasher->finish(SByteSpan(...))` passes a temporary to a non-const lvalue
reference, which MSVC allows as an extension and GCC/Clang reject.

Rather than name a local at each of the 13 sites, `IHasher::finish()` now
takes `const SByteSpan&`. That is the right fix rather than the expedient one:
no implementation ever reassigned the span, the sibling `SHAKE*::squeeze()` in
the same classes already took `const SByteSpan&`, and the newer APIs in this
library (`CSecure::zero`, `CMlKem`, `MlDsaCodec`) all use the const form. The
span's `data` is a `uint8_t*`, so the buffer is still writable; only
reassignment is prevented.

The distinction is principled, not blanket: `IAsymmetricContext::sign()` and
`CBase64::finish()` genuinely do truncate their span to the bytes written
(`out = SByteSpan(out.data, n)`), so those keep `SByteSpan&`.

This is an API change for anyone implementing `IHasher` outside the library —
an override's signature has to match.

It also turned out to fix more than was reported. The 13 sites in `src/` were
the ones the reporter hit, but `tests/` and `examples/` pass temporaries to
`finish()` at 7 more — invisible in their build, which had
`-DCERTPP_BUILD_TESTS=OFF -DCERTPP_BUILD_EXAMPLES=OFF`. Patching the 13 call
sites by hand would have left those broken and the next non-MSVC build would
have hit them. The signature change fixes all 20.

### 3. `uint64_t*` vs `unsigned long long*` in the ADX/BMI2 path

`_mulx_u64`/`_addcarry_u64` are declared in terms of `unsigned long long*`. On
LP64 targets `uint64_t` is `unsigned long` — a *distinct* type of the same
width — so passing `&x` is a hard error there while compiling fine on Windows,
where the two coincide. The packed 64-bit arrays and locals in
`mulAccelerated()` are now declared `unsigned long long` outright, rather than
casting the pointers, which would compile but alias one integer type as
another.

### 4. `find_package(certpp)` did not work after install

The install wrote only `certpp-targets.cmake`, and CMake looks for
`certpp-config.cmake` by name. Added that plus a `SameMajorVersion`
`certpp-config-version.cmake` via `CMakePackageConfigHelpers`. The config file
is deliberately minimal — it had a speculative `find_dependency(Threads)` in
its first draft, removed once a grep confirmed the library uses no threading
at all; the one real system dependency, `bcrypt`, is already carried in the
exported targets as `$<LINK_ONLY:bcrypt>`.

### How these were verified

Not by inspection. Clang was run with `-fno-ms-compatibility
-fno-delayed-template-parsing`, which makes it reject the same constructs GCC
does, across *every* source file in the library — it reproduced exactly the 13
rvalue-binding errors reported, found the second `template` site the report
had not, and now reports nothing. Issues 1, 2 and 4 are additionally covered
end to end: the library was configured with the reporter's exact options
(`-DCERTPP_BUILD_SHARED=OFF -DCERTPP_BUILD_TESTS=OFF
-DCERTPP_BUILD_EXAMPLES=OFF`), installed to a prefix, and consumed by a
separate project through `find_package(certpp REQUIRED)` that hashes, signs
and verifies with a P-256 node key — including a `finish(SByteSpan(...))` call
with a temporary, the exact construct that used to fail.

Issue 3 cannot be reproduced on Windows, where `uint64_t` *is* `unsigned long
long`, so it rests on the type analysis plus the existing `mul()` cross-check
test against an independent reference multiply, which exercises that path.

## Post-quantum: ML-DSA's parameter sets

`MlDsaParams` (`src/crypto/asyms/mldsaparams.hpp`) holds FIPS 204 Table 1 and
derives every length from it, the way `SMlKemParams` does — and for the same
reason, that a mistyped key or signature length stays internally consistent
and surfaces only against an external vector.

The derived figures are `static_assert`ed against FIPS 204 Table 2, so a
mismatch fails the build rather than a test run. All nine match: public keys
1312/1952/2592, private keys 2560/4032/4896, signatures 2420/3309/4627. The
test additionally re-derives each size a *second* way — by summing the parts a
key or signature is actually made of — rather than restating the formula it is
checking.

Two entries in the table do not behave the way a reader expects, and both are
asserted explicitly because an assumption either way would be silent:

- **η is not monotone in security level**: 2, 4, then back to **2** for
  ML-DSA-87. Reading it as rising gives ML-DSA-87 the wrong private-key range
  *and* the wrong `sk` length. There is a `static_assert(P87.eta < P65.eta)`
  purely to make that explicit to the next reader.
- **γ₁ is shared between two sets**: 2^17 for ML-DSA-44, 2^19 for *both*
  ML-DSA-65 and ML-DSA-87, so it cannot tell the latter two apart.

`maxSignatureBytes()` is 4627, derived from ML-DSA-87 rather than written
down — the final standard's figure, where 4595 was the initial public draft's
and still circulates.

The test also cross-checks the table against the units already built:
`highBitsRange()` must agree with `MlDsaRounding::highBitsRange(gamma2)`
computed from γ₂ alone (two independent routes to one number), every set's
`k`/`l`/`tau` must fit the samplers' own maxima, and `omega` must fit the
single byte `HintBitPack` writes it into.

## HMAC and HKDF, for a downstream link-encryption handshake

Requested downstream: cppskit's libcskcwk needs to encrypt node-to-node mesh
links. libcertpp already had the key agreement (X25519) and the ciphers; what
was missing was a KDF and an AEAD. This is the KDF half.

`CHmac` (`crypto/hmac.hpp`) implements RFC 2104 over any of this library's
fixed-output hashers, with the streaming shape `IHasher` uses — `reset()` to
key it, `push()`, `finish()` — and a one-shot `compute()`. Re-keying an
existing instance reuses the underlying hasher, so HKDF's expand loop does not
allocate per output block.

`CHkdf` (`crypto/hkdf.hpp`) implements RFC 5869 as three entry points:
`extract()`, `expand()` and `derive()` for the two together. A concrete
utility rather than one implementation of an `IKdf` family, following `CRng`'s
precedent — HKDF's two-step shape does not generalize to a password-based KDF
(salt plus iteration count, no `info`) without an interface that fits neither
well, so introducing one now would be speculative.

### Two decisions worth recording

**`verify()` exists so callers don't reach for `memcmp`.** A MAC comparison
that stops at the first differing byte tells an attacker how long a prefix
they guessed, which is enough to forge a tag a byte at a time. `CHmac::verify`
goes through `CSecure::equalsMask` and also handles RFC 2104 4's truncated
tags, comparing only the bytes the caller presented.

**The block sizes live in `CHmac`, not on `IHasher`.** HMAC needs the hash's
block size (64, 128, or the SHA-3 rate) and `IHasher` exposes only
`byteWidth()`. Putting it on the interface would mean changing `IHasher`'s
constructor and all ten implementations — a second API change in a row for the
downstream consumer who had just absorbed `finish()`'s `const`. The cost of
keeping it local is that a hasher added later is unsupported by HMAC until
someone extends `blockBytesOf()`, which fails loudly at `reset()` rather than
silently computing a wrong tag. If a second consumer ever needs the block
size, it should move onto `IHasher` rather than be duplicated.

SHAKE128/SHAKE256 are refused: they are XOFs with a caller-chosen output
length, and RFC 2104 is defined over a fixed-output hash. SHA3-256/512 are
accepted using their sponge rate, though KMAC is what NIST actually recommends
for SHA-3.

### The tests found my own transcription errors, twice

Both suites failed on the first run, and in both cases the implementation was
right and the test data was wrong. Worth recording because the way it was
diagnosed matters more than the typos:

- **HMAC**: one of fifteen transcribed vectors (RFC 4231 case 4, SHA-512) was
  wrong. Rather than guess, every vector was checked against Python's `hmac`
  module — 14 matched, which located the error immediately and proved the C++
  correct.
- **HKDF**: three of six Appendix A cases failed, and the pattern was the
  clue — A.2, A.4 and A.5 passed while A.1, A.3 and A.6 failed, and those
  three share one input. The IKM had been written as 21 octets of `0x0b` where
  RFC 5869 specifies **22**. The expected values were correct all along; the
  input was a byte short. Testing 21, 22 and 23 octets against the RFC's
  published PRK confirmed it in one step.

Had the expected values been generated from this implementation instead of
transcribed, both errors would have been invisible — which is the whole
argument for external vectors.

RFC 4231's seven cases across SHA-1/256/384/512 and all six of RFC 5869's
Appendix A cases now pass, each checked through the one-shot path, the
streaming path at four different chunk sizes, and a single-bit tamper at every
tag position.

## ChaCha20-Poly1305 AEAD, for downstream link encryption

The other half of libcskcwk's request. With HMAC/HKDF already in, this
completes what it needs to encrypt node-to-node mesh records: X25519 for the
agreement, HKDF to split the shared secret per direction, and an authenticated
cipher per record.

- `CPoly1305` (`crypto/poly1305.hpp`) — RFC 8439 2.5.
- `CChaCha20Poly1305` (`crypto/aeads/chacha20poly1305.hpp`) — RFC 8439 2.8.
- `ChaCha20Core` extracted from `crypto/syms/chacha20.cpp` into its own private
  unit, the way `DesCore` and `KeccakCore` already were.

### Why the core had to be extracted

The AEAD needs the ChaCha20 block function at two *different* counters, and
`ISymmetric` cannot express either: counter 0, whose first 32 bytes are the
one-time Poly1305 key (RFC 8439 2.6), and counter 1 onward for the payload,
because block 0 is spent on that key. The stream cipher always starts at 0, so
reusing it through the public interface was not an option and duplicating the
block function would have been worse.

### What the API guarantees, and why

The request asked for in-place operation, a reusable context, and a
constant-time `open`. All three are in, and one of them has a consequence
worth spelling out:

**`open()` verifies before it writes a single plaintext byte.** The tag covers
the ciphertext, so it can be checked while the input is still intact — and
because `out` may alias `in`, the obvious decrypt-then-verify order would
overwrite the caller's only copy of the ciphertext with unauthenticated
plaintext *before* noticing the forgery. A failed `open()` therefore leaves the
buffer exactly as it was, which the test asserts for every single-bit tag
change (128 of them) and every single-byte ciphertext change.

The tag comparison goes through `CSecure::equalsMask`, not `memcmp`: a
comparison that stops at the first difference reveals how much of a forged tag
was right, which is enough to construct one byte by byte.

`CPoly1305::finish()` deliberately *consumes* the state rather than being a
repeatable query like `IHasher::finish()`. Poly1305 is a one-time MAC — two
messages under one key let an attacker solve for `r` and forge at will — so
leaving the instance usable would invite exactly the misuse that breaks it. It
also does not implement any shared MAC interface alongside HMAC: HMAC is keyed
and reusable, this is neither, and letting the two be swapped behind one
interface would make that difference invisible at the call site.

`padToBlock()` exists as its own operation because RFC 8439 2.8's `pad16`
closes a partial block rather than extending the message. Pushing zeros
instead would be indistinguishable from the field itself ending in zeros, and
keeping the AEAD's four fields from running into one another is the entire
point of the padding.

### Verified against the RFC at every published step

A round trip proves almost nothing here: each of the likely errors is
self-consistent. So the test checks RFC 8439 2.5.2 (Poly1305), 2.6.2 (the
one-time key derivation) and 2.8.2 (the full AEAD) — the intermediate vector
included, not just the end-to-end one.

Four negative controls, each confirming the vectors bite:

| change | result |
|---|---|
| keystream from counter 0 instead of 1 | 3 assertions fail |
| MAC length-footer fields swapped | 2 fail |
| `pad16` between aad and ciphertext omitted | 2 fail |
| Poly1305's `r` clamping weakened by one mask | 4 fail |

Every one of those produces output that seals and opens perfectly against
itself; only the RFC's bytes catch them.

The suite also includes an integration case shaped like cskcwk's actual
protocol — one context per direction over HKDF-derived keys, a 4-byte prefix
plus 64-bit counter nonce, eight records sealed in place — asserting that every
record's ciphertext and tag differ, that a record replayed under the wrong
counter is rejected, and that the opposite direction's key cannot open it.

All six new/changed units were additionally checked with Clang under
`-fno-ms-compatibility`, so they do not repeat the portability breakage fixed
in `d297767`.

## XChaCha20-Poly1305, so nonces can be random

The AEAD above needs a nonce that never repeats under one key, and 96 bits is
too short to get that by picking at random: a birthday collision becomes likely
after roughly 2^48 records, so the nonce has to be a counter, and a counter has
to survive restarts and not be shared between senders. XChaCha20-Poly1305
(draft-irtf-cfrg-xchacha, the variant WireGuard and libsodium use) takes a
192-bit nonce, which is long enough that random nonces are safe for any
realistic record count — so a key can be used by parties that cannot coordinate
a counter at all.

- `ChaCha20Core::hchacha20()` — the draft's nonce-extension function.
- `CXChaCha20Poly1305` (`crypto/aeads/xchacha20poly1305.hpp`) — the AEAD, as a
  wrapper: `subkey = HChaCha20(key, nonce[0:16])`, then `CChaCha20Poly1305`
  under that subkey with the 96-bit nonce `00000000 || nonce[16:24]`.

It delegates rather than reimplementing RFC 8439 2.8, so the in-place aliasing,
the counter-1 start, the MAC field order and the constant-time
verify-before-write are the existing AEAD's, inherited rather than restated.
The subkey depends on the nonce, so a reused context can cache nothing; it goes
in a stack struct that keys a stack `CChaCha20Poly1305` and zeroes itself in its
destructor, which keeps the no-per-call-allocation contract without a `mutable`
member or a non-const `seal()`.

### HChaCha20 is not the block function

It shares the twenty rounds, which is why it lives in `ChaCha20Core`, and
differs in two ways that each produce something *self-consistent* if got wrong:
the 128-bit nonce fills words 12–15 (there is no counter), and there is **no
feed-forward** — the rounds' output is emitted as-is, words 0–3 then 12–15.
Reusing `block()` verbatim yields a subkey that round-trips perfectly against
itself and agrees with no other implementation.

The whole construction was written in Python first and checked against the
draft's vectors before any C++ existed — 2.2.1 (HChaCha20), A.3.1 (the AEAD),
and A.3.2.2 (the XChaCha20 stream at counter 1, which pins the inner nonce
independently of the MAC).

### Negative controls

| change | result |
|---|---|
| feed-forward added back into HChaCha20 | 5 test cases fail |
| subkey taken as output words 0–7 instead of 0–3 ‖ 12–15 | 5 fail |
| inner nonce built as `nonce[16:24] ‖ 00000000` | 3 fail |
| `open()` forced to return true | 2 fail (incl. the tampered-AAD case) |

The third is the instructive one: the subkey is identical either way, so the
HChaCha20 vectors still pass and only the AEAD ciphertexts catch it. That is why
the test checks the subkey separately from the ciphertext rather than only end
to end — when the end-to-end vector fails, the subkey assertion says which half
is wrong.

## Fe25519: a constant-time field for X25519

Raised downstream alongside the AEAD request: X25519's own test comments note
that the big-number arithmetic underneath it is not constant-time, which for an
online handshake with ephemeral keys is a live side channel rather than a
theoretical one. This is the substrate for fixing it; the ladder rewrite
follows.

`Fe25519` (`src/crypto/asyms/fe25519.hpp`) implements GF(2^255 − 19) in ten
signed limbs at radix 2^25.5, with no data-dependent branches, memory indices
or divisions.

### Why `CBigNum` cannot be made to do this

`CBigNum` stores a *canonical* limb array — leading zero limbs are trimmed —
so the number of limbs, and therefore the work done, depends on the value.
Every add, multiply and reduction over it leaks something about its operands
through timing. For certificate verification that is tolerable; for a
handshake it is not. `Fe25519`'s limb count is fixed at ten regardless of the
value.

`CBigNum::condSwap` is the sharpest example: its own documentation admits it
is a plain branch. In a Montgomery ladder the swap condition *is* a bit of the
private scalar, so that branch leaks the key one bit per iteration.

### Why radix 2^25.5 and not 2^51

A 51-bit radix is the faster layout and what most 64-bit implementations use,
but its products need 128-bit arithmetic and **MSVC has no `__int128`**. With
alternating 26- and 25-bit limbs every product fits `int64_t`: the worst-case
multiply accumulator is 10 × (2^26−1)² × 38 = **2^60**, three bits of headroom,
and the test asserts that bound so a future change to the radix cannot
silently overflow it.

Limbs are *signed*, which is load-bearing rather than incidental: `sub()` then
needs no borrow handling, since a limb simply goes negative and the next carry
pass propagates it through an arithmetic shift. Unsigned limbs would require
either adding a multiple of p before every subtraction or branching on the
sign — and the second is exactly what this class exists to avoid.

### The error the Python pass caught

Validated against exact arithmetic before any C++ was written, and the first
version of the multiply was wrong on **every** input. Because the radix is not
a whole number of bits, `OFFSET[i] + OFFSET[j]` is one bit above
`OFFSET[i+j]` whenever *both* indices are odd — two half-bit offsets adding to
a whole one. I had applied that doubling only to the products that wrap past
2^255, where it is also needed, and not to the rest. Exact arithmetic found it
in one run; a round-trip test never would have, since a packer and unpacker
consistently wrong in the same way agree with each other.

### Testing

`CBigNum` is the oracle — heavily tested, shares no code with this unit, and
exact. `add`/`sub`/`mul`/`square`/`mulA24`/`invert` are checked against it over
3000 random pairs, plus **every pair of ten edge values** (0, 1, 2, 19, 38,
p−1, p−2, 2^254, 2^128, (p−1)/2), where the carry chain and the 19× wrap are
most strained and where random sampling essentially never lands.

Two cases are checked specifically because they survive a round trip:

- `toBytes()`'s conditional subtraction of p only matters for values in
  [p, 2^255), which decode back to the same element either way. The test feeds
  unreduced representatives directly and requires the canonical bytes.
- `invert()` is checked by `x · x⁻¹ == 1` rather than against a reference
  inverse, so a wrong addition chain cannot agree with itself by construction —
  and then against `CBigNum::modInverse` as well.

7 test cases, 32,468 assertions. Checked under Clang with
`-fno-ms-compatibility` so it does not repeat the portability breakage fixed in
`d297767`.

## X25519: a constant-time ladder, and 5-7x faster as a side effect

`Curve25519`'s Montgomery ladder now runs on `Fe25519` instead of `CBigNum`,
which closes the timing channel a downstream consumer reported. Nothing in
`x25519.cpp` touches `CBigNum` any more, so there is no path by which a secret
scalar reaches variable-time arithmetic.

What changed, beyond swapping the field type:

- **The scalar bit is read from the bytes directly**, not through
  `CBigNum::testBit()`, whose cost depends on the value's limb count.
- **The conditional exchange is `Fe25519::condSwap` under an arithmetic mask**,
  replacing `CBigNum::condSwap`, which its own documentation admits is a plain
  branch. In a ladder that condition *is* a bit of the private scalar.
- **Clamping produces bytes, not a `CBigNum`**, and `scalarMult()` clears its
  clamped copy before returning.
- **`checkPrivateKey()`'s cofactor check calls `ladder()` rather than
  `scalarMult()`**, deliberately: its scalar is the small public constant 8 and
  must *not* be clamped, since clamping would turn it into a different scalar.
  That distinction was implicit before, when the check passed a raw `CBigNum`;
  it is now a visible difference between two named entry points.

One check became structural rather than tested. The old code verified the
derived u-coordinate was canonically reduced (`u >= p` rejected);
`Fe25519::toBytes()` emits the canonical representative in [0, p) by
construction, so that can no longer fail. The bit-255 mask is asserted in its
place, since that is the one thing a 32-byte encoding could still carry.

### The measured effect

Not the point of the change, but worth recording, because `CBigNum` was
allocating per operation and reducing against a runtime-computed prime:

| | before | after |
|---|---|---|
| `generateKeyPair` | 4.7 ms | **0.907 ms** |
| `deriveSharedSecret` | 2.0 ms | **0.287 ms** |

All 12 X25519 test cases and 4217 assertions pass unchanged, RFC 7748's
vectors included — which is the check that matters, since a ladder that is
subtly wrong still produces consistent key agreement between two copies of
itself.

Still short of the 100 µs/operation the consumer asked for. Two causes are
identified and not yet addressed: `Fe25519::mul` carries two branches per
partial product inside a 10x10 loop that the compiler is unlikely to unroll,
and `generateKeyPair` runs three ladders (one to derive the public key, then
`checkPrivateKey` recomputing it plus the cofactor check) where it already has
the first result in hand.

## Performance pass, driven by a downstream report with numbers

cppskit's libcskcwk reported concrete figures and targets for the link-
encryption path. This records what moved, what did not, and the one place the
target turns out to be unreachable without work the report did not anticipate.

| | reported | now | target |
|---|---|---|---|
| X25519 `generateKeyPair` | 4.7 ms | **333 µs** | ≤100 µs |
| X25519 `deriveSharedSecret` | 2.0 ms | **167 µs** | ≤100 µs |
| AEAD seal, 64 KiB | ~300 MiB/s | 331 MiB/s | ≥1.5 GiB/s |
| AEAD seal, 64 B | 507 ns | ~440 ns | ≤150 ns |

### Where the AEAD time actually goes

Isolated by subtraction, at 64 KiB: Poly1305 60.6 µs, ChaCha20 128.4 µs. So
the report's diagnosis was right that ChaCha20 dominates — but the arithmetic
has a consequence it did not reach:

- ChaCha20: **487 MiB/s**, about 5.9 cycles/byte.
- Poly1305: **1032 MiB/s**, about 2.8 cycles/byte.

2.8 cycles/byte is roughly what a scalar 26-bit-limb Poly1305 should cost, so
the MAC is already near its ceiling for this representation — and since the two
compose as `1/total = 1/cipher + 1/mac`, **Poly1305 alone caps the AEAD at
1032 MiB/s no matter how fast the cipher gets.** Reaching 1.5 GiB/s needs
*both*: with the MAC at 3 GiB/s the cipher must reach 3 GiB/s; with the MAC at
2 GiB/s the cipher must reach 6. That means SIMD on both sides, or Poly1305 in
64-bit limbs via `_umul128`. Worth knowing before anyone spends a week on
ChaCha20 alone and lands at 1 GiB/s.

### What was done

**ChaCha20: prepared state, word-wise XOR.** The block function took the key
and nonce per call, so it re-parsed eleven little-endian words for every 64
bytes; `ChaCha20Core::SState` now hoists that to once per message.
`xorStream()` combines whole blocks 32 bits at a time instead of byte by byte,
and the `ISymmetric` transformer routes its block-aligned bulk through it while
keeping its cross-call cursor for the edges. Measured: 286 → 331 MiB/s.

That is a smaller gain than the change suggests, and the reason is the useful
part: neither the state setup nor the byte-wise XOR was dominant — **the twenty
rounds are**, at ~376 cycles per block. Further cipher gains need SIMD, not
bookkeeping.

**Fe25519: unrolled multiply.** The 10x10 loop carried two branches per
partial product (the odd/odd doubling and the wrap). Pre-scaling the operands
folds both constants out, leaving pure multiply-accumulate — and the expression
was *generated* from the same rule the Python reference validated, rather than
hand-typed, so the 100 terms cannot drift from it. Measured: derive 287 → 167 µs.

**X25519 keygen: one derivation instead of two.** `generateKeyPair` derived the
public key, then called `checkPrivateKey()`, which derived it again purely to
compare against the value just computed. The three validity checks moved into a
shared `validatePublicValue()` that both paths call, so nothing is weakened —
the comparison that was dropped was between a value and itself. Measured:
540 → 333 µs, consistent with three ladders becoming two.

### What was tried and reverted

`carryPass()` was unrolled with literal shift amounts, on the theory that
`widthOf(i)`'s modulo was costing something across the ~50,000 calls a ladder
makes. It made **no** difference, inside a run-to-run spread of about 11% —
`widthOf()` is `constexpr` and the bound is fixed, so the compiler was already
doing it. The loop is back, with the negative result recorded in a comment so
nobody repeats it.

A dedicated squaring was *not* written, deliberately. It would halve the
partial products of the four squarings per ladder iteration — perhaps 30% — but
it is a second 100-term expression with its own doubling rules interacting with
the radix's, and the ladder would still agree with itself if it were wrong.
Left until the gain can be attributed rather than assumed.

### What remains for 100 µs

derive is 1.7x off. The dominant remaining cost is that a 2^25.5 radix needs
**100** limb multiplies, where a 2^51 radix needs 25 — that is the real 4x, and
it is why 64-bit implementations use it. It needs 128-bit products, which MSVC
can do via `_umul128` even without `__int128`. With that plus a squaring,
100 µs is comfortably reachable; without it, it is not.

## AES-GCM and unpadded CBC, for an IKEv2 consumer

An IKEv2 implementation needs the two transforms RFC 7296/4106/5282 actually
negotiate: AES-GCM as an AEAD, and AES-CBC over a payload the protocol has
already padded itself.

- `CAesGcm` (`crypto/aeads/aesgcm.hpp`) — NIST SP 800-38D, AES-128/192/256, a
  96-bit IV, and a 96- to 128-bit tag. Its API matches
  `CChaCha20Poly1305`'s deliberately: the same consumer picks one or the other
  by negotiation and should not have to restructure around the choice.
- `Ghash` (`src/crypto/aeads/ghash.hpp`) — GHASH and GCM's `GF(2^128)`, private
  to `src/`.
- `AesCore` extracted from `crypto/syms/aes.cpp` into its own private unit, the
  way `DesCore` and `ChaCha20Core` already were.
- `ESymPaddings` on `ISymmetricContext` — `ESYMPAD_PKCS7` (the default,
  unchanged) or `ESYMPAD_NONE`.

### Why GHASH is not `CGf2m`

`CGf2m` already multiplies in `GF(2^m)` with a PCLMULQDQ path, and GHASH's
modulus `x^128 + x^7 + x^2 + x + 1` would even fit its pentanomial
`SGf2mField`. It was still the wrong tool, for three independent reasons, and
the first is the one that matters:

**GCM's field is bit-reflected.** The most significant bit of a block's first
byte is the `x^0` coefficient (SP 800-38D 6.3) — the opposite of the
polynomial-basis convention `CGf2m` and the rest of this library use. Handing
`CGf2m` the bytes as they arrive produces a product that is commutative,
associative, distributive and perfectly self-consistent, and is not GHASH.
Nothing but a published vector catches that, which is this repository's
recurring failure mode (the transposed SHA-3 rotation table, the transcribed
P-521 digits, the ChaCha20 vector path no RFC vector was long enough to reach).

The other two: `H` is secret, so the multiply has to be constant-time, and
`CGf2m` documents that it is not hardened at all — the right trade for ECDSA's
public curve arithmetic, the wrong one for a MAC key. And `CGf2m` carries nine
limbs through a generic pentanomial reduction over an eighteen-limb product,
where GHASH is two 64-bit words with one fixed modulus, once per 16 bytes.

### Python first, then C++

SP 800-38D was implemented in Python — AES included, so nothing was taken on
trust — and checked against the GCM specification's Appendix B test cases
before a line of C++ was written. All twelve of the cases that use a 96-bit IV
(1–4, 7–10, 13–16: three key sizes, an empty plaintext, an empty AAD, and a
60-byte plaintext with a 20-byte AAD) matched, including each case's published
subkey `H`. The same script also confirmed that those vectors *can* see each
error class before relying on them to. The C++ then passed all twelve on its
first run.

### The accelerated path does not use the reflected convention

The textbook PCLMULQDQ GHASH multiplies in GCM's own reflected representation,
which needs a shift-by-one across the 256-bit product plus a reduction whose
constants (`slli_epi32` by 31, 30, 25, then 1, 2, 7) are easy to transcribe and
impossible to check by eye. This one instead converts both operands out of the
reflected convention with twelve SSE2 instructions — reversing the bits within
each byte, which is the whole of the conversion, since little-endian byte order
is what a load already gives — multiplies in the ordinary one, where the
reduction is the textbook `x^128 = x^7 + x^2 + x + 1` (`0x87`), and converts the
product back. Slower in principle than the mirrored form; derivable on paper,
which was worth more.

Published vectors cannot tell the two paths apart: the dispatch is a runtime
CPUID check, so whichever one this CPU takes is the only one they ever reach.
`tests/crypto/aeads/ghash.cpp` therefore compares them directly over 2048
random operand pairs plus every single-bit block, and pins the bit order down
with the field identities — in GCM's order the multiplicative identity is the
block `80 00 … 00`, so `X ⊗ 80 00 … 00 == X` fails for any unreflected
multiply however self-consistent it is elsewhere. `Ghash` has no public header
and no `CERTPP_API`, so that test compiles `ghash.cpp` into itself through
`CERTPP_TEST_PRIVATE_SOURCES`.

### Negative controls

Each was introduced, built, and confirmed to fail a test before being reverted:

| break | caught by |
| --- | --- |
| payload counter starts at `J0`, not `J0 + 1` | `aesgcm` (the Appendix B ciphertexts) |
| length block in bytes, not bits | `aesgcm` |
| length block little-endian, not big-endian | `aesgcm` |
| reflection dropped in the portable multiply | `ghash` (identity + differential) |
| reflection dropped in the PCLMULQDQ multiply | `ghash` *and* `aesgcm` |
| AAD left out of the hash | `aesgcm` (the tampered-AAD subcase) |

The le64-vs-be64 one is worth noting: ChaCha20-Poly1305's otherwise analogous
length footer is little-endian (RFC 8439 2.8), and GCM's is big-endian. Two
AEADs in one directory with the same-shaped footer and opposite endianness is
exactly the kind of neighbour that invites a copy.

### Unpadded CBC, without changing what already worked

`CbcTransformer` always padded, and the SP 800-38A tests plus every other
caller depend on that, so `ESYMPAD_NONE` is an opt-in rather than a change of
default. Unpadded, nothing is held back and nothing is stripped: every whole
block is emitted as it completes, and `transformFinal()` returns `ERET_BADREQ`
on a partial block rather than quietly rounding the length up.

`padding()` is deliberately *not* cleared by `reset()` or `key()`, unlike the
key, IV and block size. It is a mode choice, not key material, and clearing it
would make `padding(ESYMPAD_NONE)` followed by `key(...)` silently revert to
PKCS#7 — a very quiet way to emit a ciphertext the peer rejects.

A side benefit: unpadded CBC is the first thing in this library that can be
held against SP 800-38A F.2's *four-block* CBC vector. Padded CBC appends a
fifth all-16s block, so until now only the single-block, all-zero-IV reduction
of F.2 was checked, which exercises no chaining at all.

## GOST R 34.11-2012 (Streebog) and GOST R 34.10-2012

Added the Russian federal hash and signature standards, as new `IHasher` and
`IAsymmetric` implementations. The algorithms only; nothing in `x509/` knows
about them yet (see "What X.509 wiring would still need" below).

### Streebog (`EHASH_STREEBOG256` / `EHASH_STREEBOG512`)

`Streebog256`/`Streebog512` (RFC 6986), sharing `StreebogCore` under `src/` the
way SHA-384/SHA-512 share `Sha2_64Core`: the core owns the round function `g_N`
and the mod-2^512 accumulators, each digest owns its own context, IV, padding
and output slice.

**Byte order was the whole problem, and it is settled by evidence rather than
by reading.** RFC 6986 numbers a `V_512` vector's bytes from the *right*
starting at zero and prints vectors most-significant-byte-first, so its example
messages and its hash codes are both written backwards relative to a byte
stream. Two independent confirmations, both checked in Python before any C++
was written:

- The RFC's example 2 hex decodes to readable CP1251 Russian text (a line of
  "The Tale of Igor's Campaign") only when read right to left, and its example
  1 is then the ASCII string `012345678901...012`.
- Streebog-512 of that ASCII string is a widely published digest, and it equals
  the RFC's own `H(M1)` **reversed, byte for byte**.

So the implementation indexes every 64-byte buffer by the spec's own byte
position -- index 0 is `a_0`, which is also the first byte of a message block.
Message bytes then stream straight in at increasing indices, the digest comes
out in the order every other implementation uses, and `MSB_256` becomes the
*upper* half of the final state (indices 32..63), not the leading one.

Two more things that bite:

- **The 256-bit digest is not a truncation.** RFC 6986 section 6.1 gives it
  `IV = (00000001)^64` where the 512-bit function gets `0^512`, so the two
  diverge from the first block. Using the wrong IV yields a perfectly
  self-consistent, universally wrong hash.
- **A message whose length is an exact multiple of 64 bytes still gets a
  padded, entirely empty final block**, because step 2.1's loop exits on
  `|M| < 512` and `|M| == 0` satisfies that. **No vector in RFC 6986 reaches
  this case** -- the same shape of gap as the ChaCha20 vector path that passed
  every published vector because they were all too short. The vector that does
  reach it came from RFC 9385 appendix A.1.1: `SKEYSEED =
  HMAC_GOSTR3411_2012_512(Ni | Nr, K)` has a 64-byte key and 64-byte data, so
  both the inner and the outer hash see exactly 128 bytes. It doubles as the
  check that `CHmac::blockBytesOf()` reports `B = 64` (RFC 7836 4.1.1/4.1.2)
  rather than copying SHA-512's 128.

**The constant tables were generated, not typed.** `Pi'`, the 64 rows of the
matrix `A` and the twelve `C[i]` are parsed out of `rfc6986.txt` by the Python
reference and emitted as C++ source text, so no transcription step exists to go
wrong. `Tau` isn't stored at all: `transformLps()` uses the identity
`Tau(8w + t) == w + 8t`, which `tests/crypto/hashers/streebogcore.cpp`
transcribes `Tau` independently to check. The 16 KiB combined S/P/L lookup
table is *derived* from `Pi'` and `A` at first use, and the same test compares
it against a deliberately slow, literal three-pass reading of section 7 on
pseudorandom states -- otherwise nothing would be checking the table's
derivation rather than merely its self-consistency.

### GOST R 34.10-2012 (`CGost3410`)

`CGost3410` (RFC 7091) over nine parameter sets, all added to `EEcKnownCurves`
/`EAsymmetrics` so the existing `CEcCurve` group arithmetic backs them:

| Identifier | Parameter set | Source |
| --- | --- | --- |
| `ECURVE_GOST256TEST` | `id-GostR3410-2001-TestParamSet` | RFC 7091 7.1 (= RFC 4357 11.4) |
| `ECURVE_GOST256A` | `id-tc26-gost-3410-2012-256-paramSetA` | RFC 7836 A.2 |
| `ECURVE_GOST256B` | `...-256-paramSetB` (= CryptoPro-A) | RFC 4357 11.4, per RFC 9215 C |
| `ECURVE_GOST256C` | `...-256-paramSetC` (= CryptoPro-B) | RFC 4357 11.4, per RFC 9215 C |
| `ECURVE_GOST256D` | `...-256-paramSetD` (= CryptoPro-C) | RFC 4357 11.4, per RFC 9215 C |
| `ECURVE_GOST512TEST` | `id-tc26-gost-3410-2012-512-paramSetTest` | RFC 9215 E |
| `ECURVE_GOST512A` | `id-tc26-gost-3410-12-512-paramSetA` | RFC 7836 A.1 |
| `ECURVE_GOST512B` | `id-tc26-gost-3410-12-512-paramSetB` | RFC 7836 A.1 |
| `ECURVE_GOST512C` | `id-tc26-gost-3410-2012-512-paramSetC` | RFC 7836 A.2 |

Every one was parsed out of the RFC text by script and then checked -- base
point on the curve, `q*P == O`, non-singular discriminant -- before being
emitted as the hex literals in `eccurve.cpp`. RFC 4357's
`GostR3410-2001-ParamSetParameters` orders its integers `a, b, p, q, x, y`
(section 10.9), which is worth knowing because reading them as `p, a, b, ...`
produces a plausible-looking curve. `XchA`/`XchB` are omitted: RFC 9215
appendix C says they are the same curves as CryptoPro-A and CryptoPro-C.

Two of the sets have **cofactor 4**, not 1. That makes `decodePoint()`'s and
`checkPrivateKey()`'s order-`q` subgroup check genuinely load-bearing for the
first time in this library -- for every curve shipped before, a point on the
curve was necessarily in the subgroup, and the check's own comment said so.

**It is not ECDSA with a different curve.** `s = (r*d + k*e) mod q`, with no
inversion of `k`; verification inverts the *hash* (`v = e^-1`) rather than `s`;
and `e` comes from the hash by GOST's own rule, which given a Streebog digest
in stream order means reading it **little-endian** -- not ECDSA's leftmost-bits
big-endian truncation. An `e` of zero becomes 1 rather than being left alone.
Reusing `CEcdsa`'s arithmetic would have produced signatures that verify
against themselves and nothing else.

**Serialization byte order is where "works against itself" hides**, so it was
determined empirically from RFC 9215's appendix D certificates *before* being
matched against that document's normative text (sections 2.3/2.4 -- they
agree):

- Public keys: `x || y`, each fixed-width **little-endian** (64 or 128 bytes).
- Signatures: `s || r`, each fixed-width **big-endian**, `s` first, no DER
  `SEQUENCE` wrapper.

The two halves of a signature are big-endian while the two halves of a public
key are little-endian. That is GOST's, not a mistake, and both are commented at
the point of use.

Private keys serialize as `d` alone, little-endian, matching the public key's
coordinate order; `createPrivateKey()` re-derives `Q = d*P` rather than
carrying it, which makes a mismatched pair impossible to import. RFC 9215
defines no private-key encoding to match here.

### Validation

Everything was implemented and checked in Python against published vectors
before any C++ existed, and the C++ tests use the values that reference
emitted:

- RFC 6986's four example digests (two messages x two lengths), plus the
  published empty-message and ASCII-string digests as the independent
  orientation check.
- RFC 9385 appendix A.1.1's `SKEYSEED`, for the exact-block-multiple case, and
  its step (4) public key, which independently re-derives `paramSetC`'s
  generator.
- RFC 7091 section 7's `(r, s)` -- the only published signature pair for the
  scheme, and the only thing that can catch a wrong verification equation or a
  swapped signature half, since the nonce is random and a round trip would
  agree with itself either way.
- RFC 9215 appendix D's three test certificates, verified end to end: Streebog
  over the real `tbsCertificate` bytes, then GOST R 34.10 against the
  certificate's own embedded public key. Three parameter sets, both digest
  lengths, every byte off the wire.

Negative controls, each introduced, rebuilt, confirmed failing, and reverted:
the 512-bit IV for the 256-bit digest (caught); reversed message-block byte
order (caught); reversed digest output order and `MSB_256` taken from the wrong
half (both caught); `verify()` reading `r || s` instead of `s || r` (caught);
and `verify()` returning `ERET_OK` unconditionally, which fired every one of
the wrong-key, tampered-message, tampered-signature, swapped-half,
reversed-digest and wrong-length assertions -- i.e. those negatives have teeth
rather than passing vacuously.

### What X.509 wiring would still need

Deliberately out of scope here. For the record, it is OIDs and encodings, not
algorithms:

- `id-tc26-signwithdigest-gost3410-12-256` (1.2.643.7.1.1.3.2) and `-512`
  (1.2.643.7.1.1.3.3) in `CCert`'s signature-algorithm tables, with the
  `parameters` field **omitted** (RFC 9215 section 2).
- `id-tc26-gost3410-12-256` / `-512` as `SubjectPublicKeyInfo` algorithms, whose
  `parameters` is a `SEQUENCE { publicKeyParamSet OID, digestParamSet OID
  OPTIONAL }` -- so the parameter set comes from the AlgorithmIdentifier, which
  means mapping each `ECURVE_GOST*` to its OID and back. The key bits are a BIT
  STRING *encapsulating an OCTET STRING*, unlike every other key this library
  parses.
- The signature value is the raw 64/128-byte `s || r` blob, not a DER
  `SEQUENCE { r, s }`, so `CCert::verifyBy()`'s path would need to stop
  assuming the ECDSA shape for these.
- DNSSEC (RFC 9558) would additionally need the DNSKEY/RRSIG wire formats,
  which differ again from the X.509 ones.

## A `dnssec` module, and what its vectors could not see

DNSSEC shares none of X.509's encodings, which is the whole reason this is a
separate module rather than a corner of `x509`. A certificate carries a public
key as a `SubjectPublicKeyInfo` and an ECDSA signature as a DER
`SEQUENCE { r, s }`; DNSSEC writes the bare key material and the bare
concatenation `r | s`. So a DNSKEY cannot be handed to
`IAsymmetric::createPublicKey()` and an RRSIG signature cannot be handed to
`verify()` -- something has to re-encode in between, and `CDnssecKeys` is that
something.

Per algorithm: RSA (RFC 3110) writes an exponent length, the exponent, then the
modulus, where this library wants `SEQUENCE { INTEGER modulus, INTEGER
exponent }` -- the two operands appear in opposite order, so getting it
backwards produces a key whose modulus is 3. ECDSA (RFC 6605) writes `x | y`,
which is the SEC1 uncompressed point less its `0x04` prefix. EdDSA (RFC 8080)
is already in the right form and is handled by an explicit case rather than a
default, so an algorithm nobody has implemented is rejected instead of being
silently treated as raw.

The signature direction has one step that cannot be skipped: a DER `INTEGER`
carries no leading zero octets, so writing `r` and `s` back out without
left-padding each to the curve's field size shifts `s` left by however many
octets `r` was short. RFC 6605 section 2 requires a fixed width. The test for
it constructs a signature with leading zeros in both halves *and* a trailing
zero, since a round trip over values that happen to be full-width proves
nothing.

### Two gaps the negative controls found in the vector set itself

Eight published examples went in -- RFC 6605 6.1/6.2, RFC 8080's four EdDSA
examples, RFC 5702's two RSA ones -- reproducing every key tag (55648, 10771,
3613, 35217, 9713, 38353, 9033, 3740) and every DS digest. They are strong
vectors because the key tag and the DS digest are both taken over the *whole*
RDATA, so no error in field order, field width or owner-name canonicalisation
survives them.

But two deliberate breakages did survive, which is the point of trying them:

- **Byte-swapping the flags field changed nothing.** Every ECDSA and EdDSA
  example uses flags 257, and 257 is `0x0101` -- identical in either byte
  order. Six of the eight vectors cannot constrain the flags field's endianness
  at all. RFC 5702's RSA examples use 256 (`0x0100`) and can, which is why they
  are in the suite even though they publish no DS record to check.
- **The case-folding test was vacuous.** It uppercased an owner name before
  passing it to a helper that folds internally, so it compared the canonical
  form against itself. It now compares against a non-folding spelling, which is
  what actually demonstrates that the folding is load-bearing for the DS
  digest.

### RFC 4034 Appendix B.1 contradicts itself

The algorithm-1 (RSA/MD5) key tag is defined there as "the most significant 16
bits of the least significant 24 bits in the public key modulus", glossed as
"the 4th to last and 3rd to last octets". Those disagree by one: the octets the
gloss names are bits 16..31, which are not inside the least significant 24 bits
at all, while the normative clause means bits 8..23 -- the third- and
second-to-last octets. The arithmetic definition is the one implemented, and
the code says so, because a later reader checking only the gloss would
otherwise "correct" it into a bug. It is unverified against any published
vector because there is none: algorithm 1 is forbidden by RFC 8624. It is
implemented rather than skipped because a resolver still has to compute the tag
of a record it is about to reject.

## Merging eight algorithms at once: what integration caught

The eight requested algorithms were implemented in parallel, each in its own
worktree, which means each was written against a tree that did not contain the
other seven. Most of what that costs is merge conflicts in the registration
points. Two things were more than that.

### `EHashers` was renumbered, across an ABI boundary

`EHASH_MD4` arrived inserted before `EHASH_MD5` -- which reads better, since
MD4 and MD5 belong together -- and thereby moved `EHASH_SHA256` from 4 to 5 and
every enumerator after it. The reasoning offered for it was that nothing in
this repository casts or persists an `EHashers` value, which is true and is
exactly what makes the mistake invisible from inside the repository. It ships
as a shared object and is consumed as an installed package: a caller compiled
against the older header goes on passing 4 and silently gets SHA-224 instead of
SHA-256.

New hashers are now appended, with a comment at the append point saying why the
tidier grouping is not available. `EHASH_BLAKE2S` and the two Streebog
enumerators were moved below the same line when they merged.

### A stale justification, and a check nothing had ever tested

`CEcdsa`'s `deriveSharedSecret()` deliberately omits a small-subgroup test, and
its comment justified that with "every prime curve `CEcCurve` ships has
cofactor 1" -- true when written. The GOST parameter sets include two with
cofactor 4, so that sentence became false the moment the two branches met,
without either file changing. The GOST sets' own note that their cofactor
"matters only for the VKO key agreement this library doesn't implement" became
false at the same moment, for the same reason.

The conclusion survives: `CEcCurve::decodePoint()` tests `n*Q == infinity`
unconditionally, and every `EcPublicKey` is built either through it or as `d*G`
by `generateKeyPair()`, so a small-order point cannot reach key agreement. Only
the stated reason was wrong, and only the reason was changed. (A first attempt
at this added the check to `deriveSharedSecret()` as well, on the belief that
the path was reachable; it was not, and the duplicate scalar multiplication was
removed again.)

What the episode did expose is that **the subgroup check had never been tested**.
On a cofactor-1 curve it cannot fail -- the only point orders are 1 and n, and
order 1 is the infinity already rejected -- so no curve in the library could
exercise it until the GOST sets arrived. There is now a case that does, built
from a concrete witness: `2P` is the infinity exactly when `y == 0`, so an
order-2 point is a root of `x^3 + a*x + b` taken with `y = 0`. Computing
`gcd(x^p - x, x^3 + a*x + b)` over F_p for `ECURVE_GOST256A` gives a cubic with
exactly one root, so that curve has exactly one order-2 point, and the test
asserts it is on the curve, in field range, of order exactly 2, and refused by
both `decodePoint()` and `createPublicKey()`. Disabling the check fails that
case and **leaves the other sixteen ECDH cases passing**, which is the
measurement of how much coverage there was before.

## One real certificate, two unrelated gaps: RSASSA-PSS and `organizationIdentifier`

`tests/x509/certs/unimplemented/` held a real, currently-valid commercial
intermediate -- "DigiCert QV G3 TS EUR RSA4096 RSASSA-PSS 2025 CA1", issued by
QuoVadis Root CA 1 G3 -- kept there because `importDer()` returned
`ERET_BADREQ` on it, with a test case asserting exactly that. The directory
name and the test's own title both blamed the signature algorithm. Both were
wrong about which gap actually failed the import, and they were wrong in a way
that is worth recording, because the misattribution survived being written down
in three places.

### The gap that actually failed the import

The certificate's subject carries an ETSI EN 319 412 `organizationIdentifier`
(2.5.4.97), which is routine on EU-regulated and qualified certificates and was
not one of the six X.520 types `CName` recognized. `CDecoder::
decodeDistinguishedName()` rejects an `AttributeTypeAndValue` whose `type`
`CName::attributeTypeOf()` can't name, so that one attribute failed the entire
subject `Name` -- and `importDer()` returned before the signature algorithm was
read at all. RSASSA-PSS was never reached.

The fix could have gone either way: teach `ENameType` the missing types, or
make the decoder skip what it doesn't recognize. Skipping is arguably what a
parser should do with an open-ended sequence, and no RFC permits rejecting a
certificate over an unrecognized DN attribute. It was still the wrong choice
*here*, because `CDistinguishedName` is a `std::map<ENameType, CName>` with no
room to preserve an unnamed attribute: skipping would discard it, and two DNs
differing only in a skipped attribute would then compare equal. DN equality is
precisely what a chain builder matches issuer against subject on, so a lenient
decode would have converted a parse failure into a wrong-certificate match. The
enum grew instead, and the decoder still fails closed on a genuinely unknown
attribute.

`ENAME_OI` plus `ENAME_SERIAL`, `ENAME_TITLE`, `ENAME_GN`, `ENAME_SURNAME`,
`ENAME_PSEUDONYM`, `ENAME_DNQ` and `ENAME_DC` were **appended** immediately
before `ENAME_MAX`, for the same ABI reason `EHashers` is appended to (see
"Merging eight algorithms at once" above): the values cross a shared-library
boundary. Three things that fell out of it:

- `TYPE_OIDS` was declared `[ENAME_MAX][4]`, which `domainComponent`
  (`0.9.2342.19200300.100.1.25`, 10 arcs, and the only recognized attribute
  outside the 2.5.4 arc) does not fit. It is now one
  `SAttributeOid { count, arcs[MAX_OID_ARCS] }` per type, with
  `attributeOid()`/`attributeTypeOf()` and `decodeDistinguishedName()`'s
  former hardcoded `arcCount != 4` check following suit.
- `ENAME_MAX` sizes three tables, and a C++ array with fewer initializers than
  its declared size compiles silently with the tail default-constructed. The
  round-trip test in `tests/name.cpp` had enumerated the six types by hand; it
  now walks `ENAME_NONE + 1` to `ENAME_MAX` and requires an entry in each of
  `TYPE_KEYS`/`TYPE_LABELS`/`TYPE_OIDS` for every one. Adding a type without
  its tables now fails a test rather than returning zeros.
- `CName::typeOf()` compared `caseCmp(TYPE_KEYS[i], key, strlen(TYPE_KEYS[i]))`
  -- only as many characters as the *table's* key is long, which makes it a
  prefix match. With six short uppercase keys that never mattered. The moment
  `"organizationIdentifier"` existed it resolved to `ENAME_O`, because
  `"O"` is one character and matches. It now compares `strlen(key) + 1` so the
  table key's own NUL takes part, and `caseCmp()` short-circuits on the first
  mismatch, so nothing is read past either string's end.

`domainComponent` also needed the encoder and decoder to handle IA5String: RFC
4519 2.4 gives it that syntax with no alternative, so recognizing its OID while
rejecting its only legal value type would have been a half-measure. The encoder
writes `ENAME_DC` as IA5String with no PrintableString/UTF8String fallback; the
decoder accepts all three.

### RSASSA-PSS, the gap the directory name was about

`id-RSASSA-PSS` (1.2.840.113549.1.1.10, RFC 4055) is now in `SIG_ALGOS`, so
`signAlgo()` reports `rsassaPss` instead of the dotted-decimal OID. The entry's
hash is `EHASH_UNKNOWN`, deliberately: unlike every other signature algorithm
in the table, this OID names no digest. The digest, the MGF1 hash and the salt
length all live in the `AlgorithmIdentifier`'s `parameters`, which `importDer()`
had been discarding for every algorithm.

`parseRsaPssParams()` (the inverse of the existing `buildRsaPssParams()`) reads
them into the new `SRsaPssParams`, exposed by `CCert::rsaPssParams(out)`, and
`_sigHashAlgo` is then set from `hashAlgorithm` so `createHasher()` and
`verifyBy()` behave as they do everywhere else. All four fields are `DEFAULT`ed
and DER *requires* a field equal to its default to be absent, so the parse
starts from `SRsaPssParams`' constructor -- which holds exactly those defaults
-- and reports an omitted field as its default rather than as "absent", since
under DER those are the same statement. The fixture certificate spells out
three of the four (SHA-256, MGF1-SHA-256, salt 32) and omits `trailerField`.

`verifyBy()` routes a PSS signature to `IAsymmetricContext::verifyPss()` with
the parsed hash and salt length. Two encodable cases fail closed with
`ERET_NOTSUP` instead of being approximated: a `maskGenAlgorithm` naming a
different hash than `hashAlgorithm`, which this library's `verifyPss()` cannot
express (it takes one hash algorithm and uses it for both the digest and MGF1 --
the only pairing RFC 8017 recommends, and the only one encountered), and a
`trailerField` other than `trailerFieldBC`. Guessing either would reject every
valid signature, which a caller cannot distinguish from a forgery. Parameters
that fail to parse are treated the same way an unresolved OID already was:
best-effort, `signAlgo()` still resolves, `_sigHashAlgo` stays
`EHASH_UNKNOWN`, `verifyBy()` reports `ERET_NOTSUP` rather than falling back to
`RSASSA-PSS-params`' SHA-1 defaults.

### What the tests can and cannot prove

The certificate moved to `certs/implemented/`. Its test case asserts the real
file's contents: four subject attributes including
`organizationIdentifier=NTRNL-30237459`, three issuer attributes, the PSS
parameters above, RSA-4096, a 512-byte signature, and its extensions.

Its parent is QuoVadis Root CA 1 G3, which is not in this repository, so **the
real signature on this certificate is never verified** -- only rejected against
the wrong key. That rejection is still worth asserting for *which* code it
returns: `ERET_BADREQ` out of EMSA-PSS-VERIFY means the PSS verifier genuinely
ran with the parsed hash and salt length, where `ERET_NOTSUP` would mean
`verifyBy()` declined before doing any arithmetic. The verification itself is
exercised separately, by signing the real certificate's own `tbsCertificate()`
digest with a generated RSA key using the parameters parsed out of the real
file, then confirming that a tampered signature, a tampered message, salt
lengths of 20 (the DEFAULT, i.e. what a parser ignoring `[2]` would use),
`saltLength - 1` and `saltLength + 1`, and the wrong hash all fail.

The `maskGenAlgorithm`-mismatch path needed a certificate nothing in the wild
produces. One is built in the test by patching the real file's *outer*
`signatureAlgorithm` parameters so MGF1's hash OID reads `id-sha384` where
`hashAlgorithm` still reads `id-sha256` -- both are 9 content octets, so the
edit is length-preserving and the DER stays well-formed, and `importDer()`
compares only the OID between the TBSCertificate's copy of the
`AlgorithmIdentifier` and the outer one. That certificate imports, reports the
mismatch through `rsaPssParams()`, and gets `ERET_NOTSUP` from `verifyBy()`.

Each negative control was confirmed by breaking the implementation and watching
a test fail: hardcoding `saltLength` to 20, hardcoding the MGF1 hash to
`hashAlgorithm`'s value, and skipping the `parameters` parse entirely so the
SHA-1 defaults apply.

Two pre-existing tests changed meaning rather than breaking:

- The self-signed RSASSA-PSS certificate `CCertBuilder` builds in
  `tests/x509/cert.cpp` used to assert
  `signAlgo() == "1.2.840.113549.1.1.10"` and had to re-verify its own
  signature through `verifyPss()` by hand, because the OID didn't resolve. It
  now asserts `rsassaPss`, asserts the parameters `buildRsaPssParams()` wrote
  come back out of `importDer()` unchanged, and verifies through
  `verifyBy(cert)` -- the first end-to-end confirmation that the writer and the
  new reader agree on the same encoding.
- `tests/asn1/roundtrip.cpp` asserted that `decodeDistinguishedName()` rejects
  a value retagged as **IA5String**, which is now the one tag that must be
  accepted. It retags as TeletexString, VisibleString and BMPString instead
  (each still rejected), then asserts IA5String decodes, and a new case
  round-trips a `DC=example, CN=host` DN through the encoder and back -- the
  only coverage that exercises a 10-arc attribute OID in both directions.

## Ed25519 onto `Fe25519`: the 100x gap was one unmigrated file

A downstream consumer measured Ed25519 at 1.84 ms to sign and 8.78 ms to verify
(GCC/Linux) against the 50–100 µs an optimized implementation takes. On this
machine the same build measured worse — and next to it, in the same build, on
the *same curve*, X25519 derived a shared secret in 246 µs.

That comparison is the whole diagnosis. `x25519.cpp` had been migrated onto
`Fe25519` (see its own entry above); `ed25519.cpp` had not. It used `Fe25519`
zero times and `CBigNum` 118 times. And `CBigNum::mulMod()` is `mul()` then
`mod()`, and `mod()` calls `divMod()` — so **every field multiplication in the
point arithmetic performed a full big-number division**, tens of thousands of
them per signature.

Nothing else was wrong. The two things the downstream report suggested adding
were already there: `EdPointProj` already carried extended coordinates with
`T = X·Y/Z`, so `pointAddProj()` already needed no inversion, and
`scalarMulBase()` already built a lazily-cached fixed-base window table. This
was a field swap inside an otherwise sound curve implementation.

| min of 12 runs, each min of 3 × 20 iterations | before | after | |
|---|---|---|---|
| `sign` | 5.96 ms | **0.306 ms** | 19.5× |
| `verify` | 29.4 ms | **1.36 ms** | 21.5× |

Measured on a loaded 4-core laptop, Release, same harness both times — the
baseline was re-measured from `HEAD` with the identical harness rather than
quoted from the original report, because the run-to-run spread here is wide
enough (sign ranged 5.96–9.90 ms before, verify 29.4–40.1 ms) that comparing a
single run against a single run would have been meaningless.

### The trap: Ed25519 has two moduli and only one of them is `Fe25519`'s

- **p = 2^255 − 19**, the field prime, for point coordinates. This is what
  `Fe25519` implements.
- **L = 2^252 + 27742317777372353535851937790883648493**, the group order, for
  scalars: the clamped private scalar, signing's nonce `r`, the reduced hash
  `k`, and a signature's `S`.

Putting a scalar through `Fe25519` yields a signature that verifies against
itself and against nothing else in the world. No round-trip test can see it;
only a known-answer vector can.

So the separation is carried by the type system rather than by care.
`EdPoint`/`EdPointProj` hold nothing but `Fe25519`; scalars stay `CBigNum`
reduced mod `groupOrder()`; and `Fe25519` has no constructor, conversion or
assignment involving `CBigNum` in either direction — its only external
representation is 32 bytes, and no code in `ed25519.cpp` converts between the
two. Mixing them does not compile. The one place they meet is
`scalarMul()`/`scalarMulBase()`, which take a mod-L scalar and return a mod-p
point, and read the scalar only as a sequence of bits.

`Edwards25519::fieldPrime()` is gone entirely, which is part of the point:
there is no longer a `CBigNum` copy of p in the file for a scalar to be
accidentally reduced against.

### Three operations `Fe25519` was missing

`Fe25519` existed for a Montgomery ladder, which needs no square root, no
negation and no equality test. Twisted Edwards point decoding needs all three.

- **`squareRoot()`**. p ≡ 5 (mod 8), so `a^((p+3)/8)` is either a root of `a`
  or `sqrt(−1)` times one. (p+3)/8 = 2^252 − 2, and p − 2 = 2^255 − 21, and
  **both exponents begin with the same 250 one-bits** — so the forty-line
  addition chain for `a^(2^250 − 1)` was factored out of `invert()` into one
  file-local `powTwo250Minus1()` that both use. That is a shared computation
  with two real callers, not a speculative helper: a square root that got the
  chain wrong in the same way as the inverse would still agree with itself on
  every self-consistency check.

  Both candidates are squared back and compared, rather than one being
  trusted. The exponentiation cannot distinguish a residue from a non-residue
  on its own — for a non-residue it returns a perfectly ordinary-looking
  element that is a root of nothing, and handing that to point decoding means
  accepting a malformed public key.

  `sqrt(−1)` is derived, not transcribed: 2 is a non-residue mod p, so
  `2^((p−1)/4)` is a root of −1, and (p−1)/4 = 2^253 − 5 is the same run of
  ones shifted up three places times 2^3 — three squarings and one multiply by
  the cube. Consistent with how `ed25519.cpp` already derives `d` and the base
  point rather than hardcoding 255-bit literals.
- **`neg()`**, a subtraction from zero. Signed limbs make it unremarkable,
  which also let `isOnCurve()` drop back to the literal `−x² + y² == 1 + d·x²y²`
  from the rearrangement it used only to dodge a `CBigNum::modNeg()`.
- **`isEqual()` and `isOdd()`**, both of which have to go through the
  *canonical* value and not the limbs. The representation is redundant: two
  limb arrays can differ and still stand for the same element, so `isEqual()`
  subtracts and tests for zero, and `isOdd()` — RFC 8032 5.1.2's "sign" of a
  coordinate — encodes first, because an unreduced limb 0 can have either
  parity while standing for the same element.

All four are validated against `CBigNum` the way the rest of `Fe25519` was,
including `squareRoot()` against `CBigNum::modExp()`'s Legendre symbol, which
checks not merely that every returned root is a root but that a root is
returned *exactly* when one exists. The test asserts both branches were taken,
or the agreement would be vacuous.

### Two checks that became structural, and one that got stricter

`checkPrivateKey()`'s "0 ≤ x, y < p" test is gone: a coordinate is an
`Fe25519`, which has no representation outside GF(p). This is the same thing
that happened to X25519's `u >= p` check when it migrated.

The matching *input* check got stricter rather than weaker, though. RFC 8032
5.1.3 **rejects** a y at or above p rather than reducing it — the opposite of
RFC 7748's rule for an X25519 u-coordinate. With p gone from the file there is
nothing to compare against, so `decodePoint()` now re-encodes the decoded y and
requires it to match the bytes it came from; `Fe25519::toBytes()` emits the
canonical representative, so a non-canonical input cannot survive that.

`encodePoint()` also lost its return value. `CBigNum::toLittleEndian()` could
report a value too large for 32 bytes; `Fe25519::toBytes()` always emits
exactly 32 canonical bytes, so two dead error paths went with it.

### The side channel that went with it

Not the reason for the change, but worth recording:

- The ladder's conditional exchange was `CBigNum::condSwap`, **a plain
  branch** by its own documentation, on a condition that *is* a bit of the
  secret scalar — one bit of the key leaked per iteration. It is now
  `Fe25519::condSwap` under an arithmetic mask.
- Every field operation was variable-time, because `CBigNum` trims leading
  zero limbs and so does work proportional to the value. `Fe25519` is fixed at
  ten limbs.
- Both scalar multiplications looped over `CBigNum::bitLength()`, so the
  *iteration count* leaked the position of the scalar's top set bit. The
  clamped private scalar is always 255 bits by construction, but signing's
  nonce `r` is reduced mod L and varies — and `r` is as sensitive as the key,
  since the signature publishes `S = r + k·s` with `k` public. Both loops are
  now fixed at 256 bits. `CBigNum::testBit()` reads false past the top limb,
  and a leading zero bit adds the identity and leaves the `r1 − r0 == P`
  ladder invariant intact, so the two extra steps cost nothing and change
  nothing.

One leak is left and deliberately not addressed here: `scalarMulBase()` indexes
`baseTable()` by a window of the secret scalar, which is a secret-dependent
memory access. The table is 16 entries of 80 bytes and realistically stays in
L1, and fixing it properly means a constant-time table scan — a separate change
with its own cost to measure. It predates this work; it is not introduced by it.

### Validation

All five of RFC 8032 section 7.1's vectors are now checked, not just TEST 1:
the empty message, 1 byte, 2 bytes, 64 bytes (`SHA(abc)`) and **1023 bytes**.
They were extracted from the RFC text rather than typed, and each is checked
three ways — the seed derives the listed public key, signing produces the
listed 64 bytes exactly, and verification succeeds both through the private
key's own public key and through one separately imported via
`createPublicKey()`, so a broken `decodePoint()` cannot hide behind a working
`scalarMulBase()`.

Ed25519 is byte-exact, which makes the negative controls unusually clean. Each
was broken, rebuilt, and restored:

| break | caught |
|---|---|
| `k·s` computed mod p through `Fe25519` instead of mod L — *the trap* | 7 of 17 Ed25519 cases fail |
| `toBytes()`'s conditional subtraction of p dropped | 13 of 17 Ed25519 cases, and 3 of 9 `Fe25519` cases |
| sign-bit test flipped in `recoverX()` | 7 of 17 Ed25519 cases fail |

The second is the interesting one: 13 of 17 is far more than the non-canonical
encoding alone explains, and the reason is `isEqual()`. It subtracts and tests
for zero, so a difference of zero represented as p stops comparing equal — a
dropped reduction does not merely leak a non-canonical byte string, it breaks
equality for *equal values*, and almost everything downstream with it.

The existing 13 Ed25519 cases and 7 `Fe25519` cases pass unchanged; no expected
value was edited.

### Still not 100 µs

Verify at 1.36 ms is 21× better and still an order of magnitude off an
optimized implementation. Where it goes, roughly: `verify` performs three
scalar multiplications, not two — `decodePoint()` runs a full `L·point`
subgroup check on the signature's R, which costs as much as the signature
verification itself. The remaining headroom is in `Fe25519` (a dedicated
squaring, and the 2^51-radix layout that MSVC's missing `__int128` currently
rules out), a dedicated doubling formula, and a cheaper cofactor check — all
separate items, none of them this one.

### P4: the dedicated `square` was attempted and reverted

Measured first, as the P3 lesson requires: the field is **53% of X25519**
(255 ladder iterations, 4 squares and 4 multiplies each, at 38.71 ns per
`mul` and 36.16 ns per `square` against a 143 µs operation). A dedicated
squaring halves the partial products — 100 becomes 55, since every
off-diagonal term appears twice — which is worth about **12% of X25519**.

Two attempts to derive the merged form were made and both were wrong. The
reason is worth recording because it is not the obvious one: the 2^25.5 radix
applies its corrections **asymmetrically**, with the odd-index doubling on the
first operand and the 19-fold on the second. So the product matrix is symmetric
in value but not in correction, and the merged factor for a pair is the *sum*
of the two single-term factors, not twice one of them. Getting that sum right
requires tracking which operand position each correction belongs to through the
merge.

The failure mode is exactly the one this class exists to prevent: a `square()`
that agrees with itself and with nothing else. The library's tests caught it
immediately. Reverted to `mul(a, a)`, which is correct and costs a known,
bounded 12% of X25519 — well under 1% of a TLS handshake. Left until the merged
factors can be derived by a tool that checks them against `mul()` mechanically.

The 2^51-radix half was not started, and the measurement that would justify
it is less favourable than assumed: at 2^51 each product needs a 64x64->128
multiply, measured at **2.5–3.1x slower** than the current 26x26, so 25 wide
products cost about as much as 78 narrow ones — a 22% reduction in multiply
work, not the 75% the limb count suggests. The header's stated blocker (MSVC
has no `__int128`) is also narrower than it looks: MSVC x64 has `_umul128`,
which produces the same 128-bit product.

## Post-quantum: ML-DSA itself (FIPS 204), and the first real PQ certificate verified

The layers underneath this were already in and already validated — the ring, the
rounding/hint machinery, the bit packing, the three rejection samplers, the
parameter table. What landed here is everything above them: FIPS 204 7.2's key
and signature encoders, KeyGen/Sign/Verify, the `IAsymmetric` wrapper, and the
X.509 wiring that makes a real post-quantum certificate verify.

- `MlDsaScheme` (`src/crypto/asyms/mldsascheme.hpp`/`.cpp`): `pkEncode`/
  `pkDecode`, `skEncode`/`skDecode`, `sigEncode`/`sigDecode`, `w1Encode`, and
  `keyGenInternal`/`signInternal`/`verifyInternal` plus `sign`/`verify`. Takes
  ξ and `rnd` as parameters, which is what lets it be driven from a vector.
- `CMlDsa` (`include/certpp/crypto/asyms/mldsa.hpp` + `src/crypto/asyms/
  mldsa.cpp`): ML-DSA as an `IAsymmetric`, one instance per parameter set.
  `EAsymmetrics` gained `EASYM_MLDSA44`/`EASYM_MLDSA65`/`EASYM_MLDSA87`,
  appended before `EASYM_MAX` — the enum crosses an ABI boundary, so inserting
  in the middle would leave an already-compiled caller silently selecting a
  different algorithm.
- X.509: RFC 9881's `.17`/`.18`/`.19` in `CCert`'s `KEY_ALGOS` and `SIG_ALGOS`,
  `resolveSigAlgoForSigning()` taught about ML-DSA so `CCertBuilder` can issue
  one, and `CCert::signsMessageDirectly()` replacing the
  `EASYM_ED25519 || EASYM_ED448` predicate that had been copied into four
  verification paths.

### Validation came first, and in Python

Everything below the C++ was established before any of it was written: a
standalone FIPS 204 reference, transcribed from the published algorithms with
nothing borrowed from an existing implementation, reproducing NIST's ACVP
vectors in full — **keyGen 75/75, sigGen 360/360 byte-exact across all 24
groups, sigVer 180/180 verdicts**. The 24 sigGen groups cover every combination
the standard admits: deterministic and hedged, internal and external interface,
pure and pre-hashed, and the `externalMu` variant. The C++ then matched the same
vectors on its first run, which is the point of doing it in that order.

Two bugs the Python reference caught, both of which would have been invisible to
a round trip:

- `rejBoundedPoly` reduced its coefficients mod q before returning them, so
  s1's −1 became q−1, and `BitPack(η − coefficient)` then encoded a nonsense
  field. `pk` still matched on all 75 keyGen cases — the NTT does not care which
  representative it is handed — and only `sk` differed. A test that generated a
  key and used it would have passed.
- `sampleInBall` and `expandMask` had the same reduction, harmlessly there, but
  the fix is the same: these three produce **signed** coefficients, and the
  C++ layer had it right all along.

### The thing this plan never named: two message conventions

FIPS 204 has an internal interface (Algorithms 7–8) that signs `M'` verbatim,
and an external one (Algorithms 2–3) that prepends
`IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx` first. RFC 9881's
`id-ml-dsa-*` OIDs mean the **external** interface with an empty context — so an
X.509 signature covers `0x00 || 0x00 || tbsCertificate`, not the TBS bytes alone.

Getting this wrong is the ideal shape of a self-consistent bug. It round-trips
perfectly, it matches half of ACVP's sigGen groups (the twelve
`signatureInterface: "internal"` ones), and it rejects every genuine
certificate. Both forms are on `MlDsaScheme`; `CMlDsa` exposes only the
external one, and `tests/crypto/asyms/kat_mldsa.cpp` asserts directly that the
two disagree and that each rejects the other's signature.

`sign()`/`verify()` compute μ themselves and hand it to the internal form as its
`externalMu` rather than concatenating prefix and message into one buffer. The
results are bit-identical, because μ is `H(tr ‖ M')` and `H` absorbs its parts
in order, but the message is never copied — and `tr` sits at a fixed offset in
the private key, so reading it costs nothing.

### `2.16.840.1.101.3.4.3.19` is ML-DSA-87

The arc runs `.17`/`.18`/`.19` for ML-DSA-44/65/87, and the three being
consecutive makes an off-by-one a realistic error rather than a hypothetical
one. The certificate settles it without reference to the registry: its
`SubjectPublicKeyInfo` BIT STRING holds 2592 bytes and its `signatureValue`
4627, and that pair belongs to ML-DSA-87 alone (ML-DSA-65's are 1952 and 3309).

Because every parameter set has a different key *and* signature length, a
mix-up is a clean refusal rather than a wrong answer — `createPublicKey()`
rejects the bytes outright. A test offers an ML-DSA-65 key to ML-DSA-87 for
exactly that reason.

### The acceptance test

`tests/x509/certs/unimplemented/identrust-mldsa-root.der` moved to
`certs/implemented/`, and its test case now asserts
`cert.verifyBy(cert) == ERET_OK`. That is a genuine ML-DSA-87 signature,
produced by somebody else's implementation over bytes this library did not
choose, verified end to end through `CCert`, `CMlDsa` and `MlDsaScheme`.

It is the only check in the suite an ML-DSA implementation cannot pass by being
consistently wrong. A companion case flips one bit in the TBSCertificate, one in
the signature and one in the public key, and requires each to fail — otherwise
the success above would be satisfied by a `verify()` that returned `ERET_OK`
unconditionally.

Two encoding details were read off the certificate rather than assumed:
`parameters` is absent from all three of its AlgorithmIdentifiers, and both BIT
STRINGs carry raw FIPS 204 bytes with no inner `OCTET STRING` wrapper. So
`CCert` needs no reshaping step for ML-DSA, unlike DSA's split `Dss-Parms`.

### `signsMessageDirectly()`, and why it is one function

`CCert::verifyBy()`, `CCrlReader::verifyBy()` and both OCSP
`verifySignature()`s each decided whether to hash first by testing
`keyAlgo == EASYM_ED25519 || keyAlgo == EASYM_ED448`. Three more algorithms
made four copies of that predicate a question of when it would drift, not
whether — and a site that missed an entry fails silently in the worst
direction: it hands raw TBS bytes to a hash-then-sign verify (truncated to the
order's bit length, so the signature covers a prefix of the plaintext), or
hands a digest to ML-DSA and signs that 32-byte string instead of the message.
The first was a real bug in this library's OCSP path. Neither is visible to a
self-signed round trip.

It is deliberately *not* a test of `_sigHashAlgo == EHASH_UNKNOWN`, which is
also what `resolveSigAlgo()` leaves behind for an unregistered OID. The
`sigIsEddsa` locals on the signing side were renamed `sigIsSelfHashing` for the
same reason; there the `EHASH_UNKNOWN` test is unambiguous, because
`resolveSigAlgoForSigning()` returns false rather than `EHASH_UNKNOWN` for an
algorithm it does not know.

### A digest-shaped interface for something that signs messages

`IAsymmetricContext::sign(digest, out)` has no second convention to offer, and
ML-DSA has no externally supplied digest: it derives μ from the message and
then signs a lattice commitment. Passing a pre-computed SHA-256 value produces
a valid ML-DSA signature **over that 32-byte string** — one no other
implementation would generate or check, since the verifier re-derives μ from
the message it was given.

The resolution is the one Ed25519/Ed448 already established and
`CDnssecKeys::hasherOf()` states from the other side: the parameter carries the
message, and `sizeOfDigest()` stays 0 to say so. Zero means "there is no digest
to compute, pass the message", and it is asserted on the IdenTrust root's own
context. The parameter keeps its interface name — renaming it per
implementation would obscure the override relationship rather than clarify it.

### Signing is hedged, which is why the KATs go through the raw layer

`CMlDsa` draws a fresh 32-byte `rnd` per signature (FIPS 204's recommended
default), so two signatures over one message differ and neither is comparable
to a fixed answer. Deterministic signing — `rnd` all zero — is the standard's
own variant, not a test contrivance, and it is what every ACVP
`deterministic: true` group uses; it is reachable through `MlDsaScheme` and
deliberately not through `CMlDsa`, so a caller cannot select it by accident.

### Zeroization, and what it does not cover

FIPS 204 3.6.3 requires sensitive intermediates to be destroyed as soon as they
are no longer needed. Signing's rejection loop has four `continue` paths and a
dozen early returns, so a scrub written at the bottom would be skipped by every
one of them — the same failure mode `CMlKem::decapsulate()`'s single exit was
built to avoid. These use RAII scrubbers instead: ρ, K, tr, μ, ρ'', s1/s2/t0 and
their NTT forms, the masking vector y, z before it is encoded, and the `c*s`
product are all cleared on scope exit however the scope is left. A-hat is left
alone — it is a function of ρ, which travels in the public key.

It does **not** extend to verification intermediates, which the standard also
mentions. Everything verification touches is public, so there is nothing there
to protect, and saying so is more useful than a scrub that implies otherwise.

### Negative controls

Five deliberate breakages, each rebuilt and run to confirm something fails, then
reverted. This is the measurement the suite's value rests on, since every one of
these bugs leaves an implementation that works perfectly with itself:

- **Decompose's `(q-1)` carve-out rewritten as `rp == q-1`** (the single point it reads as,
  instead of the band of width γ₂ it is). Caught by `mldsarounding`, both KAT suites **and
  the IdenTrust certificate** — four failures.
- **`ExpandA`'s row/column seed bytes swapped.** Caught by `mldsasampler`, both KAT suites
  and the certificate. `tests/crypto/asyms/mldsa.cpp` — the `IAsymmetric` round-trip suite —
  **passed**, which is the whole argument for the other three: a transposed matrix is a
  different-but-valid scheme, and generating a key, signing with it and verifying against
  itself cannot see that.
- **`skDecode`'s s1/s2 range check deleted.** Caught by `kat_mldsa`, which feeds a key whose
  first s1 coefficient decodes to −5 and requires `checkPrivateKey()`, `signInternal()` *and*
  `sign()` to all refuse it. The `IAsymmetric` suite still rejected the same key, but by a
  second route — `publicKey()` re-derives the public half, whose tr then disagrees — so the
  range check is not what that test measures.
- **`verifyInternal()`'s final commitment comparison replaced with `return true`.** Caught by
  everything: both KAT suites, the `IAsymmetric` suite, and the certificate's
  tampering case.

- A fifth, for a check added during this work rather than one the plan called for:
  **the re-derived-t0 comparison in `publicKeyOf()` removed.** t0 is the one part of a
  private key no decode check can reach — its field is exactly 13 bits wide for a 13-bit
  range, so every byte string decodes to a legal t0, and `tr = H(pk)` does not cover it.
  Caught by `tests/crypto/asyms/mldsa.cpp`'s t0-tampering case, which is the only thing that
  can catch it.

Three of the four original controls are invisible to a sign-then-verify round trip against a
freshly generated key. That is the measurement this suite exists to make.

19 test cases, 510 assertions across the three new files (`kat_mldsa.cpp` 7/137,
`kat_mldsaver.cpp` 4/137, `mldsa.cpp` 8/236), plus the ML-DSA builder cases in
`tests/x509/cert.cpp` and the two certificate cases in `tests/x509/realcerts.cpp`.
The suite is 121 tests, all passing.

### What is deliberately not here

Only the pure variant. HashML-DSA was validated in the Python reference (ACVP's
twelve `preHash` groups all match) but is not in the C++: RFC 9881 8.3 says its
OIDs MUST NOT appear in an X.509 certificate, and nothing else in the tree needs
them. `MlDsaScheme` also stays private to `src/`, unlike ML-KEM's public
`CMlKem` — every entry point is parameterized by `MlDsaParams`, and exporting
the signatures would mean moving that already-tested private header into the
public API or duplicating it, for a surface callers do not need.

## `CMontgomery`: taking the long division out of every modular multiply

`CBigNum::mulMod(other, modulus)` is `mul(other)` followed by `mod(modulus)`,
and `mod()` calls `divMod()`, which is Knuth's Algorithm D. That is the right
shape for the method — it has nowhere to cache anything, and it has to keep
working for any non-zero modulus, including an even one — but it means every
modular multiply in every curve operation performed a full big-number division.
Across the 113 `mulMod` and 51 `mod` call sites in `eccurve.cpp`, `ed448.cpp`,
`ed25519.cpp`, `ecdsa.cpp` and `gost3410.cpp`, that was the single largest cost
in this library's asymmetric algorithms.

`include/certpp/utils/montgomery.hpp` + `src/utils/montgomery.cpp` add
`CMontgomery`: one odd modulus plus `n' = -m^-1 mod 2^32` and `R^2 mod m`,
precomputed once, with a CIOS Montgomery multiply over `CBigNum`'s raw limbs.
See [architecture.md](architecture.md)'s entry for the API and the two domains
it works in. Three decisions are worth recording here.

**Montgomery, not Barrett.** Barrett's advantage is that it needs no residue
domain and works for an even modulus; Montgomery's is a cheaper inner loop
(~2k² limb multiplies against Barrett's ~2.5k², and no `mu` of `k+1` limbs with
the truncations that implies) *provided* several operations share one modulus.
The curve code does hundreds of operations against one fixed prime per scalar
multiplication, which is precisely that case, and Barrett's generality buys
nothing here because `CBigNum::mod()` already covers the even-modulus case and
is staying.

**Additive, never a substitution.** `CBigNum::mod()` and `mulMod()` are
byte-for-byte unchanged. Montgomery reduction requires an odd modulus, so
silently rerouting them was never an option; `CMontgomery` is an opt-in fast
path beside them, and one built from an even or zero modulus reports
`isValid() == false` and makes every operation a no-op rather than computing
something plausible-looking.

**`add`/`sub`/`dbl` mattered as much as `mul`.** The expectation going in was
that the win would come from the multiplies. It did not come only from there:
the code being replaced spelled a field addition as `.add(x)` followed by
`.mod(p)`, which is a long division to reduce a sum that is at most `2p`, and a
subtraction as `.modSub(y, p)`, which reduces *both* operands first — two more.
Those are a single conditional subtraction and a single conditional add-back on
a context, and `doublePointJac()` alone contained seven of them.

### What was converted

- **`CEcCurve`'s Jacobian point arithmetic** (`infinityJac`, `toJacobian`,
  `toAffineFromJac`, `doublePointJac`, `addJac`, and the two scalar-multiply
  loops): one caller first, measured before going further, because it serves
  all 29 prime curves — ECDSA, ECDH and GOST R 34.10-2012 alike. The context is
  built per `scalarMul()`/`scalarMulBase()` call rather than cached on the
  curve, since `p`/`a`/`b` are public mutable fields and a cached context would
  have to be invalidated whenever one was written; its two divisions do not
  register against the thousands the loop would otherwise do.
- **`Edwards448`'s extended-projective arithmetic** (`toProjective`,
  `toAffine`, `identityPointProj`, `pointAddProj`), plus `fieldSqrt()`'s
  `x2^((p+1)/4)` through `CMontgomery::modExp()` — ~670 modular multiplications
  that each used to be followed by a division, once per decoded point, i.e.
  once per `verify()`.
- **Deliberately not converted:** the affine `add()`/`doublePoint()`/
  `isOnCurve()`. A single group operation is dominated by its one modular
  inversion, so there is nothing for a context to amortize over, and these are
  the validation paths — not where to take risk for an unmeasurable gain.
  `ed25519.cpp` was left alone because it was concurrently moving onto the
  dedicated `Fe25519` field, which is a better fix for that one curve.

The multiplication by the literal 8 in `doublePointJac()` (`8*C`) became three
`dbl()` calls: 8 is a plain integer, the operands are Montgomery-form, so
multiplying by it would have needed `toMont(8)`, whereas doubling is
domain-agnostic — and cheaper anyway.

### The measured effect

Release build, minimum across 3 invocations of (minimum of 5 runs of 30
iterations). This machine is a loaded 4-core i7-11370H with other work running,
and the run-to-run spread on a single metric reached 30%, so these are minima
and anything under ~20% should be read as noise.

| | before | after | |
|---|---|---|---|
| ECDSA P-256 sign | 6.81 ms | **2.04 ms** | 3.3x |
| ECDSA P-256 verify | 22.50 ms | **5.53 ms** | 4.1x |
| ECDSA P-384 sign | 13.34 ms | **4.27 ms** | 3.1x |
| ECDSA P-384 verify | 39.92 ms | **13.99 ms** | 2.9x |
| ECDSA P-521 verify | 72.36 ms | **28.94 ms** | 2.5x |
| Ed448 sign | 14.62 ms | **5.52 ms** | 2.6x |
| Ed448 verify | 70.73 ms | **23.83 ms** | 3.0x |

The whole test suite dropped from roughly 50s to 17.6s as a side effect.

### Validation

The 118 existing test cases pass with **no expected value edited** — every RFC
8032, RFC 5903, FIPS 186-4, RFC 6986/7091 and ACVP vector in the tree is a
check on this change, and `tests/crypto/eccurve.cpp`'s group-law cases and
`kat_ecdsa.cpp`'s FIPS vectors both proved able to catch a broken conversion
(see below).

The primary evidence, though, is `tests/utils/montgomery.cpp`, written the way
`divmod.cpp` is: it asserts nothing against expected values, only that each
`CMontgomery` operation agrees with the `CBigNum` operation it is the fast path
for. ~915k assertions over every modulus the library ships (the 29 `CEcCurve`
sets' `p` *and* `n`, plus edwards448's `p` and `L`), random odd moduli from 1
to 32 limbs, exhaustive `[0, 2m+2]²` coverage for single-limb moduli (which
exercise the `s == 1` path where the reduction pass's inner loop does not run
at all), the `0`/`1`/`m-1`/`m`/`m+1`/`m²-1`/`m²+m` operand classes per modulus,
operands at twice the modulus's bit width, and 200-step chained sequences —
because every other check starts from freshly reduced operands and would hide
an error that only accumulates.

Negative controls, each injected, rebuilt, and restored:

| injected fault | caught by |
|---|---|
| final conditional subtraction removed from the CIOS multiply | 2,499 failures in 6 of 7 `montgomery` test cases |
| `n'` computed for a perturbed modulus (sanity check disabled too) | 303,591 failures in 6 of 7 cases |
| `fromMont()` dropped from `modExp()`'s return | 48 failures, in the `modExp` case only |
| `fromMont()` dropped from one coordinate of `toAffineFromJac()` | `crypto_asyms_kat_ecdsa` (FIPS 186-4) and `crypto_eccurve` both fail |

The first of those is the one the differential test exists for: an unreduced
result in `[m, 2m)` is correct modulo `m`, so it propagates silently and only
disagrees with the slow path on inputs that happen to land there — about half
of them, which a hand-picked known-answer suite can easily miss entirely.

One subtlety worth naming, because it was wrong in the first draft. The CIOS
accumulator is `limbs(m)+2` words and its final reduction has to subtract `m`
from the low `limbs(m)` of them while also decrementing the top word *if and
only if* that subtraction borrowed out. `CBigNum::subtractLimbs()` does not
report its borrow, so the comparison has to be consulted *before* the
subtraction, not after — the first version decremented the top word
unconditionally.

## `x509/csr`: PKCS#10 certification requests (RFC 2986)

CSR support had been listed as deliberately out of scope in both
[`CLAUDE.md`](../CLAUDE.md) and [`docs/roadmap.md`](roadmap.md). That changed
by the repository owner's decision, and this is what landed: `x509/csr.hpp`'s
`CCertRequest`/`CCertRequestBuilder`, plus the CA-side
`CCertBuilder::subjectFrom()`.

### Four decisions, and why

- **Its own header pair, not an addition to `cert.hpp`.** `cert.hpp` was
  already ~920 lines, and CRL and OCSP each got their own header; a third
  protocol inside the certificate header would have been the odd one out.
- **`CCertRequest`/`CCertRequestBuilder`, split.** Named after
  `COcspRequest`/`COcspRequestBuilder`, the closest precedent in the tree: an
  object one party produces and a different party consumes, which is also why
  `CCrlReader`/`CCrlWriter` are split. `CCsr` was considered and dropped --
  every other type here is named after its ASN.1 structure, not after an
  informal acronym.
- **The key comes in as one `crypto::SKeyPair`, and there is no other way.**
  A CSR's entire purpose is to prove that the public key it carries and the
  private key its holder has are halves of one pair, so an API that let those
  be set independently would let a caller produce a request asking a CA to
  certify a key nobody in the exchange can prove possession of -- and its
  signature would still verify, just against the wrong key. `build()` also
  re-derives the public half from the private one and compares
  (`ERET_KEY_ERROR` if they differ), and always signs, so there is no path to
  an unsigned or wrongly-signed request either.
- **`CCertBuilder::subjectFrom(request)` exists; a "copy the requested
  extensions" counterpart deliberately does not.** Issuing from a request is
  the reason CSRs exist, so leaving it out would have left every consumer
  writing the same two assignments by hand. But a request's self-signature
  proves possession of a key and says nothing about whether its subject name
  or its requested `BasicConstraints`/`KeyUsage`/`SubjectAlternativeName` are
  ones this CA should certify. A `copyExtensionsFrom()` would be the single
  most dangerous method in the library -- it is how a CA issues a CA
  certificate because the requester asked for one -- so instead a CA that
  wants to grant a requested extension reads that one extension
  (`request.extension<CSanExtension>()`), checks it against its own policy,
  and pushes it onto `extensions` itself. One explicit decision per extension.

### The import verifies; it does not merely offer a `verify()`

`CCertRequest::importDer()` checks the self-signature and refuses to report
`ERET_OK` without it; a request signed with an algorithm this library cannot
verify is rejected (`ERET_NOTSUP`) rather than imported unchecked. `verify()`
is public as well, but it is not the only line of defence.

That is the opposite of `CCert::importDer()`'s documented leniency, on
purpose. A certificate's fields stay meaningful to a caller who cannot reach
the issuer's key -- other parties vouch for them. A CSR's do not: every field
is an unauthenticated claim by whoever produced it, and the self-signature is
the only thing the structure attests. A caller who got `ERET_OK` does not go
back and ask again, so "parsed but unverified" is not a state worth being able
to reach.

### The refactor

`CCertBuilder::build()` already encoded a `Name`, an `AlgorithmIdentifier`, a
`SubjectPublicKeyInfo` and an `Extensions` block, resolved a signature
algorithm and signed; `CCert::importDer()`/`verifyBy()` already decoded an
SPKI, built a public key from it and checked a signature. A CSR needs every
one of those, so they came out of those two bodies as `CCert` statics rather
than being copied: `encodeAlgorithmIdentifier()`,
`encodeSubjectPublicKeyInfo()`, `decodeSubjectPublicKeyInfo()` (with a private
`SSpkiFields` to carry its five results), `makePublicKey()`,
`encodeExtensions()`, `signTbs()`, `verifySignedBlob()`, and
`parseExtensions()` turned from a member into a static with an out-parameter.
`CCertBuilder::build()` lost ~150 lines to them and behaves identically --
every pre-existing `CCertBuilder` test passes unmodified.

Two of those are load-bearing beyond mere deduplication. `signTbs()` and
`verifySignedBlob()` are now the single place that decides hash-then-sign
versus sign-the-message (through the existing `signsMessageDirectly()`) and
PKCS#1 v1.5 versus PSS. That predicate's own doc comment already warned that
a site which misses an entry "does not fail to compile or fail loudly" -- it
hands raw TBS bytes to a hash-then-sign verify as though they were a digest --
and OCSP had exactly that bug once. Adding a fifth hand-written copy of the
decision for CSRs was the obvious way to acquire it a second time.

### `attributes` is not optional

RFC 2986 4.1's `attributes [0] IMPLICIT Attributes` has no `OPTIONAL`, so a
request with nothing to carry writes a present-but-empty SET (`A0 00`) and one
that omits the field is malformed. This is the single easiest field in PKCS#10
to leave out by accident and the hardest to notice: a parser that treats it as
optional and an encoder that omits it agree with each other perfectly. OpenSSL
itself accepts a request without it, which is why the check is explicit on
both sides here, and why the suite carries a correctly-signed fixture that
omits the field and requires `ERET_BADREQ`.

PKCS#9's `extensionRequest` (1.2.840.113549.1.9.14) is the one attribute
decoded further: its single value is an `Extensions` SEQUENCE, handed to
`CCert::parseExtensions()`, so a requested SubjectAlternativeName surfaces as
the same `CSanExtension` a certificate's own would and
`request.extension<T>()` reads exactly like `cert.extension<T>()`. Every other
attribute comes back as an `SCertRequestAttribute` holding its type OID and
its `values SET OF` content verbatim -- the same representation in both
directions, so a parsed attribute feeds straight back into a builder. The
builder orders the Attributes SET per X.690 11.6 (ascending by member
encoding, shorter-prefix first), since it is a SET OF and not a SEQUENCE OF.

### Testing: nothing that only talks to itself

`tests/x509/csr.cpp` (20 cases, 442 assertions). The acceptance fixtures are
all produced outside this library, because a builder and a parser that share
one mistake agree with each other -- the lesson of nearly every entry above:

- Four `openssl req` outputs (OpenSSL 3.4.0): RSA/SHA-256 with no attributes
  at all, P-256 with an `extensionRequest` carrying SAN + KeyUsage, Ed25519
  (the self-hashing path), and RSASSA-PSS.
- Two assembled byte by byte from RFC 2986's ASN.1 in Python -- no ASN.1
  library -- and signed with `openssl dgst -sign`, then confirmed with
  `openssl req -verify`: one carrying *two* attributes (challengePassword plus
  `extensionRequest`), so its SET-of-two and that SET's DER ordering are
  encodings this library's encoder never produced; and one deliberately
  missing `attributes [0]`.
- A byte-exact known answer for this library's own output, from a fixed PKCS#1
  key (RSA PKCS#1 v1.5 is deterministic, so the whole request is one fixed
  byte string). It was hand-decoded field by field in Python -- version, each
  subject RDN with its string type, the SPKI compared against
  `openssl pkey -pubout`, `attributes` confirmed present, empty, exactly
  `A0 00` and last inside the CertificationRequestInfo, the signature
  AlgorithmIdentifier's OID and its NULL -- and the signature checked with
  `openssl dgst -verify` over the extracted CRI bytes, plus the same signature
  over an altered CRI required *not* to verify.
- The other direction too: requests this library builds for RSA, RSASSA-PSS,
  DSA, P-256, P-384, Ed25519 and Ed448 all pass `openssl req -verify`, and
  `openssl req -text` reads the requested SAN out of the extensionRequest
  attribute. (ML-DSA is the exception only because OpenSSL 3.4 has no ML-DSA
  at all; that request's DER walks fine under `asn1parse`.)

Three negative controls were injected, built and run:

1. **Omit `attributes [0]` when there is nothing to put in it.** Caught --
   4 cases failed, including the one that reads the raw `A0 00` back out.
2. **Verify against a re-encoded `CertificationRequestInfo` instead of the
   original bytes.** Caught -- all five externally-produced fixtures failed to
   import, because their DNs use `UTF8String` where this library's own encoder
   prefers `PrintableString`. Every self-built round-trip case still passed,
   which is precisely the point: this is the bug a round trip cannot see, and
   it would have rejected every real-world CSR.
3. **Import without acting on the verification result.** Caught -- both
   tampering cases (a flipped signature bit, and a flipped letter inside the
   signed subject CN) failed.

## `x509/chain/pem`: the PEM container format, and PEM moved out of `CCert`

`include/certpp/x509/chain.hpp` had defined `IChainFormat` — read and write a
`CCertCollection` as a container file — with `builtIn()` returning null for
every format. This is the PEM half: `CPemChainFormat`
(`include/certpp/x509/chain/pem.hpp`, `src/x509/chain/pem.cpp`), wired into
`builtIn(ECHAINFMT_PEM)`.

The non-obvious part is the direction of the dependency. `CCert` already had
PEM: multi-block scanning, label handling, base64 framing, and four ways of
recognising a private-key block (PKCS#1, DSA traditional, SEC1, PKCS#8 — the
last of those tried four ways in turn). All of that was *container* work
sitting in a certificate class because, until `CCertCollection` existed, there
was nowhere else to put it. So it moved rather than being wrapped:
`CPemChainFormat` is now the only PEM handling in the library, and
`CCert::importPem()`/`exportPem()`/`detectCertFormat()` are thin delegations —
`importPem()` loads a one-entry collection and keeps the first entry,
`exportPem()` saves one, `detectCertFormat()` asks
`IChainFormat::detect()`. The 15 existing `CCert` PEM test cases passed
unmodified afterwards, which is the only reason a refactor of this shape is
safe to make. A new case in `tests/x509/chain/pem.cpp` additionally pins
`exportPem()`'s bytes to the format's own `save()` output byte for byte, so the
delegation cannot quietly become a second implementation.

Two things `CCert` keeps and the format reaches through friendship: `_asym`
(the algorithm a candidate key block has to parse under, already resolved by
`importDer()`) and a new private `lookupKeyAlgoOid()` over the existing
`KEY_ALGOS` table — the OID a PKCS#8 key block carries has to come from the
same table `importDer()` resolved the certificate's algorithm from, not from a
second copy that can drift.

The decisions worth recording, since the interface allowed either answer:

- **`save()` does not write private keys unless asked.** PEM has no
  encryption, so a key written out is a key in the clear; `builtIn()` returns
  the certificates-only form and `CPemChainFormat(true)` is the opt-in (what
  `exportPem(out, /*includePrivateKey=*/true)` constructs). A key in the clear
  is occasionally what a caller wants; a key in the clear that nobody asked for
  is not. The `password` argument is *ignored outright* in both directions —
  not accepted-and-checked, which would read like protection — and the header,
  the doc comments and a test all say so.
- **A certificate whose algorithm this library cannot resolve is loaded, not
  rejected.** `importDer()` parses it fully and leaves `keyAlgo()`/`signAlgo()`
  as raw OID text; dropping it would lose a certificate the file genuinely
  holds and that the collection's name-based lookups still work on. Only its
  key is unavailable, so no private key ever pairs with it. Tested against a
  real certificate with one byte of its SPKI algorithm OID changed.
- **Key blocks are paired cryptographically, not positionally.** The whole file
  is scanned first, then each certificate is offered every unconsumed key block
  until `CCert::privateKey(IPrivateKeyPtr&)`'s own public-key comparison
  accepts one. A key before its certificate, a key after it, and a key that
  belongs to neither all behave correctly, which positional pairing cannot
  manage.
- **A structurally broken block fails the whole container** (`ERET_BADREQ`),
  where `CCert::importPem()` used to stop scanning at that point and report
  success with whatever it had already found. That is the one documented
  behaviour the move deliberately changes: silently truncating a scan is how a
  file loses a certificate, or a key, without anyone being told. It is called
  out in `importPem()`'s own doc comment.
- **A password-encrypted key block is `ERET_NOTSUP`, not `ERET_BADREQ`** —
  either an `ENCRYPTED PRIVATE KEY` label (PKCS#8) or RFC 1421's
  `Proc-Type: 4,ENCRYPTED` header, which openssl still writes. The file is
  well-formed; what it needs is a password this format has no way to accept.
  Without the `Proc-Type` check the legacy form would have reported "malformed"
  instead, since its headers are not base64.
- **PKCS#9 attributes ride in openssl's own `Bag Attributes` shape**
  (`friendlyName:`/`localKeyID:` outside the encapsulation boundaries, where
  RFC 7468 5.2 allows arbitrary text and every other reader skips it), so
  `SCertEntry`'s attributes survive a PFX → PEM → PFX trip, as `IChainFormat`'s
  own doc comment promises for both formats. A `friendlyName` containing a line
  break is refused rather than written into a header it would run out of.

One thing the old `CCert` version did not do and this one does: the decoded
key blocks are zeroized (`CSecure::zero`) on the way out of `load()`, whichever
of its return paths is taken — they are plaintext private keys, and leaving
this function's own copies in freed heap memory is free to avoid. It is not a
claim that no copy survives: the caller's PEM text holds the same bytes in
base64 and is the caller's to scrub.

`load()` builds up locally and commits to the collection only once the whole
file has parsed, because the interface requires appending *and* requires that a
failure leave the collection untouched — writing into the output as the scan
proceeds reads as the obvious implementation and is exactly the bug that
sentence exists to forbid.

Testing deliberately avoids proving the implementation against itself. The
fixtures under `tests/x509/chain/certs/` were all written by OpenSSL 3.4.0:
`tests/x509/certs/implemented/`'s three real commercial certificates converted
with `openssl x509 -inform DER`, a throwaway RSA and P-256 self-signed pair
from `openssl req -x509 -newkey ...` interleaved so each key sits next to the
certificate it does *not* belong to, the same EC key as a traditional SEC1
block, a `openssl pkcs12 -nokeys` bag dump for the `Bag Attributes` parsing,
and the key encrypted both ways openssl can encrypt it. The three real
certificates come back out of openssl's base64 byte-identical to the `.der`
files on disk, which is the interoperability claim that matters. Nothing was
fetched from the network.

Negative controls, each injected, rebuilt, and restored:

| injected fault | caught by |
|---|---|
| `load()` commits each entry into the output collection as it parses, instead of at the end | 9 failures: all four corrupt-container subcases report the collection left half-populated, and three key-pairing cases break as well (the committed copies never receive the key) |
| `load()` clears the collection before adding, i.e. replaces instead of appending | 5 failures in the merge case (count 6 instead of 7, every index shifted) |
| a block whose payload decodes but isn't a certificate is skipped instead of failing the container | 4 failures: the corrupt-payload and whole-group-truncation subcases both report `ERET_OK`, and the collection is left with the surviving entries |

The third control also found a gap in the first draft of the tests. The
"truncated payload" case had removed 40 characters from the end of the base64
body, which leaves a partial 4-character group — so the *decoder* rejected it
and the certificate parse never ran, meaning the test would have passed even
with the DER check disabled. The fix was a second subcase that truncates by a
whole number of base64 groups, which decodes cleanly and can only be caught by
the DER parse. Two layers, two subcases.

## PBKDF2, and PKCS#12/PFX as the first container format

`x509/chain.hpp` had defined `IChainFormat` and `ECHAINFMT_PFX` with
`builtIn()` returning null for every format. This filled in PFX. The
prerequisite turned out to be a missing primitive rather than anything about
PKCS#12.

### `CPbkdf2` (RFC 8018 5.2), and why `CHkdf` could not stand in

The library had `CHkdf` and no password-based KDF at all. HKDF is not a
substitute and the reason is not a technicality: it runs two HMACs over input
that already has full entropy, and being fast costs it nothing because
guessing that input is hopeless. A password does not have full entropy, so the
only defence a KDF over one has is making each guess expensive — which is
exactly the property HKDF lacks. Feeding a password to `CHkdf` produces a key
that is derived correctly and cracked at the attacker's line rate.

So `CPbkdf2` landed in `include/certpp/crypto/pbkdf2.hpp` +
`src/crypto/pbkdf2.cpp`, beside `CHkdf` rather than hidden inside the PFX code
— it is a general-purpose primitive and callers will want it on its own.
`CHkdf`'s doc comment had predicted that if PBKDF2 ever arrived an `IKdf`
interface should be introduced with it; the prediction was revisited and
declined, because the two share only "a static `derive()` taking spans", which
is a shape and not an abstraction. That comment was updated to say so rather
than left to read as an unkept intention.

Three parameter decisions are stated in the header because each is a place an
implementation quietly goes wrong:

- **An iteration count of 0 is `ERET_BADREQ`, not "no iterations".** RFC 8018
  defines `c` as positive and `T(i)` is the XOR of at least `U(1)`, so 0 leaves
  the block undefined. More to the point, a count parsed out of a
  caller-supplied container must never be able to turn the derivation into a
  free one.
- **The output is bounded at `(2^32 - 1) * hLen`**, because `INT(i)` is a
  32-bit counter; past that it wraps back to block 1 and the output repeats.
  `maxDeriveBytes()` computes the bound in 64 bits and saturates, since on a
  32-bit `size_t` the real value does not fit and a bound that wrapped would be
  no bound.
- The salt may be empty. RFC 8018 4.1 asks for 64 bits from a random source,
  but a caller reproducing somebody else's container has to accept whatever
  salt is in it, so the minimum is documented and not enforced.

#### Validation

Every expected value was reproduced from Python's `hashlib.pbkdf2_hmac` before
being written into the test, and that step earned its keep immediately: two of
the values recalled from the RFCs were wrong. RFC 6070's fourth case ends
`...8b291a964cf2f07038`, not `...8b291a964fe0858c`, and RFC 7914 section 11's
first SHA-256 case has `...fec1691c22544b60...` with one `5` where it is easy
to type two. Had those gone in as written, the implementation would have been
"fixed" until it reproduced them.

`tests/crypto/pbkdf2.cpp` covers all five of RFC 6070's HMAC-SHA1 cases
(including the embedded-NUL password and salt, and the 25-byte output that is
the only one exercising `INT(i)` at all, since with `dkLen <= hLen` the counter
is always 1 and a wrong encoding of it is invisible) and both of RFC 7914
section 11's HMAC-SHA256 cases.

RFC 6070's 16777216-iteration case is **deliberately left out**, and the
reason is runtime: it is the same derivation as the 4096-iteration case with a
larger `c`, and at this library's throughput (measured at 0.50 µs per
HMAC-SHA256 operation in a release build) it would add minutes to every
`ctest` run to re-test one loop. It was verified once out of band — Python's
C-backed hashlib takes 17.3 s on it and agrees with the RFC — and the 4096-
and 80000-iteration cases carry the same loop in the suite.

### `CPfxFormat` (RFC 7292)

`include/certpp/x509/chain/pfx.hpp` + `src/x509/chain/pfx.cpp`, wired into
`IChainFormat::builtIn()`. `docs/architecture.md` records the format decisions
(PBES2/AES-256-CBC only, HMAC-SHA-256 for the MAC, 600,000 iterations,
MAC-before-decrypt, the two password encodings); what follows is what the work
turned up.

**The legacy PKCS#12 KDF had to be implemented after all, and only just.** The
plan was to avoid RFC 7292 Appendix B entirely in favour of PBES2. That is
possible for *encryption* — OpenSSL 3 defaults to PBES2 with AES-256-CBC, so
the legacy RC2/3DES ciphers can simply be refused with `ERET_NOTSUP`. It is
not possible for *integrity*: RFC 7292 section 4 specifies that `MacData`'s
key comes from the Appendix B KDF with purpose byte 3, there is no alternative
in the RFC, and every real container therefore uses it. (RFC 9579's PBMAC1,
from 2024, does allow PBKDF2 there; nothing writes it yet.) So the KDF is
implemented, scoped to exactly that one key, and kept as a file-local helper
in `pfx.cpp` rather than put in `crypto/` beside `CPbkdf2` — it is a legacy
PKCS#12-only construction and nothing else should reach for it. No PBES1 key
or IV is ever derived with it; no RC2 or 3DES is read or written.

**The password is encoded two different ways in the same file.** PBES2 is
PKCS#5 and takes the password bytes as given. Appendix B's KDF is PKCS#12's
own and takes them as a NUL-terminated big-endian UTF-16 BMPString. Getting
these the same way round produces a container nothing else can read, and —
this is the trap — one the writing implementation reads back perfectly. Both
were pinned in Python against a real OpenSSL container before any C++ was
written: the Appendix B derivation was checked by recomputing the fixture's
HMAC and matching its stored MAC byte for byte, and the PBES2 side by deriving
the key both ways and handing each to `openssl enc -d` to see which one
decrypted the certificate bag. The raw-bytes key is the one that works.

The UTF-8-to-UTF-16 direction matters too. Older OpenSSL's `OPENSSL_asc2uni`
zero-extended each byte, Latin-1 style; OpenSSL 3 converts UTF-8. For an ASCII
password the two agree, which is why `fixtures/openssl-utf8-password.p12` is
in the tree — a container written elsewhere under `passwörd` is the only thing
that distinguishes them, and a round trip through this library cannot, since
it would agree with itself either way.

#### Refactoring `CCert` rather than copying it

PFX stores keys as PKCS#8 and `CCert` already had the inbound half, in
`unwrapPkcs8PrivateKey()` and the per-algorithm conversions `importPem()`
uses. None of it was reusable as it stood: `tryAttachPrivateKey()` guesses at
a blob's shape by trying it under one certificate's own algorithm until
something parses, which a key bag cannot do (it has to be readable before it
is known which certificate it pairs with), and
`buildSec1PrivateKey()`/`convertPkcs8DsaInnerToNative()` read their inputs out
of `CCert`'s own parsed fields.

Rather than write a second copy, two public statics were added —
`CCert::exportPkcs8PrivateKey()` and `importPkcs8PrivateKey()` — and the two
state-dependent helpers were split so both callers reach one encoder:

- `buildSec1FromNative(native, curveOid, publicPoint, out)` is
  `buildSec1PrivateKey()`'s body with its three inputs passed in. The public
  point stays an explicit argument even though the native blob embeds one, so
  the refactor cannot change what `exportPem()` has always written.
- `buildDsaNative(dssParms, y, innerX, out)` is the shared body of
  `convertPkcs8DsaInnerToNative()` and the new import path. The two differ only
  in where `y` comes from, and that difference is itself worth recording: a
  certificate carries `y`, and a PKCS#8 DSA key does not carry it at all, so
  reading one standalone costs a `g^x mod p` via `CBigNum::modExp()`.

ML-DSA is refused (`ERET_NOTSUP`) rather than wrapped: its PKCS#8 form is a
CHOICE between a 32-byte seed and the full expanded key, and this library's own
key blob is neither shape, so writing one would be guessing at an encoding
nothing reads. `CCert`'s existing tests pass unmodified.

#### Validation: reading what this library did not write

A PFX this code wrote and read back proves that two bugs cancel. `openssl` was
on PATH, so five containers were produced once with `openssl pkcs12 -export`
and checked in under `tests/x509/chain/fixtures/` (so the suite itself needs no
openssl): an EC key under OpenSSL 3's own defaults, an RSA key, a
two-certificate chain, an explicit SHA-1 `MacData`, and a `-legacy -certpbe
PBE-SHA1-3DES` container that must come back `ERET_NOTSUP`. A sixth was added
for the non-ASCII password. Before any of them was used as a fixture,
`openssl asn1parse` and a hand-written Python decoder walked the first one TLV
by TLV, so the structure the C++ expects was derived from a real file rather
than from a reading of the grammar.

That first run found the bug the exercise exists for, and it was not subtle in
hindsight: `parsePbes2()` was handed the PBES2-params SEQUENCE's *content* by
every caller (they all reach it through `readNextElement()`) and opened with
another `readSequence()`, so it read the `keyDerivationFunc` as though it were
the whole of PBES2-params and failed one level further down. Every load of
every fixture returned `ERET_BADREQ`. A self-round-trip suite would have failed
identically, so this one is not by itself evidence for the interop fixtures —
but nothing else in the file would have said *which* side was wrong.

The other direction was checked by hand, since a test cannot shell out: the
round-trip cases write `pfx-written-by-certpp.p12` into the working directory,
and `openssl pkcs12 -info` on it verifies the MAC, decrypts both the
certificate bag and the shrouded key bag, reports `PBES2, PBKDF2, AES-256-CBC
... PRF hmacWithSHA256` and `MAC: sha256`, prints the `friendlyName` and
`localKeyID`, and separates the leaf from the two CA certificates by that
`localKeyID`. The extracted key's public point hashes identically to the leaf
certificate's, and `openssl` rejects a wrong password on the file with `Mac
verify error: invalid password?`.

#### Negative controls, each injected, rebuilt, and restored

| injected fault | caught by |
|---|---|
| MAC verdict deferred until after the AuthenticatedSafe is parsed and decrypted | 605 failures in the tamper-sweep case — most flips become `ERET_BADREQ` |
| `std::memcmp` in place of `CSecure::equals()` for the MAC | **nothing** — see below |
| `CSecure::zero()` removed from the derived PBES2 key | **nothing** — see below |
| empty-password refusal removed from `save()` | 2 failures, and it wrote a container under no password |

The two that were not caught are honest misses, and both were expected to be.
`memcmp` returns the same answer as `CSecure::equals()`; it only takes a
different amount of time, and no functional test can see that. A missing
`CSecure::zero()` leaves key bytes in freed heap, which is likewise invisible
to anything the suite can assert. Neither is defended by a test, and claiming
otherwise would be the wrong record to leave: they are defended by review, by
the primitives being the obvious ones to reach for, and by the doc comments
that say why. The timing one is worth keeping even though a PFX MAC is compared
against a value the attacker already holds — this is a library, and a caller
who exposes `load()` to uploaded files turns it into exactly the online oracle
a constant-time comparison is for.

The tamper sweep itself was sharpened during this work. It began as "flip every
seventh byte of the back two-thirds of the file and expect `ERET_KEY_ERROR`",
which failed on three offsets — and investigating them was more useful than
fixing them. All three lie in `MacData`, which the MAC cannot cover, because
`MacData` is where the MAC is. Two were a corrupt `DigestInfo` (`ERET_BADREQ`)
and an unrecognised digest OID (`ERET_NOTSUP`); the third flipped the `NULL`
tag in the digest `AlgorithmIdentifier`'s ignored `parameters` field and
changed nothing at all, so the container loaded — correctly, because it was
still authentic. The sweep now locates the AuthenticatedSafe and flips **every
one** of its bytes (1048 of them, which is what took the case from a sample to
exhaustive coverage of the range an attacker could put a payload in), and the
comment states what the MAC's scope is rather than implying the whole file is
protected.

#### Two things review found that the tests did not

Both came out of asking "what runs before the MAC has vouched for anything?"
and "what does this buffer type actually do?", and neither would have shown up
as a failing assertion.

**`CBuffer::resize()` does not truncate in place.** `aesCbc()` allocates a
block of headroom (encrypting always appends a pad block) and originally
trimmed the result with `out.resize(total)`. But `resize()` *always* allocates
a fresh block, copies the part it keeps, and `delete[]`s the old one — without
wiping it. On the decrypt path that old block holds the complete plaintext,
which for a `pkcs8ShroudedKeyBag` is a private key, so trimming handed the key
to the allocator in the clear and the caller's own `CSecure::zero()` then
scrubbed the surviving copy instead. It now copies the exact length out, wipes
the oversized block, and swaps it away (move-assignment swaps, per this
library's convention, so the wiped block is the one that gets destroyed).

**`MacData`'s iteration count drives work before the MAC is checked.** The MAC
key has to be derived to check the MAC, and the count comes out of the file, so
it is the one iteration count in the format that an attacker picks. The
original bound was `0x7FFFFFFF`, which is about eighteen minutes of CPU for a
200-byte file. `CPfxFormat::MAX_MAC_ITERATIONS` is now 10,000,000 — far above
RFC 7292's 1024, OpenSSL's 2048 or this library's own 600,000, so it costs no
interoperability. The test for it rebuilds a real container with only that
field changed and checks three outcomes, because the interesting part is that
they differ: past the ceiling and at zero are `ERET_BADREQ`, while a count
inside the ceiling that is simply wrong for the container is `ERET_KEY_ERROR`.
A blanket rejection would pass the first two and fail the third.

While here, the private-key locals in `CCert`'s two PKCS#8 methods moved onto a
small TU-local `ScopedWipe`. Twenty `return` statements between them each held
a key in two or three buffers, and a wipe written out beside each one is a wipe
that is wrong the first time a branch is added. It does not reach the
*intermediate* states of a growing `CBuffer` — `resize()` frees each previous
block unwiped — which is a property of the buffer type, shared with
`exportPem()`'s own key paths, and belongs in `CBuffer` rather than here.

#### A comment that was wrong, and a lifetime that was not

`SBag` originally held its bag value as a span into the decrypted
`SafeContents` plaintext, with the plaintexts kept alive in a
`TArray<CBuffer>`. That looked like a dangling-span bug — growing the array
relocates its elements — and it was changed to an owning `COctet` per bag.
Checking `TArray::reserve()` afterwards showed the original was in fact safe:
it relocates by move-construction, and `CBuffer`'s move hands over the same
heap block, so the addresses survive. The change was kept anyway, for a smaller
but real reason — each plaintext can now be wiped as soon as its bags have been
read, instead of living until the end of `load()` — and the comment was
corrected to say that instead of claiming a bug that was not there. `SBag`'s
destructor does the wipe, because an encrypted `SafeContents` may hold a plain
`keyBag` and there are half a dozen error returns between reading it and the
end of the method.

#### Validation

The 123 existing test cases pass with no expected value edited;
`tests/crypto/pbkdf2.cpp` and `tests/x509/chain/pfx.cpp` bring the suite to
125 executables, all passing (the PFX file alone is 22 cases and ~4,500
assertions, most of them the tamper sweep).

#### Not done

- **The legacy PKCS#12 ciphers** (RC2-40-CBC, `pbeWithSHAAnd3-KeyTripleDES-CBC`
  under PBES1) are refused, not read. Containers written by tooling older than
  roughly 2021, or by `openssl pkcs12 -legacy`, need them; the fixture is in
  the tree asserting the `ERET_NOTSUP`, so adding support later has a test
  waiting to be inverted. Scoped as a follow-up rather than half-done.
- **Public-key integrity and privacy modes** (a `signedData` `authSafe`, or an
  `envelopedData` ContentInfo) return `ERET_NOTSUP`.
- **RFC 9579 PBMAC1**, which would let `MacData`'s key come from PBKDF2 instead
  of Appendix B's KDF, is not implemented in either direction.

## Three API gaps the wiki's example code exposed

Writing a compiled example for every public type turned out to be an audit as
much as a documentation job: an example is the first caller that has to obtain
a type the way a caller would, and three types could not be used that way.
Each was found by trying to write its example and failing.

### `EDecoderStatus` was a public enum nothing public could produce

`asn1/decoder.hpp` exports seven status values. `decodeLength()`, the only
thing that produced them, was private, and every public `CDecoder` entry point
returned `bool`. So the one distinction the enum exists to carry — `EDEC_NEED_MORE`,
"truncated, send more bytes", against `EDEC_RESERVED`/`EDEC_TOO_BIG`/
`EDEC_PROHIBITED`, "malformed, give up" — was unavailable to the callers who
need it most, anyone decoding off a socket or a stream.

The status was being computed and then thrown away. `readIndefiniteContent()`
and the depth-tracking `readEncodedValue()` now return `EDecoderStatus` instead
of `bool`, so `EDEC_NEED_MORE` propagates out of a nested value rather than
flattening into the same failure as a malformed one, and a new public
`tryReadEncodedValue()` hands it to the caller. The `bool readEncodedValue()`
keeps its exact signature and is now `tryReadEncodedValue(...) == EDEC_OK`,
so there is one implementation rather than two that could drift apart.

Two places needed a judgement call rather than a mechanical conversion:

- **A tag that will not decode.** `CTag::decode()` folds "no bytes at all",
  "the high-tag-number form runs past the end of the span" and "not a tag"
  into one invalid tag, and only the first is distinguishable afterwards. An
  empty source reports `EDEC_NEED_MORE`; anything else reports
  `EDEC_BAD_ARGS`, because telling a caller to append bytes to a genuinely
  malformed tag is a promise that cannot be kept.
- **Indefinite-length nesting past `MAX_NESTING_DEPTH`** reports
  `EDEC_TOO_BIG` rather than `EDEC_PROHIBITED`: the encoding is legal BER, it
  is this decoder that declines to go deeper, and the two statuses say
  different things about whose fault it is.

The negative controls: collapsing a truncated value back into `EDEC_BAD_ARGS`,
dropping the end-of-contents case back to a generic failure, and discarding
`decodeLength()`'s own status as the old code did were each injected
separately, and each was caught.

The example this type carries on the wiki used to classify the length octets
by hand, because that was the only example possible. It now drives a real
read loop, which is the thing the enum was for.

### `COctet` could not wipe its own secret without a `const_cast`

A `COctet`'s bytes are reachable only through the read-only `toPtr()`/
`toSpan()`, so `CSecure::zero()` could not be pointed at them. That bites
wherever one carries key material — a PKCS#9 `challengePassword` out of
`CCertRequest::attributeOf()`, a decoded private-key blob — and the workaround
a caller would reach for is a `const_cast`, which is not something to publish
as the house style for handling a secret.

`secureClear()` zeroizes and then releases, following `CBigNum::secureClear()`'s
precedent. A mutable `toPtr()` was the alternative and was rejected: it would
let anything rewrite an owned buffer piecemeal, which is exactly what
`store()`'s replace-the-whole-content design prevents. Naming the operation
keeps the capability to the one use that needs it.

Its doc comment states the limit rather than implying none: it reaches the
bytes *this* instance owns at the moment it is called, and not a copy an
earlier assignment made, nor the block `store()` frees when it replaces
content of a different size. It shortens the window a secret stays in freed
memory; it does not close it.

The test case says plainly what it cannot check. The zeroization is not
observable — the block is freed immediately after, and reading freed memory
would measure the allocator rather than the wipe — so the case covers the
observable contract and leans on `CSecure::zero()`'s own tests for the rest.
The negative control (wipe but never release) is caught.

### `ParseFixedDigits`, `ValidateTimeFields`, `WriteFixedDigits`

Private static members in PascalCase, where
[coding-conventions.md](coding-conventions.md) calls for `camelCase` on
members and reserves PascalCase for free functions. Renamed across 32 call
sites; no behaviour change.

## `RSA::checkPrivateKey` rejected every OpenSSL and BIND private key

Reported downstream: cppskit's cskdns_certpp imports DNSSEC keys produced by
BIND's `dnssec-keygen`, and `checkPrivateKey()` returned `ERET_KEY_PARAM` for
all of them — while a sign/verify probe on the very same key succeeded. The
workaround downstream was to validate with that probe instead, which is a
sound diagnosis of where the fault was.

The check computed `phi = (p-1)*(q-1)` and required `d == e^-1 mod phi`
exactly. But RFC 8017 3.2 defines `d` as the inverse of `e` modulo **either**
`lambda(n) = lcm(p-1, q-1)` or `phi(n)`, and the two values differ whenever
`gcd(p-1, q-1) > 2`. `lambda` divides `phi`, so the `lambda(n)` value is the
smaller one, and a check written against `phi` rejects it.

It is not a corner of the standard that nothing uses. Generating keys with
OpenSSL 3.2 and reading their parameters back shows the split directly:

| `openssl genrsa` | `d == e^-1 mod lambda` | `d == e^-1 mod phi` |
|---|---|---|
| 2048-bit | yes | **no** (3 of 4 sampled keys) |
| 1024-bit | — | yes |

At 2048 bits and up OpenSSL follows FIPS 186-4, which requires `d < lambda(n)`;
below that it keeps the historical `phi(n)` value. So `openssl genrsa 2048`,
the single most common way to produce an RSA key, was rejected, and only the
sizes nobody should still be using passed. `dnssec-keygen` and ldns produce the
`lambda(n)` form as well.

The fix checks the congruence rather than a specific representative:
`e*d ≡ 1 (mod p-1)` and `e*d ≡ 1 (mod q-1)`, which together are
`e*d ≡ 1 (mod lambda(n))`. That accepts both forms — and also a `d` offset by
any multiple of `lambda`, which is equally valid and equally functional — while
still rejecting a `d` that is not an inverse at all. The `gcd(e, phi) == 1`
test above it needs no change, since `phi` and `lambda` have the same prime
divisors. The CRT checks below it needed none either: `dP = d mod (p-1)` holds
for both forms, because that identity is what makes the CRT exponents work in
the first place.

### What the test pins

A sign/verify round trip would not have caught this and did not: the bug was
in the validator, not the arithmetic. The regression test therefore carries one
real 1024-bit `openssl genrsa` key encoded as PKCS#1 `RSAPrivateKey` twice —
same `n`, `e`, `p`, `q`, with `d` in each form — chosen so that
`gcd(p-1, q-1) = 24` and the two `d` values are genuinely 24× apart rather
than coinciding, which they do about half the time when the gcd is 2. Both
must now validate, and the two imports must agree on their public half, which
is what proves they are the same key rather than two unrelated ones.

A third vector is the `lambda(n)` key's `d` plus one, with `dP`/`dQ`
recomputed to match so that the congruence is the only thing wrong. It must
still be rejected — a fix that simply dropped the `d` check would pass the
first two cases and leave nothing behind it.

Confirmed by negative control: with the one-line condition reverted, the
`lambda(n)` cases fail and the `phi(n)` and non-inverse cases still pass,
which is exactly the signature of the reported bug.

## Measuring the library on two toolchains, and what they disagree about

`README.md`'s Performance section carried a single set of figures, from one
Release/MSVC run. Re-running `examples/05_benchmark.cpp` on both toolchains in
one session -- MSVC 19.36 on Windows and GCC 13.3 on Ubuntu 24.04 under WSL2,
same 4-core i7-11370H -- turned that one column into two, and the second is not
a second copy of the first.

The methodology mattered more than usual here, because a comparison was the
whole point. The two toolchains ran one after the other rather than
concurrently: on eight cores, with a compiler that saturates them, running
both at once would have had each measuring the other's compiler. Each figure
remains the harness's own fastest-of-three-batches-of-20, best of three runs.

### What the two toolchains disagree about

GCC is equal or faster on most of the library, by a lot in places -- SHA3-256
by 2.8x, Streebog-256 by 42%, ML-KEM by 30%, AES-256-GCM by 28%, Ed25519
signing by 18%. Two entries run the other way, and RSA is the one that
matters:

| | MSVC | GCC |
|---|---|---|
| RSA-2048 sign | **8.06 ms** | 19.1 ms |
| RSA-2048 verify | **0.145 ms** | 0.392 ms |
| MD5, 64 KiB | **593 MiB/s** | 455 MiB/s |

RSA's two halves moving together, while every prime curve runs *faster* on
GCC, is a specific shape of result. It rules out the big-number backend being
slow in general, and points at RSA as the one place `mulMod()` dominates
enough for a codegen difference to be the whole result.

### The obvious explanation, and why it is wrong

The first thing to try was the one that would have made this a non-issue: GCC
cannot emit MSVC's `_mulx_u64`/`_addcarry_u64`, so it must be falling back to
the portable multiply. That is wrong, and `src/utils/bignum.cpp` says so
directly. `CBigNum::mul()` dispatches on `hasAdxBmi2()` (`bignum.cpp:531`), and
`mulAccelerated()` reaches the same MULX/ADCX path on both toolchains -- GCC
through the function-level `__attribute__((target("bmi2,adx")))`, MSVC through
its unconditional intrinsic use -- and this CPU reports both features. The one
type mismatch Linux ever found in that code, `uint64_t*` against
`unsigned long long*`, is fixed and in the changelog above.

So the difference lives in codegen, and it has not been profiled. Two
candidates worth measuring before anything is changed: the shape of the
Montgomery reduction, and whether GCC keeps `row[]`/`r64[]` resident across
`mulAccelerated()`'s Step A / Step B boundary. That is now open work in
`docs/roadmap.md`, with the exclusions recorded next to it so the ruled-out
hypothesis does not get re-derived.

### Two limits on the comparison

Both are stated in `README.md` rather than left for the reader to infer:

- **WSL2 is a VM, not bare metal.** The harness is single-threaded CPU-bound
  cryptography, so the hypervisor's share of each measurement ought to be
  small -- but that is an argument that it ought to be, not a measurement
  showing that it is. The GCC column reads as "this toolchain in this setup",
  not as Linux performance in general.
- **"Both Release" is not "the same settings".** CMake's Release defaults are
  `/O2` for MSVC and `-O3` for GCC, so toolchain and optimization level are
  varied together. Calling the RSA gap a GCC bug would need a re-measurement
  on bare metal first.

### The old numbers were measured under load

The MSVC column replaces figures published earlier, whose own text described
them as taken on a loaded machine. Re-measured, every row came in equal or
faster, most by 10--20%; the largest movement is ECDSA P-256 verify, 3.53 ms
to 2.44 ms, just outside the harness's own stated 20--30% spread. Nothing in
the code changed to account for that, which is the useful part of it: it
measures the conditions, not the library. So the tables now state those
conditions and the spread explicitly, and treat a difference smaller than
20--30% as not being a result.

## Profiling: RSA was never on Montgomery, and the small-record cost is two blocks

Following the roadmap's P0 and P1. Both changed the plan rather than merely
executing it, which is why they are recorded here at length.

### P0 -- two measurement gaps, and what came out of closing them

`examples/05_benchmark.cpp` now times ML-KEM-768 key generation, which
`benchKem()` previously called once for setup and never measured -- the reason
`README.md`'s table carried a dash in that cell -- and a new
`benchSmallRecord()` reports the 64 B `seal()` that the small-record target is
written in and that nothing measured. Both toolchains were re-measured three
times rather than from the single run that would have filled the cells.

Reusing one key and nonce in that loop is not flattering the number, and worth
being explicit about: `CChaCha20Poly1305::seal()` re-derives the one-time key
through `ChaCha20Core::block()` on every call and constructs a fresh
`CPoly1305` for the tag, so there is no cross-call state for the loop to warm.
What the loop does hold constant is the key.

The result inverts an ordering the tables implied. **AES-256-GCM is the fastest
of the three AEADs at 64 B and the slowest at 64 KiB**, on both toolchains:

| | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305, 64 B | 410 ns | 332 ns |
| XChaCha20-Poly1305, 64 B | 545 ns | 449 ns |
| AES-256-GCM, 64 B | **225 ns** | **179 ns** |
| ChaCha20-Poly1305, 64 KiB | 578 MiB/s | 650 MiB/s |
| AES-256-GCM, 64 KiB | 370 MiB/s | 475 MiB/s |

(The 64 KiB row is what the AVX2 keystream later changed, to 736 and 835; the
64 B rows are unchanged by it, as they were meant to be.)

AES-GCM encrypts one block where ChaCha20 encrypts two, the second being the
block deriving the Poly1305 one-time key at counter 0 (RFC 8439 2.6). A bulk
sender and a per-record caller are looking at different winners, so the
roadmap's ChaCha20-Poly1305 item -- one target, 1.5 GiB/s bulk against a 150 ns
per-record cost -- has been split into two changes that do not overlap. The
per-record half was sequenced first: folding the key derivation into a single
four-wide SSE2 pass is one pass against an entire AVX2 rewrite, and it helps
every record-sized caller rather than only bulk ones. **That sequencing turned
out to rest on a measurement that was wrong, and the correction is recorded
under "the small-record cost is not what it seemed" below.**

ML-KEM-768 key generation measured 0.193 ms on MSVC and 0.142 ms on GCC, slower
than either encapsulate or decapsulate.

### The small-record cost is not what it seemed

Measuring where the 410 ns actually goes, rather than adding up the parts,
overturned the P0 conclusion twice over -- and both corrections pointed away
from the original claim.

A sweep of nine sizes shows the cost curve is not a line and has a step in it.
Fitting 64 B against 192 B and reporting the intercept as zero, which is what
the first reading did, is wrong because 192 B is not "two blocks more" than
64 B in any sense the curve respects: `xorStream()` sends only whole four-block
groups to SSE2 (`vectorBlocks = wholeBlocks & ~size_t(3)`,
`chacha20core.cpp:225`), so 64/128/192 B all take the scalar path and 256 B is
the first vectorised size. Measured, min of 5x20000 over two runs, GCC:

| payload | blocks | keystream path | `seal()` |
|---|---|---|---|
| 0 B | 0 | -- | **180--210 ns** |
| 64 B | 1 | scalar | 340--352 ns |
| 128 B | 2 | scalar | 485--488 ns |
| 192 B | 3 | scalar | 634--639 ns |
| **256 B** | 4 | **SSE2** | **568--575 ns** |

192 B costs more than 256 B, and that reproduces every run -- it is what the
straight-line fit was absorbing. So there **is** a fixed cost of about 200 ns,
the one-time key block plus Poly1305 over the AAD and length blocks, roughly
half of a 64 B record. The 150 ns target is therefore unreachable at any payload
size without removing the one-time key derivation itself, and is withdrawn.

The proposed fix fails for a clearer reason than the original one gave. It was
to generate counters 0--3 in one SSE2 pass, a lane-counting argument, but the
real problem is that sub-256 B records never reach the vectorised path at all.
Vectorising a *run* of blocks was tried first and came out 24% slower;
`blockVectorized()`, which produces byte-identical output (verified over 4456
cases), came out **1.43x slower** because discarded lanes still pay for SIMD
shuffles and register pressure. Reproduced in situ against the scalar loop's own
shape from `chacha20core.cpp:235` -- one block is 142.9--151.4 ns scalar against
177.8--212.7 ns vectorised, **1.17--1.49x slower** -- so the isolated benchmark
understated it, because the scalar loop never materialises a keystream block at
all and XORs straight into the caller's buffer.

Lowering the four-block threshold to one was the obvious follow-up and is also
a regression, for the same reason. The serial path has no slack to offset it
either: `twentyRounds()` compiles to **zero xmm registers** (32 `rol`, 32 `xor`,
31 `add`, no auto-vectorisation) and `block()` costs 100.5 ns, which at 3.92 GHz
is **6.2 cycles/byte** -- squarely normal published scalar ChaCha20 for x86-64.
That last figure first looked implausible and prompted the disassembly check;
it is correct, not a compiler artifact.

### P3 bulk -- an AVX2 eight-block keystream, and where the target actually goes

Of seven changes attempted in this area, this is the first to survive
measurement. ChaCha20 blocks are independent by construction, so the existing
SSE2 path already exploits that with four lanes; this doubles it. On 64 KiB
(GCC, min of 5x40, two runs) the keystream goes **48.0 to 24.6 us, 1.95x**, and
the whole AEAD 97.6 to 72.8 us, 1.34x. On the project harness:

| | before | after |
|---|---|---|
| MSVC ChaCha20-Poly1305, 64 KiB | 578 MiB/s | 736 MiB/s |
| MSVC XChaCha20-Poly1305, 64 KiB | 577 MiB/s | 748 MiB/s |
| GCC ChaCha20-Poly1305, 64 KiB | 650 MiB/s | 835 MiB/s |
| GCC XChaCha20-Poly1305, 64 KiB | 648 MiB/s | 840 MiB/s |

AVX2 is not part of any x86-64 ABI, so the gate is a runtime CPUID check rather
than the architecture, cached in a function-local static because CPUID is
serialising. It is also gated on **512 bytes and up**, deliberately: eight lanes
computed and six discarded is a loss for a short payload, which is the same trap
the four-block path falls into below 256 B. Small records are unchanged at
410--440 ns.

The 8x8 transpose needed `_mm256_permutevar8x32_epi32` per 128-bit half rather
than the shuffle-based sequence the four-block path uses. `_mm256_shuffle_epi32`
and the unpack family operate within each 128-bit lane independently, so after
the first two stages each vector holds two rows interleaved lane by lane and no
half-select can separate them; a brute-force search over all 256
`permute2x128` immediates confirmed no combination of them works. Which lane
holds which value was derived by transposing an identity matrix and reading the
result -- column k's rows 0..3 sit in `u[k/2]` and rows 4..7 in `u[k/2 + 4]`,
even k reading lanes {0,1,4,5} and odd k {2,3,6,7} -- because two hand-derived
attempts were wrong first.

**The 1.5 GiB/s target is not reached, and the reason is arithmetic.** Splitting
the 64 KiB AEAD shows the two halves are equal -- 48.0 us of keystream against
48.2 us of Poly1305 -- so the MAC is 50% of the cost and no keystream
improvement alone can reach the target. At the measured AVX2 keystream the budget
for cipher and MAC together is 40.7 us, of which the cipher now takes 24.6,
leaving 16.1 us for a MAC that currently needs 48.2.

### P3 -- Poly1305, and why the target is closed rather than open

Attempted, measured, and it does not pay on this CPU. Two things had to be
established before concluding that, and the first one is the one that mattered.

**The scalar routine is throughput-bound, not latency-bound.** That distinction
decides whether any parallel approach can help: if a serial dependency chain were
the cost, overlapping independent accumulators would recover it. Running two,
three and four independent accumulators over the same data instead costs 0.51x,
0.67x and 0.75x of a *single stream's rate*, so the multiply throughput is
already what saturates and there is no idle chain to fill.

**The vector form is slower than the scalar one.** Two floors, measured
(min of 5x60 over three runs, GCC):

| | cycles/block |
|---|---|
| 25 scalar multiplies, no adds or carries | 24.1 |
| **`absorbBlock()` as it ships** | **45.7** |
| 13 `vpmuludq` packing those same 25 products | 26.3 |

So vectorising the multiply costs 1.06--1.09x, reproducibly. This is the same
trap the ChaCha20 attempts fell into in a different place: AVX2 has no
64x64->128 multiply -- that is AVX512IFMA -- so a 26x26 product is one
`vpmuludq` either way, and putting two in an instruction only saves one if the
operands already sit in the lanes `vpmuludq` reads. They do not; they have to be
shuffled into place first, and that costs more than the multiply it saves. The
adds, the carry chain and the reduction are all still owed on top.

The only route below the scalar floor is *fewer* multiplies rather than cheaper
ones, which needs 64x64->128 or the precomputed powers of `r` this roadmap
already names -- and neither has a usable instruction path for this recurrence on
this CPU. **The ChaCha20-Poly1305 throughput target is therefore closed as a
measured negative result.** In cycles/byte, which is how it should be judged
against other hardware: the landed AVX2 keystream is 1.47, the MAC is 2.88, and
the 1.5 GiB/s target is 2.43 for the two together -- missed by roughly 0.45
cycles/byte on the MAC side, which no multiplication-side vectorisation closes.

The wider scalar experiments stand and are not disturbed by this: three 44-bit
limbs with nine 64x64->128 products per block measured no faster than the
portable five-limb 26-bit path, and slower again once the carries went through
`_addcarry_u64`.

One methodological note, because it nearly produced a wrong conclusion here. A
first run of the multiply-floor probe reported 15% overhead and a later one 67%,
which was not measurement drift: the probe had failed to compile (a missing
`<immintrin.h>`) and the run script executed the stale binary left over from an
earlier edit. Every benchmark script used from here on removes its output binary
before compiling and exits if the build failed, because a benchmark that measures
a different program than the one edited is worse than no benchmark.

### P1 -- the RSA bottleneck, and a correction

Profiling the WSL Release build with `perf` put **36.7% of all cycles in
`CBigNum::divMod()`**, reached as `RsaContext::sign` -> `CBigNum::modExp` ->
`CBigNum::mulMod` -> `CBigNum::mod` -> `CBigNum::divMod`. The source agrees:

- `CBigNum::modExp()` (`bignum.cpp:913`) is an ordinary integer exponentiation
  and `CBigNum::mulMod()` (`bignum.cpp:763`) is still `mul()` then `mod()`.
- `CMontgomery::modExp()` (`montgomery.cpp:444`) exists, is Montgomery, and does
  not appear in the profile at all. Its callers are the prime curves
  (`eccurve.cpp:747`) and Ed448 (`ed448.cpp:65`).

So RSA performs a schoolbook long division for every modular multiplication in
a private-key operation, while code paths next to it use Montgomery. That
corrects a diagnosis the roadmap gave two commits earlier, which nominated the
Montgomery reduction's *shape* -- whether the accumulator was wide enough to
avoid a conditional subtract per step. The shape is not the question here: RSA
never reaches that code. It also reframes the cross-toolchain gap recorded
above. A 2.4x gap there reads as a codegen curiosity; more likely it is a shared
inefficiency both toolchains pay, differing only in degree. Two compilers do not
disagree by 2.4x about a division, but they do disagree about how expensive it is
once both are paying it.

The fix is to route `rsa.cpp`'s `CBigNum::modExp` calls (`rsa.cpp:433`, `:434`,
`:444`, `:463`, `:518`, `:627`, `:677`) through `CMontgomery`, and it is not a
small one. It touches the CRT blinding and its fault-attack countermeasures
(`rsa.cpp:417--444`), and the CRT constants `dp`, `dq` and `qInv` are derived
modulo *different* primes than `n`, so each half needs its own Montgomery
context rather than sharing one. `tests/` must go on proving that the CRT result
agrees with a full re-encrypt, which is the countermeasure that makes CRT worth
doing at all.

### How the profile was taken, and what it does not show

`perf record` over the whole harness rather than a purpose-built RSA-only
workload. RSA dominates wall clock in that run, so it dominates the profile, but
the 36.7% is a share of the entire process rather than of RSA signing alone. The
absence of `CMontgomery::modExp` from the profile is the load-bearing evidence;
the percentage is corroboration. A dedicated profile isolating
`RsaContext::sign` would give a sharper number, and should be the first thing
done when that work starts.
