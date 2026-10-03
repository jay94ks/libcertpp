# Changelog

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
