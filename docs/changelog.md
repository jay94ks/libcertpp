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
