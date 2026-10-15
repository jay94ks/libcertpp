# Audit, documentation, and planning

[한국어](02-audit-and-planning.ko.md)

## Project-wide audit: memory safety, DER strictness, signature verification

← [History](../HISTORY.md)

A five-part read-only audit (utils/io/asn1, hashers/RNG/symmetric,
asymmetric/curves, x509/examples, and the docs against the code) produced the
fixes below. Two slices independently reported the same two defects — the
digest-truncation bug and the non-minimal INTEGER acceptance — which is part of
why both are described here in detail.

#### Memory safety

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

#### DER strictness at the untrusted boundary

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

#### Signature verification

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

#### Other correctness

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

← [History](../HISTORY.md)

Audited every claim in the docs against the code and corrected what had
drifted, which was concentrated at the newest edge of the library:

- **Seven extension class names in `CONCEPTS.md` did not exist** (16
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
- `BUILDING.md` gained the missing `CERTPP_BUILD_EXAMPLES` row, an Examples
  section (including `CERTPP_EXAMPLE_OUTPUT_DIR` and why the examples are
  deliberately not CTest cases), and the AddressSanitizer recipe that
  `build-asan/` implied but nothing documented.
- `RULES.md`'s buffer-handling rule now separates its two halves:
  the bulk-call half has exceptions, the raw-pointer half applies even to code
  that must stay a loop. `CbcTransformer` is the worked example.
- Both READMEs called `CBuffer` "a fixed-size owning byte buffer" — it is the
  resizable working buffer, `COctet` is the fixed-size one — and omitted
  `COctet`/`CBase64` entirely. The "no git history yet" premise in
  `HISTORY.md` and both READMEs is now true-as-of-then rather than false.
- `CLAUDE.md` claimed `x509` "parses (not yet generates)", listed neither the
  symmetric ciphers nor CRL/OCSP, and linked three of the five docs.

## Post-quantum: review tidied, implementation plan added

← [History](../HISTORY.md)

`docs/PQC.md` was written before any PQ code existed and had gone stale
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
