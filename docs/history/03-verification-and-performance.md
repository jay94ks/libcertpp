# Verification and arithmetic performance

[한국어](03-verification-and-performance.ko.md)

## Signature verification, external KAT vectors, and x509 parser hardening

← [History](../HISTORY.md)

The audit above left four things open that needed a decision rather than a
patch. All four were taken, in this order — tests first, because they are what
makes the rest safe to change.

#### External known-answer vectors (and what they immediately proved)

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

#### Adversarial DER tests

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

#### x509 parser hardening

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

#### Certificate and CRL signature verification

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

← [History](../HISTORY.md)

Two systemic choices in the arithmetic layer were each costing roughly an
order of magnitude. Both were bit-serial algorithms sitting underneath
everything else, and both were replaceable without touching a single
interface.

**The result, measured on the full test suite: 1243s to 140s, an 8.9x
speedup overall.** Individually, `crypto_asyms_rsa` went 85.7s to 6.1s
(~14x), `crypto_asyms_x25519` 445.6s to 39.5s (~11x), and
`crypto_asyms_dsa` 64.4s to 8.5s (~7.5x). All 88 tests still pass.

#### `CBigNum::divMod()` — Knuth's Algorithm D

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

#### `CGf2m::reduceWide()` — word-level polynomial reduction

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
