# Integration and real certificates

[한국어](11-integration-and-certificates.ko.md)

## Merging eight algorithms at once: what integration caught

← [History](../HISTORY.md)

The eight requested algorithms were implemented in parallel, each in its own
worktree, which means each was written against a tree that did not contain the
other seven. Most of what that costs is merge conflicts in the registration
points. Two things were more than that.

#### `EHashers` was renumbered, across an ABI boundary

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

#### A stale justification, and a check nothing had ever tested

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

← [History](../HISTORY.md)

`tests/x509/certs/unimplemented/` held a real, currently-valid commercial
intermediate -- "DigiCert QV G3 TS EUR RSA4096 RSASSA-PSS 2025 CA1", issued by
QuoVadis Root CA 1 G3 -- kept there because `importDer()` returned
`ERET_BADREQ` on it, with a test case asserting exactly that. The directory
name and the test's own title both blamed the signature algorithm. Both were
wrong about which gap actually failed the import, and they were wrong in a way
that is worth recording, because the misattribution survived being written down
in three places.

#### The gap that actually failed the import

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

#### RSASSA-PSS, the gap the directory name was about

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

#### What the tests can and cannot prove

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
