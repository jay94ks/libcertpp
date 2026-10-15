# GOST and DNSSEC

[한국어](10-gost-and-dnssec.ko.md)

## GOST R 34.11-2012 (Streebog) and GOST R 34.10-2012

← [History](../HISTORY.md)

Added the Russian federal hash and signature standards, as new `IHasher` and
`IAsymmetric` implementations. The algorithms only; nothing in `x509/` knows
about them yet (see "What X.509 wiring would still need" below).

#### Streebog (`EHASH_STREEBOG256` / `EHASH_STREEBOG512`)

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

#### GOST R 34.10-2012 (`CGost3410`)

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

#### Validation

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

#### What X.509 wiring would still need

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

← [History](../HISTORY.md)

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

#### Two gaps the negative controls found in the vector set itself

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

#### RFC 4034 Appendix B.1 contradicts itself

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
