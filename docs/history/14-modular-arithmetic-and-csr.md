# Modular arithmetic and certificate requests

[한국어](14-modular-arithmetic-and-csr.ko.md)

## `CMontgomery`: taking the long division out of every modular multiply

← [History](../HISTORY.md)

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
See [CONCEPTS.md](../CONCEPTS.md)'s entry for the API and the two domains
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

#### What was converted

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

#### The measured effect

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

#### Validation

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

← [History](../HISTORY.md)

CSR support had been listed as deliberately out of scope in both
[`CLAUDE.md`](../../CLAUDE.md) and [`docs/PLANS.md`](../PLANS.md). That changed
by the repository owner's decision, and this is what landed: `x509/csr.hpp`'s
`CCertRequest`/`CCertRequestBuilder`, plus the CA-side
`CCertBuilder::subjectFrom()`.

#### Four decisions, and why

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

#### The import verifies; it does not merely offer a `verify()`

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

#### The refactor

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

#### `attributes` is not optional

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

#### Testing: nothing that only talks to itself

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
