# Post-Quantum Cryptography: Review and Implementation Plan

[한국어](pqc-review.ko.md)

This started as a preliminary design review -- "what would it take, and what should go
first" -- written before any post-quantum (PQ) code existed. Part of what it proposed has
since been built, so the review sections below have been corrected to describe what is
actually in the tree, and a concrete [implementation plan](#implementation-plan) is
appended at the end.

## Current status

| Item | State |
|---|---|
| `SHAKE128` (`crypto/hashers/shake128.hpp`) | **done** -- `EHASH_SHAKE128`, umbrella header, KAT tests |
| Shared `KeccakCore` (`src/crypto/hashers/keccakcore.hpp`) | **done** -- permutation + sponge absorb, shared by SHAKE128/SHAKE256 |
| `IKem`/`IKemContext` (`crypto/kem.hpp`) + KEM key family (`crypto/keys.hpp`) | **done** -- designed ahead of the algorithm, now with ML-KEM behind it; `EKems` has its three members and `IKem::builtIn()` dispatches them. In `certpp.hpp` |
| Incremental SHAKE squeezing (`SHAKE128`/`SHAKE256::squeeze()`) | **done** -- chunk-invariant streaming output, tested against `hashlib` across every chunk size and rate boundary |
| ML-KEM ring arithmetic (`src/crypto/kems/mlkemring.hpp`) | **done** -- NTT/inverse NTT/base-case multiply over R_q, q=3329; twiddle tables derived from ZETA and asserted entry by entry, NTT-domain multiply checked against a schoolbook negacyclic multiply |
| ML-KEM samplers + ByteEncode/ByteDecode/Compress | **done** -- `src/crypto/kems/mlkemcodec.hpp`; the samplers are now public as `CMlKemSampler` (`crypto/kems/mlkem.hpp`); pinned against an independent model by whole-array checksum |
| SHA3-256 / SHA3-512 (ML-KEM's H and G) | **done** -- a prerequisite this plan had missed; the library had SHAKE but no fixed-output SHA-3 |
| ML-KEM, the algorithm (`crypto/kems/mlkem.hpp`: `CMlKem`, `SMlKemParams`, `SMlKemPoly`) | **done** -- K-PKE plus the FO transform over raw spans, validated against ACVP for all three parameter sets including the implicit-rejection and key-check negative cases |
| ML-KEM as an `IKem` (`crypto/kems/mlkem.hpp`, `EKEM_MLKEM512/768/1024`) | **done** -- `MLKEM` serves all three sets from one class; keys serialize as FIPS 203's own encodings, and this is the only layer that draws from `CRng` |
| ML-DSA parameter sets (`src/crypto/asyms/mldsaparams.hpp`) | **done** -- FIPS 204 Table 1, with every key/signature length derived and `static_assert`ed against Table 2 |
| ML-DSA samplers (`src/crypto/asyms/mldsasampler.hpp`) | **done** -- SampleInBall/RejNTTPoly/RejBoundedPoly plus ExpandA/ExpandS/ExpandMask; pinned against known answers cross-checked with dilithium-py, including ExpandA's transposed seed order |
| ML-DSA bit packing + hint encoding (`src/crypto/asyms/mldsacodec.hpp`) | **done** -- SimpleBitPack/BitPack and their inverses, HintBitPack/HintBitUnpack with all three rejection conditions; the ranges decoding cannot guarantee are documented and `inRange()` provided for them |
| ML-DSA rounding/hints (`src/crypto/asyms/mldsarounding.hpp`) | **done** -- Power2Round/Decompose/HighBits/LowBits/MakeHint/UseHint; the inversion identity checked at the bucket boundaries and across Decompose's `(q-1)` band, which is a band of width gamma2 rather than the single point it reads as |
| ML-DSA ring arithmetic (q=8380417) | **done** -- `src/crypto/asyms/mldsaring.hpp`; complete 8-layer NTT (zeta's order is 512, unlike ML-KEM's 256, so the transform runs to completion and the NTT-domain multiply is pointwise), checked against FIPS 204 Appendix B's printed table and a schoolbook negacyclic multiply |
| ML-DSA | not started |
| X.509 OID/algorithm wiring for PQ | not started |

So Phases 1-4 are complete: ML-KEM works, matches NIST's vectors for all three parameter
sets, and is reachable both as the raw-span `CMlKem` (which is what let it be validated
straight from a test vector) and as `IKem::builtIn(EKEM_MLKEM768)` like every other algorithm
in the library. Phase 5 has started with its ring arithmetic, which indeed shares nothing with
ML-KEM's beyond the Keccak primitives and the general shape of an NTT -- `MlDsaRing` is a
separate unit, not a parameterization. Its rounding and hint machinery is in, and so is the bit packing -- including
`HintBitUnpack` with all three of its rejection conditions. The three rejection samplers, the Expand* procedures and the parameter table are in too. What
remains for ML-DSA is the key/signature encoders that sit on top of the bit packing
(`pkEncode`/`skEncode`/`sigEncode` and their inverses), and then sign/verify.

## Why this matters for libcertpp specifically

`libcertpp` is an X.509/ASN.1 library: its `crypto` module exists to make `x509::CCert`
parsing/building and signature verification work, and every `IAsymmetric` algorithm it
has today (RSA, DSA, `CEcdsa`/`CEcdsa2`, `Ed25519`/`Ed448`, `X25519`) is exactly the set a
real certificate or CMS/PKCS#7 structure can carry a key or signature for. The IETF LAMPS
working group has now **published** the X.509 profiles -- RFC 9881 (ML-DSA, 2025-10),
RFC 9909 (SLH-DSA, 2025-12) and RFC 9935 (ML-KEM, 2026-03) -- so the OIDs and the
SubjectPublicKeyInfo/signature encodings are settled rather than moving; composite
ML-DSA+ECDSA (`draft-ietf-lamps-pq-composite-sigs`) is IESG-approved and in the RFC Editor
queue. On the deprecation side, **NIST IR 8547** (initial public draft, 2024-11-12) proposes
deprecating 112-bit-security classical algorithms (RSA-2048, P-256, etc.) after 2030 and
disallowing them after 2035, with SP 800-131A Rev 3 (ipd, 2024-10-21) as its companion --
both still drafts, so treat the dates as direction rather than law. A certificate library has a
longer relevance horizon than most of the software that will eventually depend on it, so
PQ support isn't speculative -- it is eventually required for `x509::CCert` to parse and
verify every certificate it's handed.

## The standardized algorithms (status re-checked 2026-10-02)

NIST finalized three PQ standards in August 2024, plus a fourth already selected and
further candidates still in progress:

| Standard | Algorithm (prior name) | Category | Hardness assumption |
|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation (KEM) | Module-LWE (lattice) |
| FIPS 204 | ML-DSA (Dilithium) | Digital signature | Module-LWE / Module-SIS (lattice) |
| FIPS 205 | SLH-DSA (SPHINCS+) | Digital signature | Hash-function security only |
| FIPS 206 (in development; **no public draft** as of 2026-10-02) | FN-DSA (Falcon) | Digital signature | NTRU lattices (shortest-vector) |

NIST also selected **HQC** (Hamming Quasi-Cyclic, a code-based KEM) on 2025-03-11 as a
structurally independent backup to ML-KEM, specifically so a future break of lattice
assumptions wouldn't leave zero standardized PQ KEMs. It is planned as **FIPS 207**; no draft
has been published. (NIST has been reported as targeting finalization around 2027, but that
is secondhand -- no dated NIST page states it.) Treat it as a candidate to revisit, not a
target.

FIPS 203/204/205 were all finalized 2024-08-13 and are safe to rely on. FN-DSA and HQC are
the two moving parts, and neither is on the critical path for Phases 1-6.
**Re-checked 2026-10-02:** FIPS 206 still has no public draft, 25 months after FIPS 204, and
HQC is still pre-draft. Neither changes the plan -- if anything the FN-DSA gap makes
deferring it better justified than when this was first written. Also now relevant to the
`IKem` work: **SP 800-227, "Recommendations for Key-Encapsulation Mechanisms", went final
2025-09-18**, and is normative guidance for how a KEM should be exposed and used.

**Recommended scope for libcertpp: ML-KEM and ML-DSA only.** The original priority order
was ML-KEM first, for the reasons below; that ordering has since been revisited -- see
"[Re-evaluating the ML-KEM-first ordering](#re-evaluating-the-ml-kem-first-ordering)",
which is the current position.

- **ML-KEM first.** A KEM is needed before a signature scheme is, because TLS 1.3's PQ/
  hybrid key exchange (`X25519MLKEM768`, already shipping in major browsers and OpenSSL
  3.x) is the single most widely deployed PQ use case today, and because `libcertpp` had
  no KEM-shaped interface at all when this was written (see "Interface-level fit" below --
  one has since been declared) -- building the new interface shape against the simpler
  primitive first (no RNG-dependent domain parameters, no hash-then-sign construction, a
  single encapsulate/decapsulate round trip) is lower risk than building it against
  ML-DSA.
- **ML-DSA second**, as the signature algorithm `x509::CCert`/`CCertBuilder` actually need
  to parse/produce PQ-signed certificates. It reuses the same module-lattice machinery
  (NTT, `R_q = Z_q[X]/(X^256+1)`, centered binomial sampling) ML-KEM needs, so the two
  share most of their low-level arithmetic if implemented back to back -- see "Shared
  substrate" below.
- **SLH-DSA and FN-DSA: deliberately deferred, not rejected.** SLH-DSA's only advantage
  over ML-DSA is a more conservative hardness assumption (plain hash security instead of a
  lattice problem), at the cost of signatures roughly 30-50x larger (7856-49856 bytes vs.
  ML-DSA's 2420/3309/4627 bytes) and far slower signing (a full Merkle-tree-of-Merkle-trees
  walk per signature) -- a reasonable algorithm-agility fallback once ML-DSA exists, not a
  first target. FN-DSA (Falcon) gives the smallest PQ signatures of the three, but its
  signing algorithm requires sampling from a discrete Gaussian distribution over a lattice
  using floating-point arithmetic with specific rounding/precision guarantees to stay
  constant-time and avoid key-recovery via signature-distribution leakage -- a published,
  still-nontrivial-to-get-right construction (see "What's genuinely hard" below) that is
  reasonable to revisit once ML-KEM/ML-DSA are solid, not before.

## Interface-level fit

`IAsymmetric` (`include/certpp/crypto/asym.hpp`) is shaped around two operations:
`sign()`/`verify()` (hash-then-sign, bound via `IAsymmetricContext`) and
`createEncrypter()`/`createDecrypter()` (an `IAsymmetricTransformer` session, modeled on
RSA's single-block PKCS#1 encrypt/decrypt). Checking each PQ algorithm against that shape:

- **ML-DSA fits `sign()`/`verify()` directly.** It's a Fiat-Shamir-with-aborts signature
  scheme over a message digest, same shape as `ECdsa`/`Ed25519`'s existing `sign()`/
  `verify()` -- no new interface needed, just a new `IAsymmetric` implementation
  (`MLDSA` under `crypto/asyms/`, alongside the existing seven).
- **ML-KEM does not fit either existing shape.** A KEM's public operation
  (`Encaps(pk) -> (ciphertext, sharedSecret)`) produces a ciphertext *and* a fresh,
  caller-unspecified shared secret together -- it isn't "encrypt this plaintext I chose"
  the way `createEncrypter()` is shaped, and `Decaps(sk, ciphertext) -> sharedSecret`
  returns a secret, not a decrypted message. Forcing ML-KEM through
  `createEncrypter()`/`createDecrypter()` (e.g. by treating the shared secret as "the
  plaintext") would be a leaky, confusing abstraction. It therefore got **a new sibling
  interface**, which now exists: `IKem`/`IKemContext` in `crypto/kem.hpp`, mirroring
  `IAsymmetric`/`IAsymmetricContext`'s shape (key-size specs, `generateKeyPair()`,
  `checkPrivateKey()`, `createPublicKey()`/`createPrivateKey()`, `createContext()`) with
  `encapsulate()`/`decapsulate()` in place of sign/verify/encrypt/decrypt.

  Two details of the built interface differ from this review's original sketch, both
  deliberately:

  - `encapsulate(SByteSpan& ciphertext, SByteSpan& sharedSecret)` takes **no** public-key
    parameter. It acts on whichever key the context has bound, the same "operate on the
    bound key, not on an argument" convention `IAsymmetricContext::sign()`/`verify()`
    already follow -- the caller binds the peer's public key with the two-key
    `keyPair(peerPublicKey, nullptr)` overload. `decapsulate(const SReadOnlyByteSpan&
    ciphertext, SByteSpan& sharedSecret)` likewise acts on the bound private key.
  - KEM keys are **their own key family** (`EKems`, `IKemKeyBase`, `IKemPublicKey`,
    `IKemPrivateKey`, `SKemKeyPair` in `crypto/keys.hpp`), not reuses of
    `IPublicKey`/`IPrivateKey`. A KEM key is not a signature or Diffie-Hellman key even
    though it is asymmetric, which is the same reasoning `ESymmetrics` already applies to
    symmetric keys.

  Either way this was a bounded, additive change -- no existing interface changed shape,
  and `X25519` (this library's one existing pure-KEX algorithm) is left as-is rather than
  retrofitted onto `IKem`, since forcing a working Diffie-Hellman interface to match a
  KEM's encapsulate/decapsulate shape for symmetry's sake isn't worth the churn.

## Shared substrate: what ML-KEM and ML-DSA need, and what already exists

Both algorithms work over the same polynomial ring `R_q = Z_q[X]/(X^256+1)` (ML-KEM:
`q = 3329`; ML-DSA: `q = 8380417`) and both need:

1. **A SHAKE-based XOF/hash layer** for domain-separated expansion (matrix generation,
   sampling, the Fiat-Shamir challenge in ML-DSA) -- **and, for ML-KEM, fixed-output SHA-3.**
   This item originally claimed the hash layer was finished once SHAKE128 existed, which was
   wrong: FIPS 203 uses `H = SHA3-256` and `G = SHA3-512`, and the library had no fixed-output
   SHA-3 at all. Both were added (`EHASH_SHA3_256`/`EHASH_SHA3_512`), sharing `KeccakCore` with
   the XOFs and a new private `Sha3Core` with each other -- SHA-3 is the same sponge as SHAKE,
   differing only in the rate and in a `0x06` domain byte where SHAKE uses `0x1F`. ML-DSA needs
   no SHA-3: FIPS 204 is SHAKE-only. **Done.** FIPS 203/204 use SHAKE128 for
   matrix/vector expansion and SHAKE256 for everything else (G, H, the signing XOF), and
   both now exist: `SHAKE256` was already there, and `SHAKE128`
   (`crypto/hashers/shake128.hpp`, `EHASH_SHAKE128`) was added for this. The
   Keccak-f[1600] permutation and sponge absorption -- rate-independent, so identical for
   both -- were promoted out of `SHAKE256` into a shared `KeccakCore`
   (`src/crypto/hashers/keccakcore.hpp`), the same "shared private header+cpp" pattern
   this codebase already uses for `DesCore`/`Sha2_32Core`/`Sha2_64Core`. One caveat for
   the PQ work specifically: both XOFs expose a single fixed output length per instance
   (`IHasher::byteWidth()`, set at construction), so squeezing an *arbitrary-length*
   stream -- which is exactly how FIPS 203/204 use SHAKE128 for matrix expansion -- needs
   either a long enough instance up front or an incremental-squeeze entry point added to
   the two classes. See Phase 2 of the plan.
2. **Modular polynomial arithmetic mod q**: addition/subtraction (trivial), and
   multiplication, which needs the **Number-Theoretic Transform (NTT)** to be practical
   (naive schoolbook polynomial multiplication is used only for comparison/testing in
   every real implementation). This is **net-new** -- nothing in `CBigNum`/`CGf2m` covers
   it; `CBigNum` is arbitrary-precision over the integers (RSA/DSA-shaped, unbounded
   width), and `CGf2m` is GF(2^m) (binary-curve-shaped, XOR-based). Neither is a
   fixed-width, small-modulus (`< 2^23`), NTT-friendly ring element. A new `CPolyRing`-
   shaped type (likely under `utils/` or alongside the algorithm, given it's
   genuinely PQ-specific rather than a general-purpose number type) with forward/inverse
   NTT, pointwise multiplication, and Montgomery/Barrett reduction for the mod-q
   arithmetic is the central new primitive both algorithms are built on.
3. **Centered binomial / rejection sampling from the XOF output stream**, to turn
   uniform random/pseudorandom bytes into the small-coefficient "noise" polynomials the
   LWE-based security proof needs -- new, but straightforward given (1) and (2).
4. **A CSPRNG** for key generation and (ML-KEM) encapsulation randomness -- `CRng`
   already covers this exactly as-is; no new work.
5. **Encoding/packing**: compressing/decompressing polynomial coefficients to their
   wire-format bit-packed representation (FIPS 203 Algorithm 5/6, "ByteEncode"/
   "ByteDecode") -- new but mechanical, closer in spirit to this library's existing DER
   TLV encode/decode discipline (`asn1/der.hpp`) than to anything cryptographic.

So roughly: items 1 and 4 are done, and items 2/3/5 are the real new work -- concentrated
almost entirely in the NTT-based ring arithmetic, which both algorithms share.

## What's genuinely hard (where the risk actually is)

Unlike this library's existing asymmetric algorithms, **lattice-based PQ schemes are not
tolerant of this project's established "correctness over timing-hardening" stance**
(stated in `CEcCurve`'s own doc comments, and the reasoning behind leaving RSA's
PKCS#1 v1.5 Bleichenbacher-class timing structure unfixed -- see `docs/changelog.md`'s
security-audit entry). That stance works for RSA/ECDSA/EdDSA because those algorithms'
*designs* (well-chosen base points, projective coordinates, Montgomery ladders) already
remove most of the *structural* branches an attacker could exploit, even without a formal
constant-time guarantee. ML-KEM/ML-DSA don't have that luxury:

- **Rejection sampling is inherently data-dependent.** ML-DSA's signing algorithm
  generates a candidate signature and *rejects and retries* if any coefficient falls
  outside an acceptable range -- a naive implementation's retry count (and therefore its
  timing) leaks information about the secret key, which is exactly how several practical
  key-recovery attacks against early Dilithium/Kyber implementations worked. The
  reference/"hardened" implementations handle this with specific constant-time
  comparison and sampling patterns (and, for Kyber's decryption failure checks, explicit
  constant-time re-encryption comparison) that have to be followed precisely, not
  approximated.
- **ML-KEM decapsulation requires the Fujisaki-Okamoto (FO) transform's implicit
  rejection**, which is subtle to get right: a malformed/invalid ciphertext must not
  cause a decapsulation failure that's *observably different* (in timing or in the
  output) from a valid one -- the whole point of the FO transform is deriving the
  "failure" shared secret from a key-dependent PRF so an attacker can't distinguish
  "ciphertext rejected" from "ciphertext accepted," which is what makes a chosen-
  ciphertext attack against the underlying PKE infeasible against the KEM. This is a
  correctness-*and*-security requirement simultaneously, not just a performance concern.
- **NTT implementation bugs are easy to introduce and easy to miss**, because an off-by-
  one in a butterfly step or a wrong twiddle-factor table often still produces *a*
  self-consistent result that round-trips correctly in isolation (forward-NTT then
  inverse-NTT recovers the input) while silently being incompatible with the standard's
  exact intermediate representation -- which matters because FIPS 203/204 fix the NTT's
  exact algorithm (not just its end-to-end behavior) as part of the specification, for
  interoperability. Needs byte-exact validation against the official ACVP/NIST known-
  answer-test vectors, not just self-consistency, echoing this project's own established
  lesson (the P-521 order transcription errors, the SHAKE256 rotation-table
  transposition, the `CBigNum::mul()` ADX carry-propagation bug -- each one "looked
  reasonable" and passed a self-consistency check before a KAT vector caught it).

  The audit recorded in [`changelog.md`](changelog.md) added a sharper version of the same
  lesson, and it is worth stating plainly here because it is the exact failure mode PQ work
  invites: ECDSA's FIPS 186-4 digest truncation was *byte*-granular instead of
  *bit*-granular, so over the eight binary curves whose subgroup order is not byte-aligned
  this library produced signatures that verified perfectly against itself and against
  nothing else. It passed every test for as long as it existed, because the per-curve tests
  only ever signed and then verified their own output. An NTT with a wrong twiddle table
  fails in precisely that shape. **A self-consistent round trip is not evidence of
  correctness for anything whose wire format is specified**; external ACVP vectors are not
  optional polish on this work, they are the only thing that can detect this class of bug.
- **Side-channel surface is larger than this library has dealt with before.** Table
  lookups indexed by secret data (common in rejection sampling and encoding) are a
  cache-timing risk even when the *algorithm* is otherwise constant-time -- something
  this library's existing constant-time work (`CbcTransformer`'s padding check,
  `CEcCurve`/`CEc2Curve`/`Ed25519`/`Ed448`'s branch-free scalar multiplication) hasn't had
  to confront, since those are all straight-line arithmetic without data-dependent table
  indexing.

None of this is a reason not to proceed -- it's the reason ML-KEM/ML-DSA should be
implemented carefully against the ACVP KAT suite from the start (not retrofitted onto a
"working" implementation later, the way the non-constant-time stance got grandfathered
into the classical algorithms), and reviewed specifically for data-dependent branches/
table indices as a distinct pass from ordinary correctness testing.

## Dependency stance

Consistent with every other algorithm in this library (RSA/DSA/ECDSA/EdDSA/X25519/AES/
DES/ChaCha20, all from scratch, no third-party crypto dependency): **implement ML-KEM/
ML-DSA from scratch**, reusing `CRng`/`SHAKE256` and the new shared Keccak/NTT primitives
described above. The NIST reference implementations and well-audited open-source ports
(e.g. the `pq-crystals` reference code) are appropriate to consult for the algorithm
*and* for its documented constant-time patterns, and the ACVP KAT vectors are the
appropriate correctness oracle -- but no code should be vendored in, matching
`third-party/`'s current scope (doctest only, test-only).

## Re-evaluating the ML-KEM-first ordering

This review originally put ML-KEM ahead of ML-DSA. Two of the three reasons it gave have
since weakened, so the ordering is worth restating rather than inherited:

- *"`libcertpp` has no KEM-shaped interface at all yet, and building it against the simpler
  primitive is lower risk."* Mostly spent: `IKem`/`IKemContext` has since been designed and
  declared. What remains is implementing against it, which is no longer the interface-design
  risk the argument was about.
- *"TLS 1.3 hybrid key exchange is the most widely deployed PQ use case."* True of the
  industry, but not an argument about **this** library: `libcertpp` is an X.509/ASN.1
  library with no TLS stack, so nothing inside it consumes a KEM. ML-KEM would ship with no
  in-tree caller; ML-DSA directly unblocks `CCert`/`CCertBuilder`.
- *"ML-KEM is the simpler primitive."* Still true, and still a real argument -- ML-DSA adds
  rejection sampling with aborts, hint encoding, and a constant-time retry loop on top of
  the same ring arithmetic.

There is also now a concrete, in-tree thing ML-DSA would fix.
`tests/x509/certs/unimplemented/identrust-mldsa-root.der` is a real, currently-valid
self-signed ML-DSA pilot root ("IdenTrust Pilot Root TLS ML-DSA CA 1", signature/key OID
`2.16.840.1.101.3.4.3.19` from NIST's CSOR ML-DSA arc), and
`tests/x509/realcerts.cpp` already asserts that `CCert` parses all of it -- subject,
issuer, validity, BasicConstraints, KeyUsage, ExtendedKeyUsage, SKI, AKI -- and resolves
the algorithm to nothing. Every part of that certificate except its algorithm is already
supported.

**Recommendation: keep ML-KEM first for the shared substrate's sake, but treat the order as
genuinely open.** Phases 2-3 below are a prerequisite either way; if the goal is to make
this library parse and verify the PQ certificates that already exist in the wild, swapping
Phases 4 and 5 is the better call and costs nothing structurally -- the ring arithmetic,
the encoding helpers and the X.509 wiring are shared regardless of which algorithm lands
first. This is a decision to make at Phase 4, not now.

## The test vectors, located and validated up front

Phases 4-6 are gated on NIST's ACVP vectors, so they were found and checked before any
algorithm work started -- the same ordering that made the Knuth-D and ECDSA-truncation work
safe. Both sets live in `usnistgov/ACVP-Server` under
`gen-val/json-files/<DIR>/<FILE>`, fetched as:

```
https://raw.githubusercontent.com/usnistgov/ACVP-Server/<rev>/gen-val/json-files/<DIR>/<FILE>
```

Pin `<rev>` rather than tracking `master`; `975de31eb83d87039ec88934fdc47d8c312b892d` is
`master` HEAD as of 2026-08-12 and is what the figures below were measured against.

| Algorithm | `<DIR>` | Coverage |
|---|---|---|
| ML-KEM | `ML-KEM-keyGen-FIPS203` | 75 cases (25 per parameter set) |
| ML-KEM | `ML-KEM-encapDecap-FIPS203` | 75 encapsulation, 30 decapsulation, plus key-validity groups |
| ML-DSA | `ML-DSA-keyGen-FIPS204` | 75 cases (25 per parameter set) |
| ML-DSA | `ML-DSA-sigGen-FIPS204` | 24 groups x 15 = 360 cases |
| ML-DSA | `ML-DSA-sigVer-FIPS204` | 12 groups x 15 = 180 cases, 144 of them negative |

Use `internalProjection.json`: it is the only file carrying inputs *and* expected outputs in
one record (`prompt.json` has inputs, `expectedResults.json` outputs, joined on `tcId`). All
byte fields are uppercase hex, no `0x`. The parameter set lives on the *group*, never on the
individual test.

What the validation established, beyond the files merely existing:

- **Every declared field length matches the standards' own parameter tables** -- FIPS 203
  Table 3 and FIPS 204 Table 2 -- across all 180 ML-KEM and 615 ML-DSA records, with the
  FIPS 204 sizes additionally re-derived from Table 1's parameters via the encoding formulas.
  No disagreement anywhere.
- **The ML-KEM implicit-rejection oracle is real, not a relabelled happy path.** All 45
  `reason: "modified ciphertext"` decapsulation cases satisfy `k == SHAKE256(z || c, 32)`
  (FIPS 203's `J(z || c)`), and none of the valid cases do -- a clean separation, which is
  exactly what is needed to test the Fujisaki-Okamoto path that must return a key-derived
  pseudorandom secret rather than an error.
- **The ML-DSA vectors were re-run against an independent implementation** (PyPI
  `dilithium-py`, used as an oracle only -- nothing vendored): keyGen 75/75 and sigGen 360/360
  byte-exact, sigVer 180/180 verdicts agreeing. So they are confirmed usable by a second
  implementation rather than only self-consistent.
- **ML-DSA's negative coverage is the decode path**, evenly split 36 each across modified
  message, modified commitment, modified hint and modified `z` -- which is precisely where the
  malleability traps below live.
- **Hedged ML-DSA signatures are byte-reproducible too**, because the prompt supplies `rnd`.
  An earlier version of this plan assumed only the deterministic variant could be compared
  against a vector; in fact all 24 sigGen groups can be.

## Implementation plan

Each phase ends in a green `ctest` run and is independently committable. "KAT" below means
NIST's ACVP vectors for the algorithm in question, fetched and transcribed the same way
`tests/crypto/hashers/shake128.cpp`'s NIST vector already was -- and cross-checked against
a second independent implementation, per the lesson restated under "What's genuinely hard".

### Phase 1 -- close out the KEM interface (small) -- **done**

- `src/crypto/kem.cpp` now defines `IKem::builtIn(EKems)`, mirroring
  `src/crypto/asym.cpp`'s `IAsymmetric::builtIn()` dispatch. It returns `nullptr` for every
  input until Phase 4 adds the first parameter set, which is the honest behaviour and,
  unlike the missing definition it replaced, links rather than failing at link time.
- `crypto/kem.hpp` is still deliberately **out** of `include/certpp.hpp`. Including a header
  whose only factory cannot return anything would advertise an API that does not exist yet;
  it goes in with Phase 4, in the same change that gives `EKems` its first member.
  [`architecture.md`](architecture.md) records this as intentional.

### Phase 2 -- incremental SHAKE squeezing (small, blocking) -- **done**

FIPS 203's `SampleNTT` rejection-samples from an unbounded SHAKE128 stream, and FIPS 204
does the same for its challenge/mask expansion, but `SHAKE128`/`SHAKE256` exposed only a
single fixed-length `finish()` from offset 0 -- no way to stream.

Both now have `squeeze(const SByteSpan&)`: it finalizes absorption on first call exactly as
`finish()` does, then returns successive chunks of the output stream, advancing the sponge
and tracking a cursor within the current rate block. Output length is independent of
`byteWidth()`, which is the whole point. The padding step both entry points need was
factored into a shared `finalizeAbsorption()` rather than duplicated.

`finish()` keeps squeezing from a *copy*, so it stays repeatable and leaves the cursor
alone; the two are documented as alternatives rather than to be interleaved. The property
worth testing is chunk-invariance, and `tests/crypto/hashers/shake_squeeze.cpp` asserts it
across every chunk size from 1 byte up, including splits landing exactly on, just before and
just after each rate boundary (168 for SHAKE128, 136 for SHAKE256) -- that boundary is where
the sponge permutes, so a cursor off-by-one would show up nowhere else. Expected streams come
from Python's `hashlib`, three rate blocks plus seven bytes long.

### Phase 3 -- the shared ring arithmetic (the real work) -- **done for ML-KEM**

A set of private units with no public headers yet -- nothing here
belongs in the API until an algorithm needs to expose it, and per the conventions an
implementation class under `src/` takes no type prefix:

- `MlKemRing`/`MlDsaRing` or one parameterized `PolyRing` over
  `R_q = Z_q[X]/(X^256+1)`: coefficient add/sub, Montgomery and Barrett reduction,
  forward/inverse NTT, and pointwise multiplication. ML-KEM uses `q = 3329`, ML-DSA
  `q = 8380417`; decide between one template and two concrete types once both are written,
  not before -- the project's standing preference is two clear copies over a speculative
  abstraction.
- The zeta/twiddle tables, derived from the root of unity at runtime rather than
  hand-transcribed, and asserted entry by entry.

  A correction to an earlier version of this plan: **FIPS 203 contains no worked examples and
  no intermediate values at all.** Its only appendices are A (the precomputed NTT zeta table),
  B (SampleNTT loop bounds) and C (differences from CRYSTALS-KYBER), and NIST publishes no
  example-values page for ML-KEM either. FIPS 204 is the same -- no end-to-end intermediates,
  though its Appendix B does give the full `zetas[0..255]` table. So the oracle available is:
  assert the tables against their defining powers of the root of unity, check the forward and
  inverse transforms round-trip, check the NTT-domain multiply against a schoolbook negacyclic
  multiply, and then rely on the end-to-end ACVP vectors. Those do pin the NTT convention
  transitively -- a transposed twiddle order changes `ek` and `c` byte for byte -- so the bug is
  still caught; it simply won't be localized to a butterfly.
- Centered binomial sampling and the rejection sampler over the Phase 2 XOF stream.
  Both now exist as `MlKemSampler` (`src/crypto/kems/mlkemsampler.cpp`). `sampleNtt()` is the
  first real consumer of `SHAKE128::squeeze()`, and it justifies Phase 2 concretely: it
  consumes 453-498 bytes of stream depending on the seed -- three-ish rate blocks, with no
  length knowable in advance.
- `ByteEncode`/`ByteDecode` bit-packing (FIPS 203 Algorithms 5/6) and `Compress`/`Decompress`
  (Algorithms 3/4), now `MlKemCodec` (`src/crypto/kems/mlkemcodec.hpp`). The compression
  rounding was checked against the exact rational definition for *every* coefficient in
  [0, q) at every width ML-KEM uses, which settled a detail worth not guessing at: q is odd,
  so the usual `(x*2^d + q/2)/q` truncates `q/2` and leaves the round-half-up tie rule to
  luck. Both that form and the provably-correct `(2*x*2^d + q)/(2*q)` do agree everywhere --
  but only one of them is right by construction, and that is the one implemented.
  `isCanonical12()` exposes the deliberate non-injectivity of `ByteDecode_12` as its own
  query, since ML-KEM's encapsulation-key validity check is exactly "does this decode with no
  12-bit segment at or above q".

Validation gate before anything is built on top: forward-then-inverse NTT round trip, the
NTT-domain multiply against a schoolbook negacyclic reference, the ring's defining identity
(`X^256 == -1`) asserted directly, and every twiddle re-derived from the root of unity
independently of how the implementation builds it. **Done for ML-KEM's ring** -- see
`tests/crypto/kems/mlkemring.cpp`, and note `CMakeLists.txt` compiles those private units straight
into those tests, since the lattice arithmetic has no public API and so is not exported.

### Phase 4 -- ML-KEM (`IKem`'s first implementation) -- **done**

- `include/certpp/crypto/kems/mlkem.hpp` + `src/crypto/kems/mlkem.cpp` hold `CMlKem`: K-PKE
  (Algorithms 13-15) and the FO transform over it (Algorithms 16-18), with **implicit
  rejection** -- a malformed ciphertext yields `J(z || c)`, a key-derived pseudorandom
  secret, and `decapsulate()` has no failure mode for a bad ciphertext at all. Plus
  `SMlKemParams` (the three parameter sets, with every size derived from the five tabulated
  figures) and `CMlKemSampler`/`SMlKemPoly`, promoted out of `src/` because the raw-span
  form is useful on its own -- for interoperability testing, for a caller that already owns
  its buffers, and for anyone who wants K-PKE rather than the KEM.
- Gate met: `tests/crypto/kems/kat_mlkem.cpp` drives ACVP keyGen/encapsulation/decapsulation
  vectors for all three parameter sets, including the `modified ciphertext` records (whose
  expected shared secret ACVP publishes, because implicit rejection is a defined output
  rather than an error path) and the `encapsulationKeyCheck`/`decapsulationKeyCheck`
  negative records. A separate round-trip case flips one ciphertext bit and asserts
  decapsulation still succeeds, returns a different secret, and returns the *same* different
  secret when asked twice.
- `SMlKemParams::isValid()`, which every `CMlKem` entry point calls first. Publishing the
  parameter struct means a caller can hand over a set the standard never defined, and the
  implementation sizes fixed-capacity buffers from `MAX_K`/`maxCiphertextBytes()` -- so
  anything but the three FIPS 203 sets has to be refused before a single size is derived
  from it. A test case checks all eight entry points reject one, with every span sized
  correctly *for the bogus set* so the length checks cannot be what rejects them.
- `include/certpp/crypto/kems/mlkem.hpp` + `src/crypto/kems/mlkem.cpp` hold `MLKEM`,
  mirroring how `crypto/asyms/` holds one file per `IAsymmetric`. `EKems` gained
  `EKEM_MLKEM512`/`EKEM_MLKEM768`/`EKEM_MLKEM1024`, all three dispatched to the one class
  with the parameter set as constructor state, as `CEcdsa` does across its curves. Private
  `MlKemPublicKey`/`MlKemPrivateKey`/`MlKemContext` sit over `CMlKem` and reimplement
  nothing. `crypto/kem.hpp` and `crypto/kems/mlkem.hpp` are both in `certpp.hpp`.
- `keySizes()` accepts the parameter set's own number (512/768/1024) and not a modulus
  width or a security strength, since ML-KEM has no size that scales and those three
  figures are names. Keys serialize as FIPS 203's own byte encodings; a decapsulation key
  embeds its encapsulation key, so `publicKey()` reads it out rather than recomputing it,
  and `checkPrivateKey()`/`createPrivateKey()` verify the embedded `H(ek)` and the `ek`'s
  canonicality rather than trusting either. The SubjectPublicKeyInfo wrapping for
  certificates is Phase 6, not here.
- This is also where the CSPRNG enters, and the only place it does.
  `CMlKem::generateKeyPair()`/`encapsulate()` take their seeds and message as parameters,
  which is what makes them reproducible from a vector; `IKemContext::encapsulate()` has no
  such parameter, so `MLKEM` fills them from `CRng`. Which also means there is no
  known-answer test available at this layer: `tests/crypto/kems/mlkem.cpp` covers what the
  wrapper adds, including that repeated `encapsulate()` calls against one key differ (a
  shared secret that was a function of the key alone would be reused every session) and
  that a tampered ciphertext comes back `ERET_OK` with a different secret rather than an
  error code.

Three details here were easy to get wrong and expensive to discover late:

- **`G(d || k)`, not `G(d)`** (Alg. 13 step 1): the parameter-set byte `k` in {2,3,4} is
  appended as byte 33. This was added *after* FIPS 203's initial public draft, so round-3
  Kyber code and any pre-final implementation omit it -- copying from either silently breaks
  all three parameter sets while still being perfectly self-consistent.
- **`SampleNTT(rho || j || i)`** (Alg. 13 step 5 / Alg. 14 step 6): the index bytes are
  **transposed** relative to the loop order, and the spec's own margin note says so
  explicitly. Encrypt uses the transpose of the matrix but samples with the same byte order.
- **`ByteDecode_12` reduces mod q and is therefore not injective**: 12-bit segments in
  3329..4095 exist but cannot come from `ByteEncode_12`. That asymmetry *is* the
  `encapsulationKeyCheck` test -- ACVP's failing cases carry
  `reason: "noisy linear system values too large"`. `decapsulationKeyCheck` failures instead
  use `reason: "modified H"`, the embedded `SHA3-256(ek)` field.

Both held up in practice. `eta` is only an output length in `PRF_eta`, **not** domain
separation, so `PRF_2` and `PRF_3` on identical input share a prefix -- the implementation
passes `eta` as a length and nothing else.

FIPS 203's requirement that the implicit-reject flag and the values around it be destroyed
before `Decaps_internal` returns is met, via `CSecure::zero()` (`utils/secure.hpp`), which
was added for it. `decapsulate()` has a single exit so the clearing cannot be skipped by an
error path. The same pass found and fixed something worse than the missing zeroization: the
re-encryption check was a `std::memcmp`, which stops at the first mismatch and so leaked the
matching prefix's length through its running time, and the verdict then drove a ternary.
Both are now `CSecure::equalsMask` + `CSecure::select`, so neither the comparison nor the
choice branches on anything secret.

The same primitive has since been applied across the pre-quantum algorithms too -- the
ECDSA/DSA signing nonces, EdDSA's nonce and expanded seed, X25519's scalar and shared secret,
and RSA's CRT intermediates -- via `CSecure::zero()` and `CBigNum::secureClear()`.

### Phase 5 -- ML-DSA (a new `IAsymmetric`)

- `include/certpp/crypto/asyms/mldsa.hpp` + `src/crypto/asyms/mldsa.cpp`; `EAsymmetrics`
  gains `EASYM_MLDSA44`, `EASYM_MLDSA65`, `EASYM_MLDSA87`, dispatched from
  `IAsymmetric::builtIn()`. No interface change -- it fits `sign()`/`verify()` as-is.
- Note one shape mismatch to settle explicitly: ML-DSA signs a *message*, not a digest
  (it does its own hashing internally), so like `Ed25519`/`Ed448` it belongs in the
  `sizeOfDigest() == 0`, "the digest parameter is the raw message" convention those two
  already established -- and `CCert`'s `EHASH_UNKNOWN`-means-self-hashing paths must be
  taught about it rather than inferring EdDSA.
- The signing retry loop must be constant-time with respect to the secret: no early exit
  whose iteration count depends on key material. **FIPS 204 Appendix C is the authority**: it
  says implementations *should not* bound the four indeterminate loops
  (`Sign_internal`, `RejBoundedPoly`, `RejNTTPoly`, `SampleInBall`), and that if they do, the
  limits must be at least Table 3's (814 / 481 / 298 / 121 iterations respectively). If a
  maximum is exceeded, all intermediate results **shall** be destroyed and the return value or
  exception **shall be identical** for every such execution -- an observable difference there
  is the leak. All three `Rej*` samplers read the incremental XOF (§3.7), which is why Phase 2
  was a hard prerequisite rather than a convenience.
- **Hint encoding (Alg. 20/21) is the sharpest decode trap.** `HintBitUnpack` must return
  failure on three distinct conditions: an out-of-range cumulative index, positions that are
  not strictly increasing within a polynomial, and any non-zero leftover byte. Implement fewer
  than all three and malleable signatures are accepted -- which is exactly what ACVP's 36
  "modified signature - hint" cases hit.
- **Verification shall reject on length alone** (§3.6.2): a signature or public key whose
  size differs from the standard's is invalid before any arithmetic runs. Cheap, mandatory,
  easy to leave out.
- **No floating-point arithmetic anywhere** (§3.6.4), and sensitive intermediates must be
  destroyed as soon as they are no longer needed (§3.6.3) -- which the spec extends to
  *verification* intermediates, not just signing. The two carve-outs are the seed (may be kept
  for key regeneration) and the expanded matrix (public, needs no protection).
- ML-DSA's ring is a *different* ring: q = 8380417 and zeta = 1753, a 512th root of unity, so
  `zetas[0..255] = zeta^BitRev8(k)`. **FIPS 204 Appendix B prints that whole table**, which
  makes it directly assertable -- and Appendix A warns the array is usually stored in
  Montgomery form, so a representation mismatch there is the self-consistent-but-wrong failure
  mode again.
- Gate: ACVP keygen/sigGen/sigVer vectors for all three parameter sets. Both the deterministic
  and the hedged groups are byte-comparable, since the prompt supplies `rnd` -- so all 24
  sigGen groups count, not just the twelve deterministic ones.

### Phase 6 -- X.509 integration (what makes it useful here)

- Register the OIDs in `src/x509/cert.cpp`'s `SIG_ALGOS` and key-algorithm tables. These are
  now fixed by published RFCs rather than needing to be inferred:
  **RFC 9881** assigns ML-DSA under `sigAlgs` (2.16.840.1.101.3.4.3) as `.17` = ML-DSA-44,
  `.18` = ML-DSA-65, `.19` = ML-DSA-87; **RFC 9935** assigns ML-KEM under `kems`
  (2.16.840.1.101.3.4.4) as `.1`/`.2`/`.3` = 512/768/1024.
- So the in-tree IdenTrust fixture, whose OID is `2.16.840.1.101.3.4.3.19`, is
  **ML-DSA-87** -- flipping it to `certs/implemented/` needs that parameter set specifically,
  not merely "some ML-DSA".
- `AlgorithmIdentifier.parameters` **MUST be absent** for both (RFC 9881 §2, RFC 9935), not
  NULL -- matching the ECDSA/EdDSA convention `cert.cpp` already implements rather than the
  RSA/DSA one. The fixture confirms it: each of its three algorithm identifiers is an 11-byte
  SEQUENCE containing only the OID.
- `subjectPublicKey` carries the **raw** FIPS 204 public key bytes with no OCTET STRING
  wrapper, and `signatureValue` the raw signature.
- Do **not** register the HashML-DSA OIDs (`sigAlgs .32`-`.34`): RFC 9881 §8.3 says they MUST
  NOT appear in X.509 certificates.
- Acceptance test: `tests/x509/realcerts.cpp`'s IdenTrust ML-DSA root moves from
  `certs/unimplemented/` to `certs/implemented/`, with its algorithm resolved and -- once
  the signature-verification API noted as missing in
  [`architecture.md`](architecture.md)'s "Where this will grow" exists -- its self-signature
  actually verified. That single fixture flipping is the clearest possible definition of
  done for this work.
- `CCertBuilder` gains the ability to issue ML-DSA-signed certificates, which follows from
  the `IAsymmetric` implementation with no builder changes beyond the algorithm tables.

### Phase 7 -- re-evaluate the rest

Revisit SLH-DSA, FN-DSA and HQC once Phases 3-6 are solid and this review's "genuinely
hard" risks have a track record here. As of the 2026-10-02 re-check, FN-DSA has no public
draft and HQC is pre-draft, so there is nothing to implement against for either.

Hybrid/composite certificates are a different situation: `draft-ietf-lamps-pq-composite-sigs`
is IESG-approved and in the RFC Editor queue, so the **encoding is effectively frozen** and
the open question is demand rather than specification. Worth noting for scoping: the
CA/Browser Forum permits PQ for S/MIME (ballot SMC013, effective 2025-08-22) but **not yet
for public TLS**, so PQ TLS roots remain pilots -- which is exactly the status of the
IdenTrust fixture in this repository.

Every phase gets its own doctest suite under `tests/crypto/` (or `tests/x509/`), mirroring
every other algorithm's KAT-based tests. Phases 4 and 5 additionally get a dedicated review
pass for data-dependent branches and secret-indexed table lookups, separate from the
functional test pass -- that review is part of the phase, not a follow-up to it.
