# Post-Quantum Cryptography: Review and Implementation Plan

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
| `IKem`/`IKemContext` (`crypto/kem.hpp`) + KEM key family (`crypto/keys.hpp`) | **declared**; `IKem::builtIn()` defined in `src/crypto/kem.cpp` and returns null, since `EKems` has no concrete members yet. Deliberately not in `certpp.hpp` until an algorithm is behind it |
| Incremental SHAKE squeezing (`SHAKE128`/`SHAKE256::squeeze()`) | **done** -- chunk-invariant streaming output, tested against `hashlib` across every chunk size and rate boundary |
| NTT ring arithmetic (`R_q`) | not started |
| ML-KEM | not started |
| ML-DSA | not started |
| X.509 OID/algorithm wiring for PQ | not started |

So the groundwork is finished and the next step is the ring arithmetic. One thing the
"declared" row above still implies: `EKems` has no concrete enumerators yet
(`EKEM_MAX = 0`), so `IKem::builtIn()` has nothing to dispatch to and correctly returns
null for every input. Phase 4 gives it its first member.

## Why this matters for libcertpp specifically

`libcertpp` is an X.509/ASN.1 library: its `crypto` module exists to make `x509::CCert`
parsing/building and signature verification work, and every `IAsymmetric` algorithm it
has today (RSA, DSA, `CEcdsa`/`CEcdsa2`, `Ed25519`/`Ed448`, `X25519`) is exactly the set a
real certificate or CMS/PKCS#7 structure can carry a key or signature for. The CA/Browser
Forum and IETF LAMPS working group have already begun standardizing PQ and PQ/classical
hybrid certificate profiles (composite ML-DSA/ECDSA SubjectPublicKeyInfo and signature
encodings, dedicated OIDs for ML-DSA/SLH-DSA/ML-KEM), and NIST's own migration timeline
(SP 800-131A revisions) targets deprecating 112-bit-security classical algorithms
(RSA-2048, P-256, etc.) by 2030 and disallowing them by 2035. A certificate library has a
longer relevance horizon than most of the software that will eventually depend on it, so
PQ support isn't speculative -- it is eventually required for `x509::CCert` to parse and
verify every certificate it's handed.

## The standardized algorithms (as of this review)

NIST finalized three PQ standards in August 2024, plus a fourth already selected and
further candidates still in progress:

| Standard | Algorithm (prior name) | Category | Hardness assumption |
|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation (KEM) | Module-LWE (lattice) |
| FIPS 204 | ML-DSA (Dilithium) | Digital signature | Module-LWE / Module-SIS (lattice) |
| FIPS 205 | SLH-DSA (SPHINCS+) | Digital signature | Hash-function security only |
| FIPS 206 (draft, not finalized at the time of writing) | FN-DSA (Falcon) | Digital signature | NTRU lattices (shortest-vector) |

NIST also selected **HQC** (Hamming Quasi-Cyclic, a code-based KEM) in March 2025 as a
structurally independent backup to ML-KEM, specifically so a future break of lattice
assumptions wouldn't leave zero standardized PQ KEMs; it's expected to reach its own FIPS
draft after ML-KEM/ML-DSA/SLH-DSA, but the exact timeline wasn't firm as of this review --
treat it as a candidate to revisit, not yet a target.

The FIPS 203/204/205 finalizations are settled history and safe to rely on. FN-DSA's and
HQC's status are the two moving parts, and neither is on the critical path for Phases 1-6
of the plan -- re-check both at Phase 7 rather than tracking them here, since this document
will go stale on them faster than anything else it says.

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
  ML-DSA's 2420-4595 bytes) and far slower signing (a full Merkle-tree-of-Merkle-trees
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
   sampling, the Fiat-Shamir challenge in ML-DSA). **Done.** FIPS 203/204 use SHAKE128 for
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
   shaped type (likely under `utils/` or a new `crypto/pq/` submodule, given it's
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

### Phase 3 -- the shared ring arithmetic (the real work)

A new private submodule, `src/crypto/pq/`, with no public headers yet -- nothing here
belongs in the API until an algorithm needs to expose it, and per the conventions an
implementation class under `src/` takes no type prefix:

- `MlKemRing`/`MlDsaRing` or one parameterized `PolyRing` over
  `R_q = Z_q[X]/(X^256+1)`: coefficient add/sub, Montgomery and Barrett reduction,
  forward/inverse NTT, and pointwise multiplication. ML-KEM uses `q = 3329`, ML-DSA
  `q = 8380417`; decide between one template and two concrete types once both are written,
  not before -- the project's standing preference is two clear copies over a speculative
  abstraction.
- The zeta/twiddle tables, generated by a checked-in script rather than hand-transcribed,
  and asserted against FIPS 203 Appendix A / FIPS 204's own worked examples.
- Centered binomial sampling and the rejection sampler over the Phase 2 XOF stream.
- `ByteEncode`/`ByteDecode` bit-packing (FIPS 203 Algorithms 5/6).

Validation gate before anything is built on top: forward-then-inverse NTT round trip, NTT
against a schoolbook reference multiplication, and -- the part that actually matters -- the
exact intermediate NTT representation against the standard's worked example.

### Phase 4 -- ML-KEM (`IKem`'s first implementation)

- `include/certpp/crypto/kems/mlkem.hpp` + `src/crypto/kems/mlkem.cpp`, mirroring how
  `crypto/asyms/` holds one file per `IAsymmetric`. `EKems` gains `EKEM_MLKEM512`,
  `EKEM_MLKEM768`, `EKEM_MLKEM1024`; `IKem::builtIn()` dispatches them.
- K-PKE (the underlying public-key encryption) first, then the FO transform on top:
  keygen, encapsulate, decapsulate with **implicit rejection** -- a malformed ciphertext
  must yield a key-derived pseudorandom shared secret, indistinguishable in both value and
  timing from success. Private `MlKemPublicKey`/`MlKemPrivateKey` implement
  `IKemPublicKey`/`IKemPrivateKey`.
- Keys serialize as FIPS 203's own byte encodings. The SubjectPublicKeyInfo wrapping for
  certificates is Phase 6, not here.
- Gate: ACVP keygen/encapDecap vectors for all three parameter sets, plus a
  wrong-ciphertext test asserting decapsulation returns a *different but well-formed*
  secret rather than an error.

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
  whose iteration count depends on key material.
- Gate: ACVP keygen/siggen/sigver vectors for all three parameter sets, including the
  deterministic (non-hedged) variant so signatures are byte-comparable against the vectors.

### Phase 6 -- X.509 integration (what makes it useful here)

- Register the OIDs in `src/x509/cert.cpp`'s `SIG_ALGOS` and key-algorithm tables:
  ML-DSA-44/65/87 and ML-KEM-512/768/1024 from NIST's CSOR arcs. Confirm every OID against
  the CSOR registry at implementation time -- do not trust the one quoted above, which is
  recorded here only because it was read out of the in-tree fixture.
- `AlgorithmIdentifier` parameters are **absent** for ML-DSA (not NULL), matching the
  ECDSA/EdDSA convention `cert.cpp` already implements rather than the RSA/DSA one.
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
hard" risks have a track record here. Hybrid/composite certificate profiles (LAMPS
composite ML-DSA + ECDSA) are a separate question again, and worth deciding only once
single-algorithm PQ support is real.

Every phase gets its own doctest suite under `tests/crypto/` (or `tests/x509/`), mirroring
every other algorithm's KAT-based tests. Phases 4 and 5 additionally get a dedicated review
pass for data-dependent branches and secret-indexed table lookups, separate from the
functional test pass -- that review is part of the phase, not a follow-up to it.
