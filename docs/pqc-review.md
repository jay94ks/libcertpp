# Post-Quantum Cryptography: Preliminary Review

This is a preliminary design review, not an implementation plan -- it exists to answer
"what would it take, and what should go first" before any post-quantum (PQ) code is
written. No code changes accompany this document.

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
| (selected, not yet a finalized FIPS as of this review) | FN-DSA (Falcon) | Digital signature | NTRU lattices (shortest-vector) |

NIST also selected **HQC** (Hamming Quasi-Cyclic, a code-based KEM) in March 2025 as a
structurally independent backup to ML-KEM, specifically so a future break of lattice
assumptions wouldn't leave zero standardized PQ KEMs; it's expected to reach its own FIPS
draft after ML-KEM/ML-DSA/SLH-DSA, but the exact timeline wasn't firm as of this review --
treat it as a candidate to revisit, not yet a target.

**Recommended scope for libcertpp: ML-KEM and ML-DSA only, in that priority order.**
Reasoning:

- **ML-KEM first.** A KEM is needed before a signature scheme is, because TLS 1.3's PQ/
  hybrid key exchange (`X25519MLKEM768`, already shipping in major browsers and OpenSSL
  3.x) is the single most widely deployed PQ use case today, and because `libcertpp` has
  no KEM-shaped interface at all yet (see "Interface-level fit" below) -- building the new
  interface shape against the simpler primitive first (no RNG-dependent domain parameters,
  no hash-then-sign construction, a single encapsulate/decapsulate round trip) is lower
  risk than building it against ML-DSA.
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
  plaintext") would be a leaky, confusing abstraction. **This needs a new sibling
  interface** -- `IKem`/`IKemContext` under a new `crypto/kem.hpp`, mirroring
  `IAsymmetric`/`IAsymmetricContext`'s shape (key-size specs, `generateKeyPair()`,
  `checkPrivateKey()`, `createPublicKey()`/`createPrivateKey()`, `createContext()`) but
  with `encapsulate(IPublicKeyPtr, ciphertext&, sharedSecret&)` /
  `decapsulate(ciphertext, sharedSecret&)` in place of sign/verify/encrypt/decrypt. This
  is a bounded, additive change -- no existing interface needs to change shape, and
  `X25519` (this library's one existing pure-KEX algorithm) is left as-is rather than
  retrofitted onto `IKem`, since forcing a working Diffie-Hellman interface to match a
  KEM's encapsulate/decapsulate shape for symmetry's sake isn't worth the churn.

## Shared substrate: what ML-KEM and ML-DSA need, and what already exists

Both algorithms work over the same polynomial ring `R_q = Z_q[X]/(X^256+1)` (ML-KEM:
`q = 3329`; ML-DSA: `q = 8380417`) and both need:

1. **A SHAKE-based XOF/hash layer** for domain-separated expansion (matrix generation,
   sampling, the Fiat-Shamir challenge in ML-DSA). `SHAKE256` already exists
   (`crypto/hashers/shake256.hpp`) and covers this directly -- **ML-KEM/ML-DSA also need
   SHAKE128**, which this library doesn't have yet (only SHAKE256); FIPS 203/204 use
   SHAKE128 for matrix/vector expansion and SHAKE256 for everything else (G, H, the
   signing XOF). `src/crypto/hashers/shake256.cpp`'s `SHAKE256::keccakF1600`/
   `permuteState` (the Keccak-f[1600] permutation itself, rate-independent) should be
   promotable to a small shared `Keccak` core so a new `SHAKE128` doesn't duplicate the
   permutation -- the same "shared private header+cpp" pattern this codebase already uses
   for `DesCore`/`Sha2_32Core`/`Sha2_64Core`.
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

So roughly: item 4 is already done, item 1 is a small, well-understood extension of
already-shipped code, and items 2/3/5 are the real new work -- concentrated almost
entirely in the NTT-based ring arithmetic, which both algorithms share.

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

## Suggested order of work (for a future, separate implementation plan)

1. `SHAKE128` (promote the Keccak-f[1600] core out of `SHAKE256` first).
2. The shared NTT-based ring-arithmetic primitive, validated against FIPS 203/204's own
   worked NTT examples before anything is built on top of it.
3. `ML-KEM` end to end (keygen/encaps/decaps) against the ACVP KAT vectors, plus the new
   `IKem`/`IKemContext` interface it's the first (and, initially, only) implementation of.
4. `ML-DSA` end to end (keygen/sign/verify) against the ACVP KAT vectors, as a new
   `IAsymmetric` implementation -- no interface changes needed, per "Interface-level fit"
   above.
5. Re-evaluate SLH-DSA/FN-DSA/HQC once (1)-(4) are solid and this review's "genuinely
   hard" risks have a proven track record in this codebase.

Each phase should get its own doctest suite under `tests/crypto/` (mirroring every other
algorithm's KAT-vector-based tests) and, specifically for (3)/(4), a dedicated review pass
for data-dependent timing/table-index patterns before being considered done -- not just
the usual functional test pass.
