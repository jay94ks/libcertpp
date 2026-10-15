# ML-KEM implementation

[한국어](04-ml-kem.ko.md)

## Post-quantum groundwork: ML-KEM's substrate, and SHA-3

← [History](../HISTORY.md)

Phases 1-3 of [`PQC.md`](../PQC.md)'s plan, plus one prerequisite
the plan had missed.

#### Incremental SHAKE squeezing (Phase 2)

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

#### SHA3-256 and SHA3-512 — a missed prerequisite

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

#### ML-KEM ring arithmetic, samplers and wire encoding (Phase 3)

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

#### Corrections to the plan itself

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

← [History](../HISTORY.md)

The first half of [`PQC.md`](../PQC.md)'s Phase 4 — the algorithm,
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

#### A hole the promotion opened

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

#### Testing

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

#### Noted but not fixed

FIPS 203 requires the implicit-reject flag and the values around it to be
destroyed before `Decaps_internal` returns. They are not: this library has no
zeroization primitive at all, and no RSA, DSA or EC private-key operation
scrubs its intermediates either. ML-KEM is therefore consistent with the rest
of the codebase rather than newly deficient — but that is a real gap in all of
them, and the fix belongs in one shared `utils/` secure-zero rather than
hand-rolled here. Recorded in the plan.

## Post-quantum: ML-KEM as an `IKem`

← [History](../HISTORY.md)

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
