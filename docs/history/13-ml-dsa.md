# ML-DSA and the first PQ certificate

[한국어](13-ml-dsa.ko.md)

## Post-quantum: ML-DSA itself (FIPS 204), and the first real PQ certificate verified

← [History](../HISTORY.md)

The layers underneath this were already in and already validated — the ring, the
rounding/hint machinery, the bit packing, the three rejection samplers, the
parameter table. What landed here is everything above them: FIPS 204 7.2's key
and signature encoders, KeyGen/Sign/Verify, the `IAsymmetric` wrapper, and the
X.509 wiring that makes a real post-quantum certificate verify.

- `MlDsaScheme` (`src/crypto/asyms/mldsascheme.hpp`/`.cpp`): `pkEncode`/
  `pkDecode`, `skEncode`/`skDecode`, `sigEncode`/`sigDecode`, `w1Encode`, and
  `keyGenInternal`/`signInternal`/`verifyInternal` plus `sign`/`verify`. Takes
  ξ and `rnd` as parameters, which is what lets it be driven from a vector.
- `CMlDsa` (`include/certpp/crypto/asyms/mldsa.hpp` + `src/crypto/asyms/
  mldsa.cpp`): ML-DSA as an `IAsymmetric`, one instance per parameter set.
  `EAsymmetrics` gained `EASYM_MLDSA44`/`EASYM_MLDSA65`/`EASYM_MLDSA87`,
  appended before `EASYM_MAX` — the enum crosses an ABI boundary, so inserting
  in the middle would leave an already-compiled caller silently selecting a
  different algorithm.
- X.509: RFC 9881's `.17`/`.18`/`.19` in `CCert`'s `KEY_ALGOS` and `SIG_ALGOS`,
  `resolveSigAlgoForSigning()` taught about ML-DSA so `CCertBuilder` can issue
  one, and `CCert::signsMessageDirectly()` replacing the
  `EASYM_ED25519 || EASYM_ED448` predicate that had been copied into four
  verification paths.

#### Validation came first, and in Python

Everything below the C++ was established before any of it was written: a
standalone FIPS 204 reference, transcribed from the published algorithms with
nothing borrowed from an existing implementation, reproducing NIST's ACVP
vectors in full — **keyGen 75/75, sigGen 360/360 byte-exact across all 24
groups, sigVer 180/180 verdicts**. The 24 sigGen groups cover every combination
the standard admits: deterministic and hedged, internal and external interface,
pure and pre-hashed, and the `externalMu` variant. The C++ then matched the same
vectors on its first run, which is the point of doing it in that order.

Two bugs the Python reference caught, both of which would have been invisible to
a round trip:

- `rejBoundedPoly` reduced its coefficients mod q before returning them, so
  s1's −1 became q−1, and `BitPack(η − coefficient)` then encoded a nonsense
  field. `pk` still matched on all 75 keyGen cases — the NTT does not care which
  representative it is handed — and only `sk` differed. A test that generated a
  key and used it would have passed.
- `sampleInBall` and `expandMask` had the same reduction, harmlessly there, but
  the fix is the same: these three produce **signed** coefficients, and the
  C++ layer had it right all along.

#### The thing this plan never named: two message conventions

FIPS 204 has an internal interface (Algorithms 7–8) that signs `M'` verbatim,
and an external one (Algorithms 2–3) that prepends
`IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx` first. RFC 9881's
`id-ml-dsa-*` OIDs mean the **external** interface with an empty context — so an
X.509 signature covers `0x00 || 0x00 || tbsCertificate`, not the TBS bytes alone.

Getting this wrong is the ideal shape of a self-consistent bug. It round-trips
perfectly, it matches half of ACVP's sigGen groups (the twelve
`signatureInterface: "internal"` ones), and it rejects every genuine
certificate. Both forms are on `MlDsaScheme`; `CMlDsa` exposes only the
external one, and `tests/crypto/asyms/kat_mldsa.cpp` asserts directly that the
two disagree and that each rejects the other's signature.

`sign()`/`verify()` compute μ themselves and hand it to the internal form as its
`externalMu` rather than concatenating prefix and message into one buffer. The
results are bit-identical, because μ is `H(tr ‖ M')` and `H` absorbs its parts
in order, but the message is never copied — and `tr` sits at a fixed offset in
the private key, so reading it costs nothing.

#### `2.16.840.1.101.3.4.3.19` is ML-DSA-87

The arc runs `.17`/`.18`/`.19` for ML-DSA-44/65/87, and the three being
consecutive makes an off-by-one a realistic error rather than a hypothetical
one. The certificate settles it without reference to the registry: its
`SubjectPublicKeyInfo` BIT STRING holds 2592 bytes and its `signatureValue`
4627, and that pair belongs to ML-DSA-87 alone (ML-DSA-65's are 1952 and 3309).

Because every parameter set has a different key *and* signature length, a
mix-up is a clean refusal rather than a wrong answer — `createPublicKey()`
rejects the bytes outright. A test offers an ML-DSA-65 key to ML-DSA-87 for
exactly that reason.

#### The acceptance test

`tests/x509/certs/unimplemented/identrust-mldsa-root.der` moved to
`certs/implemented/`, and its test case now asserts
`cert.verifyBy(cert) == ERET_OK`. That is a genuine ML-DSA-87 signature,
produced by somebody else's implementation over bytes this library did not
choose, verified end to end through `CCert`, `CMlDsa` and `MlDsaScheme`.

It is the only check in the suite an ML-DSA implementation cannot pass by being
consistently wrong. A companion case flips one bit in the TBSCertificate, one in
the signature and one in the public key, and requires each to fail — otherwise
the success above would be satisfied by a `verify()` that returned `ERET_OK`
unconditionally.

Two encoding details were read off the certificate rather than assumed:
`parameters` is absent from all three of its AlgorithmIdentifiers, and both BIT
STRINGs carry raw FIPS 204 bytes with no inner `OCTET STRING` wrapper. So
`CCert` needs no reshaping step for ML-DSA, unlike DSA's split `Dss-Parms`.

#### `signsMessageDirectly()`, and why it is one function

`CCert::verifyBy()`, `CCrlReader::verifyBy()` and both OCSP
`verifySignature()`s each decided whether to hash first by testing
`keyAlgo == EASYM_ED25519 || keyAlgo == EASYM_ED448`. Three more algorithms
made four copies of that predicate a question of when it would drift, not
whether — and a site that missed an entry fails silently in the worst
direction: it hands raw TBS bytes to a hash-then-sign verify (truncated to the
order's bit length, so the signature covers a prefix of the plaintext), or
hands a digest to ML-DSA and signs that 32-byte string instead of the message.
The first was a real bug in this library's OCSP path. Neither is visible to a
self-signed round trip.

It is deliberately *not* a test of `_sigHashAlgo == EHASH_UNKNOWN`, which is
also what `resolveSigAlgo()` leaves behind for an unregistered OID. The
`sigIsEddsa` locals on the signing side were renamed `sigIsSelfHashing` for the
same reason; there the `EHASH_UNKNOWN` test is unambiguous, because
`resolveSigAlgoForSigning()` returns false rather than `EHASH_UNKNOWN` for an
algorithm it does not know.

#### A digest-shaped interface for something that signs messages

`IAsymmetricContext::sign(digest, out)` has no second convention to offer, and
ML-DSA has no externally supplied digest: it derives μ from the message and
then signs a lattice commitment. Passing a pre-computed SHA-256 value produces
a valid ML-DSA signature **over that 32-byte string** — one no other
implementation would generate or check, since the verifier re-derives μ from
the message it was given.

The resolution is the one Ed25519/Ed448 already established and
`CDnssecKeys::hasherOf()` states from the other side: the parameter carries the
message, and `sizeOfDigest()` stays 0 to say so. Zero means "there is no digest
to compute, pass the message", and it is asserted on the IdenTrust root's own
context. The parameter keeps its interface name — renaming it per
implementation would obscure the override relationship rather than clarify it.

#### Signing is hedged, which is why the KATs go through the raw layer

`CMlDsa` draws a fresh 32-byte `rnd` per signature (FIPS 204's recommended
default), so two signatures over one message differ and neither is comparable
to a fixed answer. Deterministic signing — `rnd` all zero — is the standard's
own variant, not a test contrivance, and it is what every ACVP
`deterministic: true` group uses; it is reachable through `MlDsaScheme` and
deliberately not through `CMlDsa`, so a caller cannot select it by accident.

#### Zeroization, and what it does not cover

FIPS 204 3.6.3 requires sensitive intermediates to be destroyed as soon as they
are no longer needed. Signing's rejection loop has four `continue` paths and a
dozen early returns, so a scrub written at the bottom would be skipped by every
one of them — the same failure mode `CMlKem::decapsulate()`'s single exit was
built to avoid. These use RAII scrubbers instead: ρ, K, tr, μ, ρ'', s1/s2/t0 and
their NTT forms, the masking vector y, z before it is encoded, and the `c*s`
product are all cleared on scope exit however the scope is left. A-hat is left
alone — it is a function of ρ, which travels in the public key.

It does **not** extend to verification intermediates, which the standard also
mentions. Everything verification touches is public, so there is nothing there
to protect, and saying so is more useful than a scrub that implies otherwise.

#### Negative controls

Five deliberate breakages, each rebuilt and run to confirm something fails, then
reverted. This is the measurement the suite's value rests on, since every one of
these bugs leaves an implementation that works perfectly with itself:

- **Decompose's `(q-1)` carve-out rewritten as `rp == q-1`** (the single point it reads as,
  instead of the band of width γ₂ it is). Caught by `mldsarounding`, both KAT suites **and
  the IdenTrust certificate** — four failures.
- **`ExpandA`'s row/column seed bytes swapped.** Caught by `mldsasampler`, both KAT suites
  and the certificate. `tests/crypto/asyms/mldsa.cpp` — the `IAsymmetric` round-trip suite —
  **passed**, which is the whole argument for the other three: a transposed matrix is a
  different-but-valid scheme, and generating a key, signing with it and verifying against
  itself cannot see that.
- **`skDecode`'s s1/s2 range check deleted.** Caught by `kat_mldsa`, which feeds a key whose
  first s1 coefficient decodes to −5 and requires `checkPrivateKey()`, `signInternal()` *and*
  `sign()` to all refuse it. The `IAsymmetric` suite still rejected the same key, but by a
  second route — `publicKey()` re-derives the public half, whose tr then disagrees — so the
  range check is not what that test measures.
- **`verifyInternal()`'s final commitment comparison replaced with `return true`.** Caught by
  everything: both KAT suites, the `IAsymmetric` suite, and the certificate's
  tampering case.

- A fifth, for a check added during this work rather than one the plan called for:
  **the re-derived-t0 comparison in `publicKeyOf()` removed.** t0 is the one part of a
  private key no decode check can reach — its field is exactly 13 bits wide for a 13-bit
  range, so every byte string decodes to a legal t0, and `tr = H(pk)` does not cover it.
  Caught by `tests/crypto/asyms/mldsa.cpp`'s t0-tampering case, which is the only thing that
  can catch it.

Three of the four original controls are invisible to a sign-then-verify round trip against a
freshly generated key. That is the measurement this suite exists to make.

19 test cases, 510 assertions across the three new files (`kat_mldsa.cpp` 7/137,
`kat_mldsaver.cpp` 4/137, `mldsa.cpp` 8/236), plus the ML-DSA builder cases in
`tests/x509/cert.cpp` and the two certificate cases in `tests/x509/realcerts.cpp`.
The suite is 121 tests, all passing.

#### What is deliberately not here

Only the pure variant. HashML-DSA was validated in the Python reference (ACVP's
twelve `preHash` groups all match) but is not in the C++: RFC 9881 8.3 says its
OIDs MUST NOT appear in an X.509 certificate, and nothing else in the tree needs
them. `MlDsaScheme` also stays private to `src/`, unlike ML-KEM's public
`CMlKem` — every entry point is parameterized by `MlDsaParams`, and exporting
the signatures would mean moving that already-tested private header into the
public API or duplicating it, for a surface callers do not need.
