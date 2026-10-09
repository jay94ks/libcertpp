# Roadmap

[한국어](roadmap.ko.md)

What `libcertpp` has been asked for and does not have yet. This file tracks
requested work and why it was requested; it is not a wish list. Anything
finished moves out of here and into
[`docs/architecture.md`](architecture.md), with the reasoning behind it in
[`docs/changelog.md`](changelog.md).

For the post-quantum track, which has its own review and phasing, see
[`docs/pqc-review.md`](pqc-review.md).

## Requested algorithms

These came from downstream consumers that need `libcertpp` to cover the
protocols they speak. The "for" column is why the algorithm is on the list
at all -- it is the thing that decides whether an awkward design question
gets answered one way or the other, so it is recorded rather than dropped.

| Algorithm | Standard | For |
| --------- | -------- | --- |
| GOST R 34.10-2012 / Streebog **X.509 and DNSSEC wiring** (the algorithms themselves are done) | RFC 9215, RFC 9558 | Russian-profile certificates and DNSSEC |

Landed, and now described in [`docs/architecture.md`](architecture.md):
SipHash-2-4 (RFC 9018's DNS server-cookie PRF), BLAKE2s in all three forms
(RFC 7693, for WireGuard), XChaCha20-Poly1305 with HChaCha20
(draft-irtf-cfrg-xchacha), AES-GCM and an unpadded CBC mode (SP 800-38D and
SP 800-38A, for IKEv2), ECDH over the prime curves (RFC 5903, also IKEv2),
MD4 (RFC 1320, for EAP-MSCHAPv2's NT hash), the DNSKEY/RRSIG conversion
utility (RFC 4034, with RFC 5702/6605/8080 for the per-algorithm encodings),
and GOST R 34.11-2012 (Streebog) with GOST R 34.10-2012 over its nine named
parameter sets.

### Notes that affect the implementations

- **Prime-curve ECDH is not constant-time today**, though not for the
  reason it first appears. `CEcCurve::scalarMul()` is *not* a naive
  `if (k.testBit(i)) add` -- it is already a branch-free-*shaped* ladder
  that does both an `addJac` and a `doublePointJac` every iteration and
  uses `condSwapJac()` to choose which register receives which. It is
  nonetheless not constant-time, for three separate reasons:
  1. the loop runs `k.bitLength()` times, so the iteration count leaks the
     position of the scalar's top set bit;
  2. `CBigNum::condSwap()` is a plain `if (swap) { std::swap(a, b); }` --
     a real branch on a bit of the private scalar, taken on every limb of
     every step. This is exactly the defect `Fe25519` was written to
     remove on the X25519 side;
  3. `CBigNum` trims leading zero limbs, so the cost of every underlying
     operation depends on its operands.

  `scalarMulBase()` adds a fourth: it indexes `_baseTable[windowValue]`
  where `windowValue` is four bits of the private scalar, which is a
  data-dependent memory access and so a cache-timing channel on top of the
  above.

  Making this constant-time is a separate, larger job -- see
  "Constant-time and performance" below. In the meantime the limitation is
  stated plainly in `deriveSharedSecret()`'s doc comment, naming the
  IKEv2 ephemeral handshake as the case where it matters and pointing
  callers at X25519 where the protocol allows a choice.
- **GOST's algorithms are implemented; only the encodings are left.**
  `Streebog256`/`Streebog512` and `CGost3410` (nine parameter sets) are in
  `crypto/`, validated against RFC 6986/7091/9215/9385 -- see
  [`docs/changelog.md`](changelog.md). What remains is OIDs and wire
  formats: the `id-tc26-signwithdigest-*` signature OIDs with an omitted
  `parameters` field, the `SubjectPublicKeyInfo` whose `parameters` carries
  the parameter-set OID and whose key bits are a BIT STRING *encapsulating
  an OCTET STRING*, and the signature value as a raw `s || r` blob rather
  than a DER `SEQUENCE { r, s }` -- so `CCert::verifyBy()` cannot assume the
  ECDSA shape for these.
- **GOST's DNSSEC story is split.** RFC 5933 registered the 2001 signature
  algorithm, and RFC 8624 says not to use it; the 2012 algorithms have
  their own later registration (RFC 9558). Which DNSSEC algorithm numbers to
  support needs confirming against the current IANA registry before the
  DNSKEY utility commits to any of them.

## Constant-time and performance

Carried over from the downstream performance report, with what has been
done and what is left. Figures are from a 4-core i7-11370H measured at
3.92 GHz sustained, min-of-N; this machine's run-to-run spread is wide
enough (11--25%, worse under load) that only large differences mean
anything.

- **ChaCha20-Poly1305 throughput.** Target 1.5 GiB/s per core at
  16--64 KiB. A four-block SSE2 keystream took a 64 KiB `seal()` from 331
  to roughly 560 MiB/s, which is most of the available scalar-to-SSE2 win
  on the cipher side. What remains: an AVX2 eight-block keystream, and
  Poly1305 in SIMD.
  Poly1305 is now the larger half, and **wider scalar limbs do not help
  it**: three 44-bit limbs with nine 64x64->128 products per block measured
  no faster than the portable five-limb 26-bit path, and slower again once
  the carries went through `_addcarry_u64`. The 26-bit path's products are
  fully independent and it propagates no carries at all during
  accumulation, which beats a nine-product block with a serial 128-bit
  carry chain. Beating it needs SIMD with precomputed powers of `r`, not
  wider limbs. At 3.92 GHz the 1.5 GiB/s target is 2.43 cycles/byte for
  cipher and MAC together, which is near the edge of what AVX2 can do --
  worth stating in cycles/byte so it can be judged against other hardware.

  One caveat on that negative result: the machine was under load for those
  runs. The `_addcarry_u64` version measured 40% down across three
  consecutive runs, which is well outside this machine's noise, but the
  first version's "no faster" was a much smaller margin and deserves
  re-measuring on a quiet machine before the conclusion is leaned on.
- **Small-record fixed cost.** Target 150 ns for a 64 B `seal()`, currently
  around 420 ns. Most of it is two scalar ChaCha20 block functions: one for
  the Poly1305 one-time key at counter 0, one for the payload. Generating
  counters 0--3 in a single four-wide SSE2 pass would cover the one-time
  key and 192 bytes of payload in one go, which is the structural fix for
  records at or below 192 bytes.
- **X25519 speed.** Target 100 us each way; currently around 333 us for
  key generation and 167 us for the shared secret. Constant-time is
  **done** (a Montgomery ladder with masked conditional swaps over
  `Fe25519`). What is left is the field: a 2^51 radix via `_umul128` cuts
  the multiply count from 100 limb products to 25, and a dedicated
  `square` is worth roughly another 30% on top. MSVC has no `__int128`,
  which is why `Fe25519` is on a 25.5-bit radix today.
- **Prime-curve scalar multiplication: the ladder is done, the field is
  not.** Branch-free laddering, projective coordinates and a fixed-base
  table have all landed for both families -- `CEcCurve::scalarMul()` is a
  two-variable Montgomery ladder over Jacobian coordinates whose addition
  runs unconditionally and selects with `condSwapJac()`, `CEc2Curve` is the
  same shape over Lopez-Dahab coordinates with `condSwapLD()`, and both
  have a lazily-built `_baseTable` behind `scalarMulBase()`.

  What blocks an honest constant-time claim is now entirely *below* the
  ladder, and it is two things:

  1. `CBigNum` trims leading zero limbs, so every operation does work
     proportional to its operands' values, and `CBigNum::condSwap()` is a
     plain branch by its own documentation -- in a ladder that branch is a
     bit of the secret scalar. This is what `Fe25519` fixed for Curve25519
     and what the prime curves have no equivalent of, because there are 29
     of them and a hand-written field per curve is not a plan.
  2. `scalarMulBase()` indexes `_baseTable` by a window of the secret
     scalar, which is a secret-dependent memory access. It needs a
     constant-time table scan; the table is small enough to stay in L1 in
     practice, which is a mitigation and not a fix.

  Until both are addressed, prime-curve ECDH and ECDSA signing should be
  described as branch-free in shape but not constant-time, which is what
  their doc comments say.

- **Signature speed.** Reported downstream, where a certificate handshake
  spent about 20 ms of CPU per side. The diagnosis then was that
  `CBigNum::mulMod()` is `mul()` then `mod()`, and `mod()` calls
  `divMod()` -- a schoolbook long division per field multiplication,
  reached from 113 `mulMod` and 51 `mod()` call sites across the curve
  code. That diagnosis was right and the fix has landed: `CMontgomery`
  owns one odd modulus plus its precomputed `n'` and `R^2`, which is the
  "the modulus needs to become a type that owns its constants" conclusion
  this entry used to end on, and `Fe25519` replaced `CBigNum` underneath
  Curve25519 and Ed25519 entirely.

  Re-measured after both (Release, loaded 4-core i7-11370H, min of 3x20,
  two runs; the run-to-run spread is 20-30%, so read nothing into a
  difference smaller than that):

  | | sign | verify |
  |---|---|---|
  | Ed25519 | **0.20 ms** | **1.00 ms** |
  | Ed448 | 3.27 ms | 13.5 ms |
  | ECDSA P-256 | 1.03 ms | 2.53 ms |
  | ECDSA P-384 | 2.21 ms | 6.62 ms |
  | ECDSA P-521 | 4.59 ms | 15.1 ms |

  Against the figures this entry previously carried, Ed25519 verify is
  35x faster and P-256 verify 7x. Ed25519 is within an order of magnitude
  of the 50--100 us an optimized implementation takes, which is the first
  time that has been true.

  What is left, in the order the remaining cost sits:

  1. **`Fe25519`'s radix.** A 2^51 layout needs 25 limb products where
     the current 2^25.5 needs 100, and a dedicated `square` is worth
     roughly another 30%. MSVC has no `__int128`, so this means
     `_umul128`. This is also the X25519 item above.
  2. **A window table per public key, for verification.** Verification
     multiplies a *variable* base, so no fixed-base table helps it -- but
     `verifyBy()` reuses one issuer key across every certificate that
     issuer signed, so caching a table per public key pays for exactly the
     chain-checking workload that prompted the report. Still open.
  3. **Ed448 and P-521 are the outliers** now that the shared reduction is
     fixed, and neither has had a pass of its own.

- **Cross-toolchain divergence, and RSA on GCC.** Measuring both toolchains in
  one session on the same machine (MSVC 19.36 on Windows and GCC 13.3 on
  Ubuntu 24.04 **under WSL2**, both Release, best of 3x20 over three runs, run
  one after the other rather than concurrently so neither could measure the
  other's compiler) shows GCC equal or faster on almost everything -- SHA3-256
  by 2.8x, Streebog by 42%, ML-KEM by 30%, AES-256-GCM by 28% -- and two
  exceptions that run the other way:

  1. **RSA-2048 is 2.4x slower to sign on GCC** (19.1 ms against 8.06 ms) and
     2.7x slower to verify. The obvious explanation is already ruled out by the
     source, and it is worth recording so nobody spends a day on it:
     `CBigNum::mul()` dispatches to `mulAccelerated()` on a `hasAdxBmi2()`
     check, and that check passes on this CPU for both toolchains -- GCC
     through the function-level `__attribute__((target("bmi2,adx")))`, MSVC
     through its unconditional intrinsic use. So this is *not* the portable
     multiply being taken by accident. The prime curves also running *faster*
     on GCC argues the backend is not slow in general; RSA is simply where
     `mulMod()` dominates enough for a codegen difference to become the whole
     result. What that difference is has not been profiled. The two things
     worth measuring before anything is changed: whether the Montgomery
     reduction's shape costs GCC more than it costs MSVC, and whether GCC keeps
     `row[]`/`r64[]` resident across mulAccelerated()'s Step A / Step B
     boundary. Nothing here has been diagnosed beyond those exclusions.

  2. **MD5 is 23% slower on GCC** (455 against 593 MiB/s) while every other
     hash is equal or faster -- one routine, one direction, so a much smaller
     job than the above.

  Both sets of figures come from the same harness on the same machine, so the
  comparison is like-for-like; `README.md`'s tables carry the full set. Two
  limits on that comparison, both of which the table's own numbers invite the
  reader to forget: the GCC side ran **under WSL2**, a VM rather than bare
  metal, so it reads as this toolchain in this setup and not as Linux
  performance in general; and "both Release" hides that CMake's Release
  defaults are `/O2` for MSVC and `-O3` for GCC, so toolchain and optimization
  level are varied together. Any of this worth chasing further should be
  re-measured on bare-metal Linux before the gap is called a GCC bug. Note too
  that MSVC's own numbers came in 10--20% under the set published before them,
  which is a reminder that the load conditions move these figures as much as
  the code does.

## Not planned

- Path validation.

Still deliberately out of scope; see [`CLAUDE.md`](../CLAUDE.md). The
distinction is worth stating precisely, because this entry used to read "chain
building and path validation" and half of it is no longer true.
`CCertCollection::buildChain()` orders certificates by who issued whom and
`verifyLinks()` checks each link's signature. What is absent is everything
*else* a validator does: validity periods, `basicConstraints`, `keyUsage`,
name constraints, policy constraints, revocation, and the decision of whether
the root at the end is one the caller trusts. An ordered chain out of this
library is a validator's input, not its verdict, and an entry that lumped the
two together invited reading the first as a promise about the second.

CSR (PKCS#10) support used to sit here too. It no longer does: it landed as
`x509/csr.hpp`'s `CCertRequest`/`CCertRequestBuilder` (RFC 2986, PKCS#9
extensionRequest included), reusing `CCert`'s own Name/SubjectPublicKeyInfo/
AlgorithmIdentifier/Extensions encoders and its signing and verification
helpers rather than growing a second copy of them. The CA-side half is
`CCertBuilder::subjectFrom()`, which takes a verified request's subject name
and key and deliberately nothing else -- see its own doc comment on why there
is no "copy the requested extensions" method to go with it.
