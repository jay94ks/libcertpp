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
- **Prime-curve scalar multiplication.** Branch-free laddering and
  projective coordinates for `CEcCurve`/`CEc2Curve`, plus a fixed-base
  comb table for signing. This is what prime-curve ECDH needs before it
  can honestly claim constant-time behaviour.
- **Signature speed: a division per modular multiply.** Reported
  downstream, where a certificate handshake spends about 20 ms of CPU per
  side and one core manages roughly 30 handshakes a second. Measured here
  (Release, loaded 4-core i7-11370H, min of 3x20): Ed25519 sign 7.4 ms /
  verify 35.1 ms, ECDSA P-256 sign 7.9 ms / verify 17.9 ms, P-384 verify
  40.7 ms. Optimized implementations verify Ed25519 in 50--100 us.

  The cause is one line: `CBigNum::mulMod()` is `mul()` then `mod()`, and
  `mod()` calls `divMod()` -- a 138-line schoolbook long division, run once
  per field multiplication. It is reached from 113 `mulMod` and 51 `mod()`
  call sites across `eccurve.cpp` (42), `ed25519.cpp` (33), `ed448.cpp`
  (30), `ecdsa.cpp` and `gost3410.cpp`.

  The control that proves it: **X25519 derives a shared secret in 246 us**
  on the same curve in the same build, because it is the one algorithm
  already moved onto `Fe25519`, which has no division. Ed25519 uses
  `Fe25519` zero times and `CBigNum` 118 times; X25519 uses it 32 times.
  A 142x gap between two implementations of the same curve.

  **Precomputation is the lever, but not everywhere -- some of it is
  already done.** Worth separating, because "precompute more points" is
  the intuitive answer and is the wrong one here:

  1. *Already present.* Both `Edwards25519::scalarMulBase()` and
     `CEcCurve::scalarMulBase()` build a lazy fixed-base window table and
     reuse it for the life of the process, and Ed25519 already keeps
     extended `(X, Y, Z, T)` coordinates with an inversion-free
     `pointAddProj()` and a precomputed `2*d`. Adding more point tables
     does not help: every point addition still pays ~8 divisions, so the
     table only changes how many of those additions there are.
  2. *The actual win -- per-modulus reduction constants.* Montgomery
     (`n' = -m^-1 mod 2^64`, `R^2 mod m`) or Barrett
     (`mu = floor(2^2k / m)`), computed once per modulus, turns each
     reduction into multiplications. This is what removes `divMod` from
     the inner loop, and unlike a per-curve field it covers all 29 prime
     curves, Ed448, GOST and DSA at once. The obstacle is API shape rather
     than arithmetic: `mulMod(other, modulus)` has nowhere to cache
     anything, so the modulus needs to become a type that owns its
     constants.
  3. *Still open, and workload-specific.* Verification multiplies a
     **variable** base -- the public key -- so no fixed-base table helps
     it. But `verifyBy()` reuses one issuer key across every certificate
     that issuer signed, so caching a window table per public key would
     pay for exactly the chain-checking workload that prompted the report.
     The downstream consumer already caches at a coarser level, per
     credential.

  Ed25519 gets `Fe25519` because that field already exists and is
  validated; everything else wants (2).

## Not planned

- Chain building and path validation.

Still deliberately out of scope; see [`CLAUDE.md`](../CLAUDE.md).

CSR (PKCS#10) support used to sit here too. It no longer does: it landed as
`x509/csr.hpp`'s `CCertRequest`/`CCertRequestBuilder` (RFC 2986, PKCS#9
extensionRequest included), reusing `CCert`'s own Name/SubjectPublicKeyInfo/
AlgorithmIdentifier/Extensions encoders and its signing and verification
helpers rather than growing a second copy of them. The CA-side half is
`CCertBuilder::subjectFrom()`, which takes a verified request's subject name
and key and deliberately nothing else -- see its own doc comment on why there
is no "copy the requested extensions" method to go with it.
