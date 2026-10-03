# Roadmap

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
| GOST R 34.10-2012 signatures, GOST R 34.11-2012 (Streebog) hash | RFC 7091, RFC 6986 | Russian-profile certificates and DNSSEC |

Landed, and now described in [`docs/architecture.md`](architecture.md):
SipHash-2-4 (RFC 9018's DNS server-cookie PRF), BLAKE2s in all three forms
(RFC 7693, for WireGuard), XChaCha20-Poly1305 with HChaCha20
(draft-irtf-cfrg-xchacha), AES-GCM and an unpadded CBC mode (SP 800-38D and
SP 800-38A, for IKEv2), ECDH over the prime curves (RFC 5903, also IKEv2),
MD4 (RFC 1320, for EAP-MSCHAPv2's NT hash), and the DNSKEY/RRSIG conversion
utility (RFC 4034, with RFC 5702/6605/8080 for the per-algorithm encodings).

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
- **GOST's DNSSEC story is split.** RFC 5933 registered the 2001 signature
  algorithm, and RFC 8624 says not to use it; the 2012 algorithms have
  their own later registration. Which DNSSEC algorithm numbers to support
  needs confirming against the current IANA registry before the DNSKEY
  utility commits to any of them.

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

## Not planned

- Chain building and path validation.
- CSR (PKCS#10) support.

Both are still deliberately out of scope; see
[`CLAUDE.md`](../CLAUDE.md).
