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
| SipHash-2-4 | Aumasson--Bernstein; RFC 9018 names it for DNS server cookies | DNS server cookies |
| BLAKE2s -- hash, keyed MAC, and HMAC-BLAKE2s | RFC 7693 | WireGuard |
| XChaCha20-Poly1305 (and HChaCha20) | draft-irtf-cfrg-xchacha | WireGuard |
| AES-GCM, and AES-CBC with no padding | SP 800-38D; SP 800-38A + RFC 7296 | IKEv2 |
| ECDH on P-256 / P-384 | RFC 5903 | IKEv2 |
| MD4 | RFC 1320 | EAP-MSCHAPv2's NT-hash |
| GOST R 34.10-2012 / Streebog **X.509 and DNSSEC wiring** (the algorithms themselves are done) | RFC 9215, RFC 9558 | Russian-profile certificates and DNSSEC |
| DNSKEY / RRSIG conversion utility | RFC 4034 Appendix A, with RFC 5702 / 6605 / 8080 for the per-algorithm key and signature encodings | DNSSEC |

### Notes that affect the implementations

- **BLAKE2s needs all three forms.** WireGuard uses the native keyed MAC
  (RFC 7693 2.9, where the key is absorbed as a padded first block) *and*
  HMAC-BLAKE2s (the generic RFC 2104 construction) in different places.
  They are different functions and one does not substitute for the other.
  `CHmac` switches over `EHashers` for its block-size mapping, so a new
  hasher that is not added there will silently misbehave under HMAC.
- **HChaCha20 has no feed-forward.** Unlike ChaCha20's block function it
  does not add the original state back. Reusing the block function verbatim
  gives a subkey that is self-consistent and incompatible with every other
  implementation.
- **GCM's field is bit-reflected.** `CGf2m` already does GF(2^m) with a
  PCLMULQDQ-accelerated multiply, but GCM's representation reverses bit
  order within each byte relative to the usual polynomial-basis convention.
  Reusing a conventional multiply unmodified produces results that are
  self-consistent and wrong. Whether GHASH should extend `CGf2m` or live
  separately is a real design question, not a formality.
- **Unpadded CBC must not change padded CBC.** The existing
  `CbcTransformer` and the SP 800-38A vectors that cover it are not to be
  disturbed; unpadded mode is a selectable mode, not a new default.
- **Prime-curve ECDH is not constant-time today.** `CEcCurve::scalarMul()`
  branches on scalar bits and `CBigNum` has a data-dependent limb count.
  For ephemeral keys in an online handshake that is a timing side channel.
  Making it constant-time is a separate, larger job -- see "Constant-time
  and performance" below -- and in the meantime the limitation gets stated
  honestly in the API docs rather than papered over.
- **MD4 is broken** and is here only to interoperate with EAP-MSCHAPv2. It
  is documented the way MD5 already is: legacy interop only, never for new
  signatures.
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
