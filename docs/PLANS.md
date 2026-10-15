# Roadmap

[한국어](PLANS.ko.md)

What `libcertpp` has been asked for and does not have yet. This file tracks
requested work and why it was requested; it is not a wish list. Anything
finished moves out of here and into
[`docs/CONCEPTS.md`](CONCEPTS.md), with the reasoning behind it in
[`docs/HISTORY.md`](HISTORY.md).

For the post-quantum track, which has its own review and phasing, see
[`docs/PQC.md`](PQC.md).

## Requested algorithms

| Algorithm | Standard | For |
| --------- | -------- | --- |
| GOST R 34.10-2012 / Streebog **X.509 and DNSSEC wiring** (the algorithms themselves are done) | RFC 9215, RFC 9558 | Russian-profile certificates and DNSSEC |

Work that was requested here and has since landed is described in
[`docs/CONCEPTS.md`](CONCEPTS.md), with the reasoning behind it in
[`docs/HISTORY.md`](HISTORY.md). It is not repeated here, and a list of it
would go stale on the next thing that lands.

Notes that affect the implementations:

- **Prime-curve ECDH is not constant-time today**, though not for the reason it
  first appears. `CEcCurve::scalarMul()` is already a branch-free-*shaped*
  ladder, but it is not constant-time: the loop runs `k.bitLength()` times,
  `CBigNum::condSwap()` is a plain `if (swap) { std::swap(a, b); }` on a bit of
  the private scalar, and `CBigNum` trims leading zero limbs so every
  operation does work proportional to its operands.
  `scalarMulBase()` adds a fourth: it indexes `_baseTable[windowValue]` where
  `windowValue` is four bits of the private scalar -- a data-dependent memory
  access and a cache-timing channel. Making this constant-time is a separate,
  larger job; see [Constant-time and performance](roadmap/performance.md).
- **GOST's algorithms are implemented; only the encodings are left.**
  `Streebog256`/`Streebog512` and `CGost3410` (nine parameter sets) are in
  `crypto/`, validated against RFC 6986/7091/9215/9385. What remains is OIDs
  and wire formats: the `id-tc26-signwithdigest-*` signature OIDs with an
  omitted `parameters` field, the `SubjectPublicKeyInfo` whose `parameters`
  carries the parameter-set OID and whose key bits are a BIT STRING
  *encapsulating* an OCTET STRING*, and the signature value as a raw
  `s || r` blob rather than a DER `SEQUENCE { r, s }`.
- **GOST's DNSSEC story is split.** RFC 5933 registered the 2001 signature
  algorithm, and RFC 8624 says not to use it; the 2012 algorithms have their
  own later registration (RFC 9558). Which DNSSEC algorithm numbers to support
  needs confirming against the current IANA registry.

## Detailed pages

- [Constant-time and performance](roadmap/performance.md)
- [Not planned](roadmap/not-planned.md)
