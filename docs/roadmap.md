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

| Algorithm | Standard | For |
| --------- | -------- | --- |
| GOST R 34.10-2012 / Streebog **X.509 and DNSSEC wiring** (the algorithms themselves are done) | RFC 9215, RFC 9558 | Russian-profile certificates and DNSSEC |

Work that was requested here and has since landed is described in
[`docs/architecture.md`](architecture.md), with the reasoning behind it in
[`docs/changelog.md`](changelog.md). It is not repeated here, and a list of it
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
  larger job; see "Constant-time and performance" below.
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

## Constant-time and performance

Carried over from the downstream performance report. Figures are min-of-N on a
4-core i7-11370H at 3.92 GHz sustained; the machine's run-to-run spread is
11--25%, so only large differences mean anything. The GCC side ran under WSL2
(a VM, not bare metal), and CMake's Release defaults differ (`/O2` vs `-O3`),
so toolchain and optimization level vary together.

Rebuilding both toolchains with `-DCERTPP_DISABLE_HWACCEL_SIMD` compiles out
four accelerations at once -- `CBigNum::mulAccelerated()`'s MULX/ADCX,
`CGf2m`'s word-level reduction, GHASH, and ChaCha20's SSE2 keystream -- so the
ratio between on and off attributes each:

| | MSVC on | MSVC off | GCC on | GCC off |
|---|---|---|---|---|
| AES-256-GCM, 64 KiB | 370 MiB/s | **53 MiB/s** | 475 MiB/s | **64 MiB/s** |
| ChaCha20-Poly1305, 64 KiB | 578 MiB/s | 346 MiB/s | 650 MiB/s | 408 MiB/s |
| XChaCha20-Poly1305, 64 KiB | 577 MiB/s | 353 MiB/s | 648 MiB/s | 409 MiB/s |
| RSA-2048 sign | 8.06 ms | 8.85 ms | 19.1 ms | 19.7 ms |
| ECDSA P-256 sign | 0.916 ms | 0.884 ms | 0.862 ms | 0.832 ms |

Two things fall out of that, and both matter more than any single number in it.

**The GF(2^m)/GHASH path is worth about 7x, and nothing else is close.**
`CBigNum::mulAccelerated()` is worth nothing measurable -- every big-number
row moves by less than the machine's own 11--25% spread, so the honest reading
is that turning the MULX/ADCX path on changes RSA and prime-curve timings by
an amount indistinguishable from noise. This cuts against the obvious plan:
there is nothing to win by improving that function.

### Ordered plan (P0--P7)

Sequenced by what the measurements actually support, not by how easy each item
looks. Each names how it would be verified, because on this machine a change
smaller than ~20% is not a change. Full detail, including negative results and
corrected diagnoses, is in [`docs/changelog.md`](changelog.md).

| Item | Status | Result |
|---|---|---|
| **P0** -- Close the measurement gaps | **Done** | `benchSmallRecord()` reports the 64 B `seal()`; ML-KEM keygen and the 64 B/64 KiB AEAD split are now measured. |
| **P1** -- Put RSA on Montgomery | **Done** | Sign 42--71% faster; cross-toolchain gap 2.37x to 1.17x. [Changelog](changelog.md) |
| **P2** -- AES-256-GCM to ChaCha level | **Closed** (negative result) | GHASH 4-block chaining measured 9--16% slower; X_1..X_4 carry descending powers and cannot share one multiplier. VPCLMULQDQ is the only remaining path. |
| **P3** -- ChaCha20-Poly1305 | **Done** (keystream half) | AVX2 eight-block keystream: 1.95x on the keystream, 1.34x on the AEAD. Poly1305 is multiply-throughput-bound and vectorising it is 1.06--1.09x *slower*. |
| **P4** -- `Fe25519` dedicated square / 2^51 radix | **Closed** (negative result) | Two attempts at the merged square were wrong (the radix corrections are asymmetric). The 2^51 radix would cut multiply work by 22%, not the 75% the limb count suggests. |
| **P5** -- A field for the prime curves | **Closed** (negative result) | The prime curves are *already* on Montgomery (`eccurve.cpp:747`), so there is no per-curve field to build. |
| **P6** -- Ed448 and P-521 | **Closed** (negative result) | Both curves already have dedicated constant-time paths: P-521 is on Montgomery (`eccurve.cpp:747`), Ed448 has its own branch-free ladder (`ed448.cpp:192`) over `CMontgomery` (`ed448.cpp:129`). |
| **P7** -- MD5 on GCC | **Done** | Unrolling the four rounds removed a branch and a modulo per step: 545 to 341 cycles/block, 1.60x. GCC 455 to 718 MiB/s; MSVC unchanged within noise. |

The lesson worth carrying to the next pass: seven changes were implemented on
the reasoning that fewer instructions would mean less work, and six of the
seven cost more, every time because they widened a computation to fill SIMD
lanes that the input did not fill. Measure the decomposition before proposing
the change, not after. And the generalisable form: the first question to ask
of any SIMD proposal is not "does it compute the same thing" but **"is the
thing I am vectorising actually the bottleneck."**

### Remaining work

Deliberately last: the constant-time items below. They are correctness and
security work rather than throughput, and their schedule should not compete
with the items above.

- **Prime-curve ECDH/ECDSA constant-time.** The ladder is done; the field is not.
  `CBigNum` trims leading zero limbs (work proportional to operands) and
  `condSwap()` is a plain branch on a secret bit. `scalarMulBase()` adds a
  secret-dependent table index. Needs a shared field type for 29 curves --
  hand-writing one per curve is not a plan. Until then, prime-curve ECDH and
  ECDSA signing are branch-free in shape but not constant-time, which is what
  their doc comments say.
- **`Fe25519` radix and dedicated square.** A 2^51 layout via `_umul128` cuts
  limb products from 100 to 25 (22% less multiply work, not 75%); a dedicated
  `square` halves the off-diagonal terms (12% of X25519). Both measured; both
  need mechanical verification of the merged factors, which is what stopped
  P4. MSVC has no `__int128`, so `_umul128` is the route; 32-bit/non-x64 would
  need a gate.
- **Poly1305 SIMD.** The only remaining path to the 1.5 GiB/s ChaCha target.
  The scalar form is multiply-throughput-bound (45.7 cycles/block against a
  24.1 floor); vectorising the multiply is 1.06--1.09x slower because AVX2 has
  no 64x64->128 and the operand shuffle costs more than the multiply it saves.
  Needs 64x64->128 (AVX512IFMA) or precomputed powers of `r`.
- **Verify-time window table.** Verification multiplies a *variable* base, so
  no fixed-base table helps it -- but `verifyBy()` reuses one issuer key across
  every certificate that issuer signed, so caching a table per public key pays
  for exactly the chain-checking workload. Still open.

### Cross-toolchain divergence

Measuring both toolchains in one session on the same machine shows GCC equal
or faster on almost everything -- SHA3-256 by 2.8x, Streebog by 42%, ML-KEM by
30%, AES-256-GCM by 28% -- and four exceptions that ran the other way, **two
resolved and two open**:

1. **RSA-2048 was 2.4x slower to sign on GCC.** Not the portable multiply
   (dispatches to `mulAccelerated()` on a `hasAdxBmi2()` check that passes for
   both toolchains), not `mulAccelerated()` itself (the
   `CERTPP_DISABLE_HWACCEL_SIMD` runs leave the ratio unchanged). The actual
   cause was that RSA was never on Montgomery -- see P1. **Resolved**: sign
   takes 4.69 ms on MSVC against 5.48 ms on GCC (1.17x, down from 2.37x).
   Knuth-D division is data-dependent; Montgomery's CIOS iterates a fixed
   number of times regardless of operand values.
2. **MD5 was 23% slower on GCC** (455 against 593 MiB/s). One scalar routine,
   one direction, no acceleration involved. **Resolved** by P7: GCC now leads
   at 718 MiB/s.
3. **DSA-2048 is 2.7x slower to sign on GCC** -- 7.29 against 2.70 ms, and
   18.1 against 6.6 ms to verify. A wider gap than RSA's ever was, found only
   when the benchmark was extended to cover every algorithm. **Open**, and
   uninvestigated: the backend is the same `CBigNum` RSA was on, so the cause
   is presumably the same shape of thing `CMontgomery` fixed, but the profile
   has not been taken.
4. **Every GF(2^m) curve is 1.2--2.1x slower on GCC** -- B-571 verify is
   19.9 ms against 7.6 ms. Ten curves, all moving the same way, which argues
   for a shared cause in `CGf2m` rather than ten coincidences. **Open**, and
   uninvestigated.

Both sets of figures come from the same harness on the same machine, so the
comparison is like-for-like. Two limits on that comparison: the GCC side ran
under WSL2 (a VM), and "both Release" hides that CMake's Release defaults are
`/O2` for MSVC and `-O3` for GCC.

### The optimisation level is not the cause, and does not need changing

The confound above was worth removing rather than leaving as a caveat, so both
toolchains were rebuilt across their optimisation levels and the same
algorithms timed. Measured on this machine, min of 3 batches of 5 iterations:

| Build | RSA-2048 sign | DSA-2048 sign | B-571 verify | MD5 | ARIA-256-CBC |
|---|---|---|---|---|---|
| GCC `-O3` (the default) | 5.65 ms | 7.25 ms | 19.39 ms | 710.6 MiB/s | 28.5 MiB/s |
| GCC `-O2` | 5.33 ms | 7.50 ms | 19.31 ms | 687.4 MiB/s | 28.3 MiB/s |
| GCC `-O1` | 5.57 ms | 7.28 ms | 19.50 ms | 665.4 MiB/s | 28.7 MiB/s |
| GCC `-Os` | 5.40 ms | 7.18 ms | 19.12 ms | 718.2 MiB/s | 28.5 MiB/s |
| GCC `-O3 -march=native` | 6.06 ms | 7.19 ms | 18.59 ms | 666.7 MiB/s | 28.2 MiB/s |
| GCC `-O3 -flto` | 6.27 ms | 7.32 ms | 19.74 ms | 717.9 MiB/s | 29.1 MiB/s |
| MSVC `/O2` (the default) | 5.71 ms | 2.73 ms | 7.76 ms | 572.5 MiB/s | -- |
| MSVC `/O3` | 5.69 ms | 2.66 ms | 7.60 ms | 567.3 MiB/s | 45.5 MiB/s |
| MSVC `/Ox` | 5.66 ms | 2.78 ms | 7.87 ms | 560.9 MiB/s | 45.1 MiB/s |

Nothing there is worth changing, and two entries are worth never using.
`-march=native` makes RSA **7% slower** (5.65 to 6.06 ms) and `-flto` makes it
11% slower again, both from changes in what the optimiser chooses rather than
from the instruction set. MSVC `/Ox` costs **20% on SHA-1** (1766 to
1407 MiB/s). Every other difference is inside this machine's 20--30% spread,
which means `/O3` on MSVC is *not* a demonstrated improvement over `/O2` even
though it wins four of the five rows.

The conclusion that matters for the two open items: **the GCC gaps do not move
with the optimisation level.** GCC is 7.2--7.5 ms on DSA-2048 signing at every
level from `-Os` to `-O3`, and 19.1--19.5 ms on B-571 verify. Those are
algorithm-level differences in the shared `CBigNum` and `CGf2m` backends, and
no flag reaches them. Anything still worth chasing should be aimed there, and
re-measured on bare-metal Linux before the gap is called a GCC bug.

## Not planned

- Path validation. Still deliberately out of scope; see
  [`CLAUDE.md`](../CLAUDE.md). `CCertCollection::buildChain()` orders
  certificates by who issued whom and `verifyLinks()` checks each link's
  signature. What is absent is everything *else* a validator does: validity
  periods, `basicConstraints`, `keyUsage`, name constraints, policy constraints,
  revocation, and the decision of whether the root at the end is one the caller
  trusts. An ordered chain out of this library is a validator's input, not its
  verdict.