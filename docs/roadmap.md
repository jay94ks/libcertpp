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

### Ordered plan (P0--P8)

Sequenced by what the measurements actually support, not by how easy each item
looks. Each names how it would be verified, because on this machine a change
smaller than ~20% is not a change. Full detail, including negative results and
corrected diagnoses, is in [`docs/changelog.md`](changelog.md).

| Item | Status | Result |
|---|---|---|
| **P0** -- Close the measurement gaps | **Done** | `benchSmallRecord()` reports the 64 B `seal()`; ML-KEM keygen and the 64 B/64 KiB AEAD split are now measured. |
| **P1** -- Put RSA on Montgomery | **Done** | Sign 42--71% faster; cross-toolchain gap 2.37x to 1.17x. [Changelog](changelog.md) |
| **P2** -- AES-256-GCM to ChaCha level | **Re-opened** -- see below | GHASH 4-block chaining measured 9--16% slower; X_1..X_4 carry descending powers and cannot share one multiplier. That is a negative result about one decomposition, not about GHASH, and this machine carries `vpclmulqdq` and `gfni`, which attack it differently. [Below](#closing-the-gap-to-openssl) |
| **P3** -- ChaCha20-Poly1305 | **Done** (keystream half) | AVX2 eight-block keystream: 1.95x on the keystream, 1.34x on the AEAD. Poly1305 is multiply-throughput-bound and vectorising it is 1.06--1.09x *slower*. |
| **P4** -- `Fe25519` dedicated square / 2^51 radix | **Re-opened** -- see below | The 22% was measured through MSVC's `_umul128` software emulation. Measured against the product accumulation on GCC, where `__int128` is native, the 2^51 layout is 4.6--4.9x cheaper, not 22%. The *dedicated square* half is still a negative result: two attempts at it were wrong because the radix corrections are asymmetric. [Below](#closing-the-gap-to-openssl) |
| **P5** -- A field for the prime curves | **Closed** (negative result) | The prime curves are *already* on Montgomery (`eccurve.cpp:747`), so there is no per-curve field to build. |
| **P6** -- Ed448 and P-521 | **Closed** (negative result) | Both curves already have dedicated constant-time paths: P-521 is on Montgomery (`eccurve.cpp:747`), Ed448 has its own branch-free ladder (`ed448.cpp:192`) over `CMontgomery` (`ed448.cpp:129`). |
| **P7** -- MD5 on GCC | **Done** | Unrolling the four rounds removed a branch and a modulo per step: 545 to 341 cycles/block, 1.60x. GCC 455 to 718 MiB/s; MSVC unchanged within noise. |
| **P8** -- AES-CBC register chain | **Done** | `CbcTransformer`'s per-block interface cost two loads and two stores a block of a chain that never needed to leave a register. Holding it in a `__m128i`: MSVC 1.94--2.14x, GCC 1.84--2.03x, AES-256-CBC now 0.94x OpenSSL. [Changelog](changelog.md) |

The lesson worth carrying to the next pass: seven changes were implemented on
the reasoning that fewer instructions would mean less work, and six of the
seven cost more, every time because they widened a computation to fill SIMD
lanes that the input did not fill. Measure the decomposition before proposing
the change, not after. And the generalisable form: the first question to ask
of any SIMD proposal is not "does it compute the same thing" but **"is the
thing I am vectorising actually the bottleneck."**

P8 is the shape those seven were not. It vectorises nothing and widens nothing;
it removes one load and one store per block from a chain whose dependency is
inherently serial. The reason it worked where the others failed is that the
bottleneck was not the arithmetic but the interface around it -- which is the
same lesson in a form that is easy to get backwards: the arithmetic being
hard is not a reason to suspect it, and the arithmetic being *solved* by a
hardware instruction is not a reason to expect the caller's layer to be free.

ARIA is the one throughput gap left, and it is not the same kind: 28 MiB/s
against OpenSSL's 114 for ARIA-256-CBC, after P8. AES-NI's absence is the whole
story and there is no ARIA equivalent to reach for, so this is portable C++
against hand-written assembly rather than anything portable C++ can be changed
to close. No further CBC work is planned.

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
- **`Fe25519` dedicated square.** A dedicated `square` halves the off-diagonal
  terms (12% of X25519). Measured, and a negative result: two attempts at the
  merged square were wrong, because the radix corrections are asymmetric. The
  2^51 *radix* half of this item moved to the OpenSSL section below, having been
  measured through MSVC's `_umul128` software emulation rather than through
  GCC's native `__int128`.
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

## Closing the gap to OpenSSL

Re-measured 2026-10-11 with `examples/06_openssl_compare.cpp` against OpenSSL 3.0.13,
GCC Release under WSL2, on the i7-11370H this file's other figures come from. The
recorded ratios reproduce, so nothing below rests on a stale number.

Two runs of the same binary, one after the other, which is also the noise floor:

| | run 1 | run 2 |
|---|---|---|
| SHA-256, 64 KiB | 0.97x | 0.97x |
| SHA-1, 64 KiB | 0.97x | 0.93x |
| MD5, 64 KiB | 0.89x | 0.92x |
| AES-256-CBC, 64 KiB | 0.95x | 0.93x |
| SHA3-256, 64 KiB | 0.66x | 0.72x |
| SHAKE-256, 64 KiB | 0.66x | 0.72x |
| SHA-512, 64 KiB | 0.51x | 0.51x |
| ARIA-256-CBC, 64 KiB | 0.26x | 0.26x |
| Ed25519 sign | 4.51x slower | 4.43x slower |

Only three of those moved at all between runs, and by less than this machine's
20--30% spread. That is the honest reading, and it is the one to carry: SHA-512,
ARIA and Ed25519 reproduce to within 2%, and the rows that wobbled are wobbling
inside noise, not trending.

### Classifying the gaps by kind, because the kind decides whether they can close

The four remaining gaps are not four instances of one problem, and treating them
as one is how the previous pass spent six of seven changes.

**1. Ed25519 signing, 4.5x -- a work-volume gap, now decomposed for the first time.**

This had never been profiled, and the only hypothesis on file could not account
for it. Measured, per signature:

| | certpp | OpenSSL |
|---|---|---|
| instructions retired | 2,262,504 | 609,642 (**3.71x**) |
| cycles | 702,145 | 157,278 (4.47x) |
| IPC | 3.22 | 3.88 |

The instruction count is where the gap is. IPC differs by 20%, which is inside
this machine's spread; **certpp is not slower because its code runs worse, it is
slower because it is 3.7x longer.** That immediately rules out the whole family of
changes that failed before -- rescheduling, better use of the FMA pipes,
wider accumulators -- none of which shorten the computation.

Where the length is, by self time:

| | share |
|---|---|
| `Fe25519::mul` | **75.8%** |
| `Fe25519::add` | 9.3% |
| `Fe25519::sub` | 8.3% |
| `Edwards25519::scalarMulBase` (self) | 2.1% |

Three quarters of it is one function, and that function is a **10x10 = 100-product
schoolbook multiply over 26-bit limbs** (`fe25519.hpp:52`, `LIMBS = 10`). Each of
its 100 products is a single 64-bit `imul`, because 26+26 = 52 bits fits in a
word. OpenSSL's field is **5 limbs at radix 2^51**: 25 products, each a
64x64->128.

Measured in isolation, the two layouts' product accumulations cost:

| layout | products | ns/call |
|---|---|---|
| 2^25.5, 64-bit accumulate | 100 | 43.2--44.6 |
| 2^51, 128-bit accumulate | 25 | 9.1--9.4 |
| | | **4.6--4.9x** |

**This re-opens P4.** P4 recorded that a 2^51 radix would cut multiply work by
22%, and closed the item on that number. That number came from MSVC, where
`__int128` does not exist and `_umul128` is a three-instruction software
emulation -- and this comparison runs on GCC, where `__int128` is native and a
64x64->128 is one `mulq`. The 22% describes the emulation, not the layout.

Two things to be careful about, because P4 was closed for a reason. The kernel
measurement above is the product accumulation only -- no carry reduction, and
certpp's real `mul` also does a x2 pass on five odd limbs and a x19 pass on eight
of `g` -- so 4.6--4.9x is an upper bound and the end-to-end number will be lower.
And P4's second attempt was *wrong*, because the 2^51 radix corrections are
asymmetric; that hazard is unchanged and is why the item needs a KAT, not just a
benchmark. What has changed is only that the arithmetic now says there is
probably 2x or more here, where the file said there was 22%.

Expected, if the arithmetic holds: signing from 0.19 ms toward ~0.08 ms, i.e.
4.5x to roughly 2.5x of OpenSSL. That is a prediction from an isolated kernel
measurement, not a result, and it is falsified or confirmed by one A/B run.

**2. SHA-512, 0.51x -- the largest hash gap, and it is not vectorisation-bound
either.** SHA-NI covers SHA-1 and SHA-256 and there is no SHA-512 equivalent, so
both sides run scalar code and the SHA-256/SHA-512 split the README describes
stands. What is untested is whether an **AVX2** path pays here: SHA-512's message
schedule is 16 words of 64 bits, which is exactly four 256-bit registers, so
unlike the changes that failed before, the input *does* fill the lanes. This
machine has AVX2. Expected 1.5--2x if it works; unmeasured, so it is a
proposal with a verification method, not a plan with a result.

**3. SHA3-256 / SHAKE-256, 0.66x -- a real gap with an awkward shape.** Keccak-f[1600]
is 25 lanes of 64 bits. AVX2 carries 4 lanes, so 25 = 6x4 + 1: six of every seven
iterations fill the registers and one does not. That raggedness is the same
failure mode as the seven closed items, in a milder form, and it is why this is
last rather than first despite being a larger gap than SHA-512's.

**4. ARIA-256-CBC, 0.26x -- not closable.** There is no ARIA instruction, and
OpenSSL's is hand-written assembly. Portable C++ has nothing to reach for. This
is now recorded as a permanent gap rather than remaining work.

### Two closed items whose stated prerequisite this machine actually has

Both of these were closed against an analysis that assumed less hardware than is
present. Worth one run each before either is accepted as final.

- **P2 (AES-256-GCM)** closed with "VPCLMULQDQ is the only remaining path". This
  CPU has `vpclmulqdq` **and** `gfni`, and carries the current 4-block chaining
  problem completely differently from the `X_1..X_4` reduction that was measured
  9--16% slower. The negative result is about one decomposition, not about GHASH.
- **Poly1305** is the "only remaining path to the 1.5 GiB/s ChaCha target", and
  its stated blocker was that AVX2 has no 64x64->128, needing AVX512IFMA or
  precomputed powers of `r`. This CPU has `avx512ifma`. Whether it helps on a
  45.7-cycles/block workload is the open question, but the item was parked
  against a hardware absence that does not apply here.

### Order, and why this order

Ranked by measured size of the gap, which on this machine is the only ranking that
survives contact with the noise floor -- and by whether the decomposition is
already done.

| | Item | Gap | State |
|---|---|---|---|
| 1 | Ed25519 field to radix 2^51, native `__int128` | 4.5x | **measured; negative** |
| 2 | SHA-512 message schedule on AVX2 | 0.51x | **measured; wrong target** |
| 3 | P2 (GHASH via VPCLMULQDQ/GFNI) | -- | **measured; closed positive** |
| 4 | Poly1305 on AVX512IFMA | -- | re-opened by hardware presence |
| 5 | SHA3/SHAKE on AVX2 | 0.66x | proposed, awkward lane fit |
| -- | ARIA-256-CBC | 0.26x | not closable; recorded and closed |

Items 1--3 are now measured and written up below. The ordering held up: item 1 had the
largest gap and the finished decomposition, and items 2 and 3 were the two whose stated
prerequisite this machine has. What the three have in common is that **two of the three
proposals named the wrong target**, and in both cases the decomposition said so before any
of it was written.

Item 1 first because it is the only one where the decomposition is finished, the
gap is the largest, and the roadmap's own verdict was reached on a number from
the wrong toolchain path. Items 2 and 5 are proposals: the SHA-512 lane fit is
the first in this file's history where the argument for vectorising is "the input
fills the lanes" rather than "fewer instructions", which is the question the
previous seven items were really about and the one P8 finally answered.

### What would falsify this section

Every ratio above is one run of fastest-of-five on one machine under WSL2, and
this file already records that WSL2 is a VM. Before any of this is treated as
settled, re-run on bare-metal Linux: the two GCC-only gaps (DSA-2048, GF(2^m))
have never been reproduced off a VM, and an AVX512 result measured inside one may
not be a result at all. The Ed25519 decomposition is less exposed -- it is an
instruction count, not a time -- but the predicted end-to-end outcome is, and it
has no KAT behind it until item 1 is implemented and the field's known-answer
tests pass.

### Item 1 measured: a negative result, and the reason is not the radix

The section above predicted that moving `Fe25519` to radix 2^51 would take Ed25519 signing from
4.5x OpenSSL to roughly 2.5x. It was implemented, it is correct, and **it is not faster.** Both
layouts, built from one source and timed back to back in one session, with OpenSSL's own timing
as the control that says the machine was quiet:

| | best of 3 |
|---|---|
| control: OpenSSL | 0.0515 ms (4% spread) |
| radix 2^51, five limbs | 0.1919 ms |
| **radix 2^25.5, ten limbs** | **0.1812 ms** |

6% the wrong way, which is inside this machine's noise floor and therefore reads as "no change".
The prediction said 2x. What happened is nothing.

The 4.6--4.9x was real. It measured the **product accumulation in isolation**, and that is still
what the two layouts differ by. The end-to-end number did not follow because the accumulation is
not what `Fe25519::mul` costs. The generated assembly for the 2^51 multiply:

| | count |
|---|---|
| `imulq` -- the 25 products | **25** |
| `movq` | 190 |
| `shrdq`/`shldq`/`salq`/`sarq` | 80 |

458 instructions for 25 multiplies. The multiply is not the cost; moving the numbers around it
is. Nine `__int128` accumulators are 18 registers and x86-64 has 15, so the products spill, and
`>> 51` on a 128-bit value is a double-precision shift -- `shrd`+`sar`, two instructions -- which
the reduction does eight of per round over three rounds.

A second version kept every carry in 64-bit words instead, which is the obvious next move and
which is the shape ref10 uses. It moved instructions per signature from 2,262,504 to 1,890,730 --
16% -- and left the wall clock where it was, with IPC falling from 3.22 to 2.44.

**So the diagnosis was right and the fix was not enough.** The bottleneck is the reduction's
data movement, not the width of the products, and narrowing the products does not touch it.

#### What is kept, and why

- `include/certpp/arch.hpp`, new and public: the single place the library decides what
  architecture it is on. Per-ISA, because the question that matters is not 32- versus 64-bit but
  whether one instruction produces a 128-bit product -- x86-64 and AArch64 can, x86 and ARM-32
  cannot, and inferring it from a word width is the mistake. Every remaining item in this section
  needs it.
- The radix-2^51 `Fe25519`, behind `CERTPP_ENABLE_FE25519_RADIX51`, **off by default**. It is
  correct -- 38,494 field assertions against `CBigNum`, every RFC 8032 and 7748 vector, 130/130 on
  both configurations -- and it is off because it is not faster, so the default build carries no
  regression risk and none of the second layout's maintenance cost. It stays in the tree so that
  the negative result is reproducible rather than merely recorded: turn the option on and re-run
  the A/B.

#### What this cost, and what it bought

Three bugs in the new code, all caught by the existing tests rather than by inspection, and the
third only after a probe whose expectations are computed in Python -- the hand-written ones were
wrong twice, in opposite directions, which is what a hand-built fixture does:

1. `toBytes` produced non-canonical bytes for values at or above p. The `CBigNum` encoding test
   caught it; 22 assertions.
2. `condSwap` zero-extended its 32-bit mask to the 51-bit limb type, so `0xFFFFFFFF` swapped the
   low half of every limb. Caught by the condSwap test, which compares limbs directly.
3. The reduction's carry chain normalised `t[0..7]` but not `t[8]`, so the 19x fold read an
   un-reduced pair. Caught only by the Python-generated probe, and only on products above 2^408
   -- everything below it was right, which is a worse way to find out.

What it bought is the reason the answer is now known rather than guessed. P4 was closed in
**two** sentences on a 22% figure that turned out to be measuring `_umul128`. Measured: that
emulation is 6.5--7.0x the native one, 66--69 ns against the 43--45 ns of the layout it would
replace, so a single 2^51 implementation everywhere would have made MSVC *slower than it is
today*. That is why this is a gate and not a rewrite, and it is the part of the investigation
that generalises to everything else in this section.

### Item 2 measured: the message schedule is not the bottleneck, and the vectorisation argument was sound

Item 2 proposed vectorising SHA-512's message schedule on AVX2, and this file's own wording said
why it should work: "the SHA-512 lane fit is the first in this file's history where the argument
for vectorising is 'the input fills the lanes' rather than 'fewer instructions'". Sixteen 64-bit
words do fill exactly four 256-bit registers. That argument is correct, and it does not matter,
because the schedule is not most of the cost. Per 128-byte block, by building the same
compression function with each part present and subtracting:

| | ns/block | share |
|---|---|---|
| packing `W[0..15]` | 18.7 | 5.0% |
| message schedule `W[16..79]` | 73.7 | 19.9% |
| **the 80 rounds** | **278.4** | **75.1%** |

The rounds are 75%, and they are a serial dependency chain -- round *i*'s `e`, `f` and `g` are
round *i-1*'s `a`, `b` and `c`. The critical path is roughly seven dependent operations per round
with a one-cycle latency each, which is close to what the measurement shows: 278 ns for 80 rounds
is about 12 cycles per round. Vectorising a 20% component against a 75% latency-bound one cannot
be the 2x that closes 0.51x.

**So the item is closed as proposed, and the diagnosis is kept.** What the decomposition did find
is that the packing -- 5% of the work, and the only part that was not doing real work -- built
each big-endian message word one byte at a time: eight loads and seven shift-or pairs per word,
where `BSWAP` is one instruction. Both x86-64 and AArch64 have it, so this needs no new ISA and
no runtime check. Measured effect on the compression function: **8.7% and 4.5% on two runs of the
same probe** -- a probe, not the library, on a machine that had a competing job for part of the
session, which is why both numbers are reported rather than the larger one.

What shipped instead, because it was measured rather than argued:

- `Sha2_64Core::loadBe64()`, one byte-swap per word. The generated packing is now three
  instructions per word (`movq`/`bswap`/`movq`) against twenty-three. SHA-384 shares this core.
- `Ch` and `Maj` in their shorter forms -- `g ^ (e & (f ^ g))` instead of `(e & f) ^ (~e & g)`,
  which spends a NOT the hardware does not have, and `((a | b) & c) | (a & b)` instead of a
  five-operation expression. Neither changes an output bit.

End to end, interleaved with OpenSSL as the control on a quiet machine: **SHA-512 333.5 ->
355.8 MiB/s, +6.7%, against a control that moved -0.4%.** A second, independent interleaved
run gave +6.4% against a control at +0.2%, so the two runs bracket it at +6.4--6.7%.

### Item 3 measured: GHASH was the larger half of GCM, and the win was in the reflection

P2 was closed on the grounds that "VPCLMULQDQ is the only remaining path", with 4-block chaining
measured 9--16% slower. The item was re-opened because this CPU has both `vpclmulqdq` and
`gfni`. Decomposing AES-256-GCM first, in instructions per 16-byte block -- an instruction count
does not need a quiet machine, which is what made this measurable at all, since a competing job
ran for much of the session:

| | per block |
|---|---|
| `AesCore::encryptBlock` (the cipher) | 167.8 |
| GHASH, xor + multiply | 179.7 |
| `CAesGcm::seal` (the whole construction) | 310.9 |

**GHASH is the larger half**, which is the opposite of the SHA-512 verdict and is why item 2 and
item 3 came out differently from the same method. It is worth attacking.

But not by the means proposed. `VPCLMULQDQ` aggregates *independent* carry-less multiplies, and
in GCM the per-block multiplies are one serial chain -- each block's accumulator depends on the
last. There is nothing there to aggregate, which is the structural reason the 4-block reduction
was slower. Decomposing the multiply instead:

| | count |
|---|---|
| `multiplyAccelerated`, as written | 91 instructions |
| of which shift/mask/or -- the basis conversion | **45** |

Half the accelerated multiply was converting between GCM's bit-reflected convention and the
ordinary polynomial basis. **One of the three conversions was on `h`**, the subkey, which is
fixed for the whole message -- it was being re-reflected once per 16 bytes. The other two are on
the block and on the product, both of which genuinely change.

So:

- `H` is reflected once, in `reset()`, into `_hReflected`. That is the "precompute what does not
  change" half, and it needs no new instruction at all.
- The two conversions that remain are one `GF2P8AFFINEQB` each where GFNI exists, against the
  twenty-instruction SSE2 sequence. **This is what GFNI is actually good for** -- not
  aggregation. The roadmap named the right feature for the wrong job.
- Which of the two applies is read from a CPUID-guarded static **once per message** rather than
  twice per block, because a guarded static costs a load and a test on every read and this is
  called every 16 bytes.

The public `Ghash::multiply()`, which takes a raw `h` and so cannot use a prepared copy, is
unchanged in cost.

Result: **310.9 -> 237.5 instructions per block, 23.6% fewer**, measured, with 19,762 GHASH
assertions and the twelve published GCM vectors passing. Wall clock, interleaved against the
control on a quiet machine: **AES-256-GCM 438.1 -> 494.1 MiB/s, +12.8%, control -0.8%**, with a
spread of 1.9% and 2.9% within each side. A second run gave +10.0% against a control at -4.7%,
so the two bracket it at +10--13%. The
instruction count is the larger number than the clock, and the gap is the point: what was removed
was cheap, well-pipelined SSE2 shifting, while what remains is latency-bound on a 5--7 cycle
`PCLMULQDQ` chain. Removing a quarter of the instructions removes an eighth of the time. Anyone
reading only the instruction count would overstate this by nearly twice.

**P2 is therefore closed, positively, and for a different reason than it was proposed.** What
generalises: the roadmap asked "is the thing I am vectorising the bottleneck" and got "yes" here
and "no" there, and in the case where the answer was yes, the work that paid was not vectorising
anything. It was noticing that a quarter of the function was recomputing a constant.

#### One thing this cost: a constant that was reasoned out and was wrong

The GFNI bit-reversal matrix came out as `0x0102040810204080`, which is the transpose of the
answer, and which computes **the identity** -- it reversed nothing at all. The GHASH field
identities failed immediately. The correct constant is `0x8040201008040201`, settled by running
every candidate against the SSE2 sequence that was already there and already correct, over all
256 byte values in all 16 positions. It is recorded here because "check the matrix against the
thing it replaces" is cheap and this file already contains one instance of trusting a constant
that ought to have been generated (`CName::TYPE_OIDS` had ten arcs where the OID has seven).

MSVC declares the GFNI intrinsics in `zmmintrin.h` rather than `immintrin.h`, which is why that
include is there; it was found by grepping the toolset headers, because the GCC build compiled
first and cleanly.

## Not planned

- Path validation. Still deliberately out of scope; see
  [`CLAUDE.md`](../CLAUDE.md). `CCertCollection::buildChain()` orders
  certificates by who issued whom and `verifyLinks()` checks each link's
  signature. What is absent is everything *else* a validator does: validity
  periods, `basicConstraints`, `keyUsage`, name constraints, policy constraints,
  revocation, and the decision of whether the root at the end is one the caller
  trusts. An ordered chain out of this library is a validator's input, not its
  verdict.

### DES measured: the permutation was already unrolled, and the change broke a table

`examples/05_benchmark` puts DES-CBC at 5.1 MiB/s and 3DES-CBC at 1.7 MiB/s against AES-256-CBC
at 1313, which reads as the largest outlier in the library. Decomposed, the cipher is the whole of
it -- `processBlock()` alone measures 1,484.9 ns against 4.8 MiB/s end to end, so there is no
interface overhead to remove, unlike AES-CBC before it.

The source suggested a specific cause. `DesCore::permute()` extracts one bit at a time through a
variable shift, and `feistel()` calls it twice per round: 208 iterations per block. Making the
tables `constexpr` and the permutation a template on the table should turn every shift amount into
an immediate and let the loop unroll.

**It did not.** `feistel()` is 175 instructions before and after, with an identical mix -- 34
`andl`, 21 `movl`, 16 `shrb`, 16 `movzbl`, 15 `sall`, 15 `orl`. GCC was already inlining
`permute()` into `feistel()` and constant-folding it; the twenty-instruction loop body in the
generated `permute` symbol was the out-of-line copy that nothing called. The variable shift I was
looking at was not in the executed path.

What the change did break was a table. Transcribing PC1 into the header swapped its last two rows,
and the classic FIPS 46-3 worked example failed at once -- `CHECK( memcmp(out, EXPECTED, 8) == 0
)` returning 71. Caught by the existing test, which is what it is for. Reverted in full; the
measured performance is unchanged because there was never any to gain.

**So DES stays at 5.1 MiB/s, and the reason is now known rather than guessed.** The block is
~2,800 instructions at IPC 0.63, and the cost is the eight S-box lookups per round -- data-dependent
byte loads from a 512-byte table, 128 of them per block -- plus the permutations, both of which
the compiler has already shaped as well as this formulation allows. Closing it means bit-slicing,
which is a rewrite of the core rather than an optimisation of it, and DES is a legacy cipher kept
for PKCS#12 compatibility. Recorded and closed, the same shape as ARIA.
