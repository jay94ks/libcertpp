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

Work that was requested here and has since landed is described in
[`docs/architecture.md`](architecture.md), with the reasoning behind it in
[`docs/changelog.md`](changelog.md). It is not repeated here, and a list of it
would go stale on the next thing that lands.

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
done and what is left.

Figures are min-of-N on a 4-core i7-11370H running at 3.92 GHz sustained under
this load; the machine's run-to-run spread is wide enough (11--25%, worse under
load) that only large differences mean anything. Three sets are reasoned from
below and all come off that same machine: the historical MSVC figures, the
cross-toolchain pair in the last item (GCC 13.3 on Ubuntu 24.04 under WSL2
alongside MSVC 19.36 on Windows), and the `CERTPP_DISABLE_HWACCEL_SIMD` runs
immediately after. The GCC side is a VM rather than bare metal, and CMake's
Release defaults differ between the two (`/O2` against `-O3`), so it reads as
toolchain plus optimization level.

### What the accelerated paths are actually worth

Rebuilding both toolchains with `-DCERTPP_DISABLE_HWACCEL_SIMD` compiles out
four accelerations at once -- `CBigNum::mulAccelerated()`'s MULX/ADCX,
`CGf2m`'s word-level reduction, GHASH, and ChaCha20's SSE2 keystream -- so the
ratio between on and off attributes each. Same machine, same session, min of
3x20 over three runs:

| | MSVC on | MSVC off | GCC on | GCC off |
|---|---|---|---|---|
| AES-256-GCM, 64 KiB | 370 MiB/s | **53 MiB/s** | 475 MiB/s | **64 MiB/s** |
| ChaCha20-Poly1305, 64 KiB | 578 MiB/s | 346 MiB/s | 650 MiB/s | 408 MiB/s |
| XChaCha20-Poly1305, 64 KiB | 577 MiB/s | 353 MiB/s | 648 MiB/s | 409 MiB/s |
| RSA-2048 sign | 8.06 ms | 8.85 ms | 19.1 ms | 19.7 ms |
| RSA-2048 verify | 0.145 ms | 0.171 ms | 0.392 ms | 0.408 ms |
| ECDSA P-256 sign | 0.916 ms | 0.884 ms | 0.862 ms | 0.832 ms |

Two things fall out of that, and both matter more than any single number in it.

**The GF(2^m)/GHASH path is worth about 7x, and nothing else is close.**
AES-GCM without it runs at 53--64 MiB/s against ChaCha20-Poly1305's 346--408.
That is the measurement behind `README.md`'s claim that GHASH rather than the
cipher is AES-GCM's bottleneck, and why AES-GCM still lands *below*
ChaCha20-Poly1305 after acceleration rather than above it.

**`CBigNum::mulAccelerated()` is worth nothing measurable.** Every big-number
row moves by less than the machine's own 11--25% spread, so the honest reading
is that turning the MULX/ADCX path on changes RSA and prime-curve timings by an
amount indistinguishable from noise. The prime-curve rows moved the other way
-- marginally faster with acceleration off, on both toolchains -- which is the
opposite sign and the same noise-sized magnitude, so neither direction is a
result either. This is the most useful single fact in the section, and it cuts
against the obvious plan: there is nothing to win by improving that function.

### Ordered plan

Sequenced by what the measurements actually support, not by how easy each item
looks. Each names how it would be verified, because on this machine a change
smaller than ~20% is not a change.

**P0 -- Close the measurement gaps.** *Done.* `examples/05_benchmark.cpp` now
times ML-KEM-768 key generation, which `benchKem()` previously called once for
setup and never measured, and a new `benchSmallRecord()` reports the 64 B
`seal()` that the small-record target below is written in but nothing measured.
`perf` covered the third gap. Two results came out of it worth more than the
gaps they closed:

- **ML-KEM-768 key generation is 0.193 ms** on MSVC and 0.142 ms on GCC, both
  slower than either encapsulate or decapsulate.
- **AES-256-GCM is the faster AEAD at 64 B and the slower one at 64 KiB** --
  225 ns against ChaCha20-Poly1305's 410 ns per record on MSVC (180 against 332
  on GCC), then 370 against 578 MiB/s in bulk. AES-GCM runs one block where
  ChaCha runs two, the extra being the Poly1305 one-time key at counter 0.
  That is real, but it does not mean what this section previously said it meant
  -- see P3, where measuring where the 410 ns actually goes overturned the
  conclusion drawn from it.

**P1 -- Put RSA on Montgomery, which it never was.** *Answered, and the answer
inverts what this item assumed.* Profiling the WSL Release build with `perf`
put **36.7% of all cycles in `CBigNum::divMod()`**, reached as
`RsaContext::sign` -> `CBigNum::modExp` -> `CBigNum::mulMod` -> `CBigNum::mod`
-> `CBigNum::divMod`. Reading the source confirms what that tree says:

- `CBigNum::modExp()` (`bignum.cpp:913`) is an ordinary integer
  exponentiation, and `CBigNum::mulMod()` (`bignum.cpp:763`) is still `mul()`
  then `mod()`.
- `CMontgomery::modExp()` (`montgomery.cpp:444`) exists and is Montgomery, but
  the profile contains no call to it. Its callers are the prime curves
  (`eccurve.cpp:747`) and Ed448 (`ed448.cpp:65`). **RSA is not among them.**

So every modular multiplication in an RSA-2048 private-key operation *was* a
schoolbook long division. That is a structural omission, not a tuning gap, and
it is larger than the cross-toolchain question it was filed under -- which is
why the 2.4x read as a codegen curiosity. Two toolchains cannot disagree about
a path only one of them takes.

This corrected the diagnosis an earlier revision of this section gave, which
nominated the Montgomery reduction's *shape* as the candidate. The shape was
irrelevant: RSA never reached it.

### P1 done, and the cross-toolchain gap went with it

All seven `CBigNum::modExp` call sites in `rsa.cpp` now route through a
`modExpMod()` helper that builds a `CMontgomery` and falls back to
`CBigNum::modExp()` for an even or zero modulus -- a fallback that is not
decoration, since `CMontgomery` turns invalid into a no-op returning zero, and
a silent zero is worse than a slow answer.

| RSA-2048 | before | after |
|---|---|---|
| MSVC sign | 8.06 ms | **4.69 ms** |
| GCC sign | 19.07 ms | **5.48 ms** |
| MSVC verify | 0.145 ms | 0.140 ms |
| GCC verify | 0.392 ms | **0.156 ms** |

**The 2.37x cross-toolchain gap collapsed to 1.17x**, which was not predicted
and is the more useful half of the result. Knuth-D division is data-dependent --
it normalizes and trial-subtracts per quotient digit -- so two compilers
translate it very differently. Montgomery's CIOS passes iterate a fixed number
of times regardless of operand values, which is the shape that compiles
similarly everywhere. The gap was a symptom of the algorithm rather than an
independent codegen defect, and removing the shared inefficiency took it with
it. So the WSL2 and differing-Release-defaults caveats below apply to the
*before* column and are largely retired for RSA.

Verified by 128/128 CTest on MSVC, by the RSA/x509/PSS subset on GCC, and
separately by cross-checking `CMontgomery::modExp` against `CBigNum::modExp`
over 2400 cases spanning the exponent shapes RSA uses. That last check is not
something the suite provides: `rsa.cpp`'s round-trips verify a signature with
the key that produced it, so a mutually-wrong pair of implementations would
still pass.

One prediction here was wrong and is worth correcting rather than quietly
dropping. This item previously said the CRT halves "need their own two
Montgomery contexts rather than sharing one", as though that were extra work
beyond the conversion. It is not: `modExpMod()` builds a context per call from
the modulus it is handed, so `privateExp()`'s two branches get `p` and `q`
contexts automatically and nothing had to be threaded through by hand. The
fault-attack countermeasures at `rsa.cpp:417--444` likewise needed no change --
`privateExp()`'s shape is untouched and only the exponentiation beneath it
moved, so the re-encrypt consistency check still runs on every signature. The
risk flagged before the work started turned out to be in the *verification*
rather than the code, which is what the 2400-case cross-check was for.

**P2 -- Bring AES-256-GCM level with ChaCha20-Poly1305.** Its 7x path is already
in place, so the remaining gap to ChaCha (370 against 578 MiB/s on MSVC, 475
against 650 on GCC) is whatever GHASH still costs above the cipher. Best ratio
of value to work on the list: a pure throughput gap on a routine that is
already vectorized, and a caller reaching for AES-GCM on x86 currently gets
less than one reaching for ChaCha20. Verify in the harness's AEAD block, both
toolchains.

Still first among the remaining items, but the margin is narrower than it was
when the plan was written: P1 removed a 42--71% gap here, and this one is 36%.

**The obvious fix for this was tried and is a regression, so do not try it
again.** GHASH multiplies one block at a time (`ghash.cpp:232`), which makes
every block's multiply depend on the previous result, and the standard remedy is
to fold four blocks against precomputed powers of H so the chain is a quarter
as long. Implemented and measured, it came out **9--16% slower**: four blocks
cost seven PCLMULQDQ multiplies against the four the recurrence needs, because
X_1..X_4 carry *descending* powers (H^4, H^3, H^2, H) and cannot be folded
against one power the way the first attempt assumed. Verified against
`multiplyPortable()` block for block, so the arithmetic was right and the shape
was wrong.

So GHASH is not waiting for better chaining; it is waiting for fewer or cheaper
multiplies, which on this CPU means VPCLMULQDQ rather than PCLMULQDQ. The
`CERTPP_DISABLE_HWACCEL_SIMD` runs above put the GF(2^m)/GHASH path at 7x,
which is what vectorization is worth here, and the remaining 36% is inside
CLMUL itself. Measure that before assuming anything about the cipher -- the
ChaCha20 SSE2 path, by comparison, is only 1.6--1.7x.

One thing that was measured and is worth keeping: hoisting `H`'s bit reversal
out of the per-block path is worth 4.6% and produces identical output. That is
below this machine's noise floor for a reported change and is **not** recorded
as done, but it is the only GHASH change tried here that was not a regression.

**P3 -- ChaCha20-Poly1305: the per-record cost is real, and its cause is a
threshold rather than the lane-counting problem this item assumed.** The 410 ns
per record is real, but the reason it is 410 is not what this section said.

*Where the 410 ns actually goes.* Measured through `seal()` across a sweep of
sizes rather than by adding up its parts, because an earlier single-pair
measurement of this got it wrong. The curve is not a line, and it has a step in
it:

| payload | blocks | keystream path | `seal()` |
|---|---|---|---|
| 0 B | 0 | -- | **180--210 ns** |
| 64 B | 1 | scalar | 340--352 ns |
| 128 B | 2 | scalar | 485--488 ns |
| 192 B | 3 | scalar | 634--639 ns |
| **256 B** | 4 | **SSE2** | **568--575 ns** |

Min of 5x20000 over two runs, GCC. Two things fall out, and they point in
opposite directions from how this section used to describe the problem.

**There is a fixed cost, and it is about 200 ns** -- read directly from the 0 B
row, not extrapolated. That is the one-time key block plus Poly1305 over the AAD
and length blocks, and it is roughly half of a 64 B record. An earlier reading of
this item fit a straight line to 64 B against 192 B and reported the intercept as
zero; the fit was wrong, because 192 B is not "two blocks more" than 64 B in any
sense the curve respects, and a straight line cannot represent the step below.
Two of the four points that fit most badly are the ones either side of it.

**Below 256 B, every payload block is scalar, and that is where the rest goes.**
`xorStream()` routes only whole four-block groups to SSE2 --
`vectorBlocks = wholeBlocks & ~size_t(3)` (`chacha20core.cpp:225`) -- so 64, 128
and 192 B all take the scalar loop and pay ~130--155 ns per block, while 256 B
drops to ~143 ns *for four blocks*. Hence 192 B costing more than 256 B, which
reproduces in both runs. The small-record cost is a **threshold**, not a
lane-counting problem: records under 256 B never reach the vectorised path at
all.

That also kills the per-record fix this item proposed, and for a structural
reason rather than a discouraging one: it was to generate counters 0--3 in one
SSE2 pass, so the one-time key and the first blocks came out of the same lanes.
SSE2 is 128-bit and fixed, so a two-block need computes four and discards two.
Measured, that is **1.43x slower** -- `blockVectorized()`, which produces
byte-identical output (verified over 4456 cases), loses to the scalar path
because the discarded lanes still pay for SIMD shuffles and register pressure.
Vectorising a *run* of blocks, rather than one, is the same mistake and was tried
first: also slower, at 24%.

What survives is therefore not the proposed change but the problem it was aimed
at, and the threshold question has now been answered rather than left open:
**lowering the four-block threshold to one is also a regression.** Measured in
situ, reproducing the scalar loop's shape from `chacha20core.cpp:235` against a
one-block SSE2 pass over the same buffer, one block runs 142.9--151.4 ns scalar
against 177.8--212.7 ns vectorised -- **1.17--1.49x slower**. The isolated
`blockVectorized` figure understated it, and for a reason worth recording: the
scalar loop never materialises a keystream block at all, it XORs straight into
the caller's buffer word by word, so the vector path's extra stores are on top of
a scalar path that is already leaner than the benchmark's baseline.

The serial path has no slack either. `twentyRounds()` compiles to **zero xmm
registers** -- 32 `rol`, 32 `xor`, 31 `add`, no auto-vectorisation -- and a full
`block()` costs 100.5 ns, which at 3.92 GHz is **6.2 cycles/byte**, squarely in
the normal published range for scalar ChaCha20 on x86-64. There is no compiler
accident inflating the comparison and no easy win on the serial side to offset a
vector path that loses.

So both halves of the per-record problem are now closed as measurements rather
than assumptions: the ~200 ns floor is real and irreducible without removing the
one-time key derivation, and the scalar-to-vector transition below 256 B cannot be
reversed in the vector path's favour.

*Bulk (the 1.5 GiB/s target):* AVX2 eight-block keystream, then Poly1305 in
SIMD. The keystream is the cheaper half -- SSE2 four-block buys 1.6--1.7x
today, so AVX2 eight-block is that argument one level up. Poly1305 needs
precomputed powers of `r`, not wider limbs; that negative result is recorded
in the item below and should not be re-tried. This CPU has both AVX2 and
VPCLMULQDQ, so the instructions exist; what is missing is the code.

The lesson worth carrying to the next pass on this file, and it has two halves.
Five changes were implemented here on the reasoning that fewer instructions would
mean less work, and all five cost more, in every case because they widened a
computation to fill SIMD lanes that the input did not fill. Measure the
decomposition before proposing the change, not after. The other half: the
original diagnosis was also wrong in the *opposite* direction, in that it claimed
the per-record cost was removable when it is not -- it is a floor. A measurement
that contradicts the plan is worth as much as one that confirms it, and this
section was wrong twice in one session.

**P4 -- `Fe25519` onto a 2^51 radix.** 25 limb products where there are 100
now, plus a dedicated `square` for roughly another 30%. Target 100 us each way;
currently 280/140 us on GCC and 333/164 us on MSVC. This covers X25519 and
Ed25519 only.

**P5 -- A field for the prime curves.** Twenty-nine curves and no per-curve
field is a plan, so this is the one item here whose scope is genuinely open.
P1 has since reported, and it does not unblock this the way the earlier
revision assumed: the prime curves were *already* on Montgomery
(`eccurve.cpp:747`), so RSA's omission says nothing about whether a field
generalizes to twenty-nine different primes. What P1 does contribute is the
counter-example -- a whole number type sitting outside the modulus abstraction
while its siblings use it, and nobody noticing, because the numbers still
validate. Whether that warrants a shared field type for the curves is a
separate decision, not a consequence of P1.

**P6 -- Ed448 and P-521.** The remaining signature outliers, neither of which
has had a dedicated pass.

**P7 -- MD5 on GCC.** 455 against 593 MiB/s: one scalar routine, no
acceleration involved, independent of everything above. Small and isolated.

Deliberately last: the constant-time items below. They are correctness and
security work rather than throughput, and their schedule should not compete
with the items above.

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
- **Small-record cost.** The 150 ns target is **withdrawn**: a `seal()` with an
  empty payload already costs 180--210 ns, so 150 ns is not reachable at any
  payload size without removing the one-time key derivation itself. Below 256 B
  the cost is also stuck on the scalar keystream path, because `xorStream()`
  only vectorises whole four-block groups (`chacha20core.cpp:225`), which is why
  192 B costs more than 256 B. Both terms are structural rather than tuning
  gaps. P3 records the sweep and the one change that could move the threshold.
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
  exceptions that run the other way, **both since resolved, in opposite
  directions**:

  1. **RSA-2048 was 2.4x slower to sign on GCC** (19.1 ms against 8.06 ms) and
     2.7x slower to verify. Two hypotheses were ruled out before the right one
     was found, and the wrong ones are recorded so nobody re-derives them. Not
     the portable multiply: `CBigNum::mul()` dispatches to `mulAccelerated()`
     on a `hasAdxBmi2()` check that passes for both toolchains -- GCC through
     the function-level `__attribute__((target("bmi2,adx")))`, MSVC through
     unconditional intrinsic use. Not `mulAccelerated()` either: the
     `CERTPP_DISABLE_HWACCEL_SIMD` runs above leave the ratio essentially
     unchanged (2.37x accelerated, 2.23x without), and that path is worth
     nothing measurable even on MSVC. The actual cause was that RSA was never on
     Montgomery at all -- see P1.

     **Resolved, and the gap collapsed with it.** After the conversion, sign
     takes 4.69 ms on MSVC against 5.48 ms on GCC: 1.17x, down from 2.37x.
     Knuth-D division is data-dependent -- it normalizes and trial-subtracts
     per quotient digit -- so two compilers translate it very differently,
     while Montgomery's CIOS iterates a fixed number of times regardless of
     operand values. The 2.4x was a symptom of the algorithm, not an
     independent codegen defect.

  2. **MD5 is 23% slower on GCC** (455 against 593 MiB/s) while every other
     hash is equal or faster. Untouched by P1 and still open, and now the only
     thing left in this item: one scalar routine, one direction, no
     acceleration involved. P7.

  Both sets of figures come from the same harness on the same machine, so the
  comparison is like-for-like; `README.md`'s tables carry the full set. Two
  limits on that comparison, both of which the table's own numbers invite the
  reader to forget: the GCC side ran **under WSL2**, a VM rather than bare
  metal, so it reads as this toolchain in this setup and not as Linux
  performance in general; and "both Release" hides that CMake's Release
  defaults are `/O2` for MSVC and `-O3` for GCC, so toolchain and optimization
  level are varied together. Neither of those is what made RSA look like a
  codegen curiosity: a 2.4x gap between two compilers on one source is not a VM
  artefact or an `/O2`-against-`/O3` artefact, and reading it as one would have
  been the mistake. Anything still worth chasing here should be re-measured on
  bare-metal Linux before the gap is called a GCC bug. Note too that MSVC's own
  numbers came in 10--20% under the set published before them, which is a
  reminder that the load conditions move these figures as much as the code
  does.

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
