# RSA profiling and Montgomery arithmetic

[한국어](18-rsa-profiling.ko.md)

## Profiling: RSA was never on Montgomery, and the small-record cost is two blocks

← [History](../HISTORY.md)

Following the roadmap's P0 and P1. Both changed the plan rather than merely
executing it, which is why they are recorded here at length.

#### P0 -- two measurement gaps, and what came out of closing them

`examples/05_benchmark.cpp` now times ML-KEM-768 key generation, which
`benchKem()` previously called once for setup and never measured -- the reason
`README.md`'s table carried a dash in that cell -- and a new
`benchSmallRecord()` reports the 64 B `seal()` that the small-record target is
written in and that nothing measured. Both toolchains were re-measured three
times rather than from the single run that would have filled the cells.

Reusing one key and nonce in that loop is not flattering the number, and worth
being explicit about: `CChaCha20Poly1305::seal()` re-derives the one-time key
through `ChaCha20Core::block()` on every call and constructs a fresh
`CPoly1305` for the tag, so there is no cross-call state for the loop to warm.
What the loop does hold constant is the key.

The result inverts an ordering the tables implied. **AES-256-GCM is the fastest
of the three AEADs at 64 B and the slowest at 64 KiB**, on both toolchains:

| | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305, 64 B | 410 ns | 332 ns |
| XChaCha20-Poly1305, 64 B | 545 ns | 449 ns |
| AES-256-GCM, 64 B | **225 ns** | **179 ns** |
| ChaCha20-Poly1305, 64 KiB | 578 MiB/s | 650 MiB/s |
| AES-256-GCM, 64 KiB | 370 MiB/s | 475 MiB/s |

(The 64 KiB row is what the AVX2 keystream later changed, to 736 and 835; the
64 B rows are unchanged by it, as they were meant to be.)

AES-GCM encrypts one block where ChaCha20 encrypts two, the second being the
block deriving the Poly1305 one-time key at counter 0 (RFC 8439 2.6). A bulk
sender and a per-record caller are looking at different winners, so the
roadmap's ChaCha20-Poly1305 item -- one target, 1.5 GiB/s bulk against a 150 ns
per-record cost -- has been split into two changes that do not overlap. The
per-record half was sequenced first: folding the key derivation into a single
four-wide SSE2 pass is one pass against an entire AVX2 rewrite, and it helps
every record-sized caller rather than only bulk ones. **That sequencing turned
out to rest on a measurement that was wrong, and the correction is recorded
under "the small-record cost is not what it seemed" below.**

ML-KEM-768 key generation measured 0.193 ms on MSVC and 0.142 ms on GCC, slower
than either encapsulate or decapsulate.

#### The small-record cost is not what it seemed

Measuring where the 410 ns actually goes, rather than adding up the parts,
overturned the P0 conclusion twice over -- and both corrections pointed away
from the original claim.

A sweep of nine sizes shows the cost curve is not a line and has a step in it.
Fitting 64 B against 192 B and reporting the intercept as zero, which is what
the first reading did, is wrong because 192 B is not "two blocks more" than
64 B in any sense the curve respects: `xorStream()` sends only whole four-block
groups to SSE2 (`vectorBlocks = wholeBlocks & ~size_t(3)`,
`chacha20core.cpp:225`), so 64/128/192 B all take the scalar path and 256 B is
the first vectorised size. Measured, min of 5x20000 over two runs, GCC:

| payload | blocks | keystream path | `seal()` |
|---|---|---|---|
| 0 B | 0 | -- | **180--210 ns** |
| 64 B | 1 | scalar | 340--352 ns |
| 128 B | 2 | scalar | 485--488 ns |
| 192 B | 3 | scalar | 634--639 ns |
| **256 B** | 4 | **SSE2** | **568--575 ns** |

192 B costs more than 256 B, and that reproduces every run -- it is what the
straight-line fit was absorbing. So there **is** a fixed cost of about 200 ns,
the one-time key block plus Poly1305 over the AAD and length blocks, roughly
half of a 64 B record. The 150 ns target is therefore unreachable at any payload
size without removing the one-time key derivation itself, and is withdrawn.

The proposed fix fails for a clearer reason than the original one gave. It was
to generate counters 0--3 in one SSE2 pass, a lane-counting argument, but the
real problem is that sub-256 B records never reach the vectorised path at all.
Vectorising a *run* of blocks was tried first and came out 24% slower;
`blockVectorized()`, which produces byte-identical output (verified over 4456
cases), came out **1.43x slower** because discarded lanes still pay for SIMD
shuffles and register pressure. Reproduced in situ against the scalar loop's own
shape from `chacha20core.cpp:235` -- one block is 142.9--151.4 ns scalar against
177.8--212.7 ns vectorised, **1.17--1.49x slower** -- so the isolated benchmark
understated it, because the scalar loop never materialises a keystream block at
all and XORs straight into the caller's buffer.

Lowering the four-block threshold to one was the obvious follow-up and is also
a regression, for the same reason. The serial path has no slack to offset it
either: `twentyRounds()` compiles to **zero xmm registers** (32 `rol`, 32 `xor`,
31 `add`, no auto-vectorisation) and `block()` costs 100.5 ns, which at 3.92 GHz
is **6.2 cycles/byte** -- squarely normal published scalar ChaCha20 for x86-64.
That last figure first looked implausible and prompted the disassembly check;
it is correct, not a compiler artifact.

#### P3 bulk -- an AVX2 eight-block keystream, and where the target actually goes

Of seven changes attempted in this area, this is the first to survive
measurement. ChaCha20 blocks are independent by construction, so the existing
SSE2 path already exploits that with four lanes; this doubles it. On 64 KiB
(GCC, min of 5x40, two runs) the keystream goes **48.0 to 24.6 us, 1.95x**, and
the whole AEAD 97.6 to 72.8 us, 1.34x. On the project harness:

| | before | after |
|---|---|---|
| MSVC ChaCha20-Poly1305, 64 KiB | 578 MiB/s | 736 MiB/s |
| MSVC XChaCha20-Poly1305, 64 KiB | 577 MiB/s | 748 MiB/s |
| GCC ChaCha20-Poly1305, 64 KiB | 650 MiB/s | 835 MiB/s |
| GCC XChaCha20-Poly1305, 64 KiB | 648 MiB/s | 840 MiB/s |

AVX2 is not part of any x86-64 ABI, so the gate is a runtime CPUID check rather
than the architecture, cached in a function-local static because CPUID is
serialising. It is also gated on **512 bytes and up**, deliberately: eight lanes
computed and six discarded is a loss for a short payload, which is the same trap
the four-block path falls into below 256 B. Small records are unchanged at
410--440 ns.

The 8x8 transpose needed `_mm256_permutevar8x32_epi32` per 128-bit half rather
than the shuffle-based sequence the four-block path uses. `_mm256_shuffle_epi32`
and the unpack family operate within each 128-bit lane independently, so after
the first two stages each vector holds two rows interleaved lane by lane and no
half-select can separate them; a brute-force search over all 256
`permute2x128` immediates confirmed no combination of them works. Which lane
holds which value was derived by transposing an identity matrix and reading the
result -- column k's rows 0..3 sit in `u[k/2]` and rows 4..7 in `u[k/2 + 4]`,
even k reading lanes {0,1,4,5} and odd k {2,3,6,7} -- because two hand-derived
attempts were wrong first.

**The 1.5 GiB/s target is not reached, and the reason is arithmetic.** Splitting
the 64 KiB AEAD shows the two halves are equal -- 48.0 us of keystream against
48.2 us of Poly1305 -- so the MAC is 50% of the cost and no keystream
improvement alone can reach the target. At the measured AVX2 keystream the budget
for cipher and MAC together is 40.7 us, of which the cipher now takes 24.6,
leaving 16.1 us for a MAC that currently needs 48.2.

#### P3 -- Poly1305, and why the target is closed rather than open

Attempted, measured, and it does not pay on this CPU. Two things had to be
established before concluding that, and the first one is the one that mattered.

**The scalar routine is throughput-bound, not latency-bound.** That distinction
decides whether any parallel approach can help: if a serial dependency chain were
the cost, overlapping independent accumulators would recover it. Running two,
three and four independent accumulators over the same data instead costs 0.51x,
0.67x and 0.75x of a *single stream's rate*, so the multiply throughput is
already what saturates and there is no idle chain to fill.

**The vector form is slower than the scalar one.** Two floors, measured
(min of 5x60 over three runs, GCC):

| | cycles/block |
|---|---|
| 25 scalar multiplies, no adds or carries | 24.1 |
| **`absorbBlock()` as it ships** | **45.7** |
| 13 `vpmuludq` packing those same 25 products | 26.3 |

So vectorising the multiply costs 1.06--1.09x, reproducibly. This is the same
trap the ChaCha20 attempts fell into in a different place: AVX2 has no
64x64->128 multiply -- that is AVX512IFMA -- so a 26x26 product is one
`vpmuludq` either way, and putting two in an instruction only saves one if the
operands already sit in the lanes `vpmuludq` reads. They do not; they have to be
shuffled into place first, and that costs more than the multiply it saves. The
adds, the carry chain and the reduction are all still owed on top.

The only route below the scalar floor is *fewer* multiplies rather than cheaper
ones, which needs 64x64->128 or the precomputed powers of `r` this roadmap
already names -- and neither has a usable instruction path for this recurrence on
this CPU. **The ChaCha20-Poly1305 throughput target is therefore closed as a
measured negative result.** In cycles/byte, which is how it should be judged
against other hardware: the landed AVX2 keystream is 1.47, the MAC is 2.88, and
the 1.5 GiB/s target is 2.43 for the two together -- missed by roughly 0.45
cycles/byte on the MAC side, which no multiplication-side vectorisation closes.

The wider scalar experiments stand and are not disturbed by this: three 44-bit
limbs with nine 64x64->128 products per block measured no faster than the
portable five-limb 26-bit path, and slower again once the carries went through
`_addcarry_u64`.

One methodological note, because it nearly produced a wrong conclusion here. A
first run of the multiply-floor probe reported 15% overhead and a later one 67%,
which was not measurement drift: the probe had failed to compile (a missing
`<immintrin.h>`) and the run script executed the stale binary left over from an
earlier edit. Every benchmark script used from here on removes its output binary
before compiling and exits if the build failed, because a benchmark that measures
a different program than the one edited is worse than no benchmark.

#### P1 -- the RSA bottleneck, and a correction

Profiling the WSL Release build with `perf` put **36.7% of all cycles in
`CBigNum::divMod()`**, reached as `RsaContext::sign` -> `CBigNum::modExp` ->
`CBigNum::mulMod` -> `CBigNum::mod` -> `CBigNum::divMod`. The source agrees:

- `CBigNum::modExp()` (`bignum.cpp:913`) is an ordinary integer exponentiation
  and `CBigNum::mulMod()` (`bignum.cpp:763`) is still `mul()` then `mod()`.
- `CMontgomery::modExp()` (`montgomery.cpp:444`) exists, is Montgomery, and does
  not appear in the profile at all. Its callers are the prime curves
  (`eccurve.cpp:747`) and Ed448 (`ed448.cpp:65`).

So RSA performs a schoolbook long division for every modular multiplication in
a private-key operation, while code paths next to it use Montgomery. That
corrects a diagnosis the roadmap gave two commits earlier, which nominated the
Montgomery reduction's *shape* -- whether the accumulator was wide enough to
avoid a conditional subtract per step. The shape is not the question here: RSA
never reaches that code. It also reframes the cross-toolchain gap recorded
above. A 2.4x gap there reads as a codegen curiosity; more likely it is a shared
inefficiency both toolchains pay, differing only in degree. Two compilers do not
disagree by 2.4x about a division, but they do disagree about how expensive it is
once both are paying it.

The fix is to route `rsa.cpp`'s `CBigNum::modExp` calls (`rsa.cpp:433`, `:434`,
`:444`, `:463`, `:518`, `:627`, `:677`) through `CMontgomery`, and it is not a
small one. It touches the CRT blinding and its fault-attack countermeasures
(`rsa.cpp:417--444`), and the CRT constants `dp`, `dq` and `qInv` are derived
modulo *different* primes than `n`, so each half needs its own Montgomery
context rather than sharing one. `tests/` must go on proving that the CRT result
agrees with a full re-encrypt, which is the countermeasure that makes CRT worth
doing at all.

#### How the profile was taken, and what it does not show

`perf record` over the whole harness rather than a purpose-built RSA-only
workload. RSA dominates wall clock in that run, so it dominates the profile, but
the 36.7% is a share of the entire process rather than of RSA signing alone. The
absence of `CMontgomery::modExp` from the profile is the load-bearing evidence;
the percentage is corroboration. A dedicated profile isolating
`RsaContext::sign` would give a sharper number, and should be the first thing
done when that work starts.

#### Follow-up -- packed exponentiation and inversion

The Montgomery routing landed with the CRT re-encrypt check intact. A later Windows Clang profile
showed that long exponentiation still converted every intermediate between `CBigNum`'s 32-bit
limbs and the 64-bit CIOS digits. Keeping the accumulator and sliding-window table packed for the
entire chain reduced RSA-2048 signing from 1.334 to 0.968 ms. The same path accelerated
Miller--Rabin and DSA exponentiation. `modExpProduct()` then kept DSA's two-base verification chain
packed, and binary extended GCD removed quotient-sized division from odd-modulus inversions. An
integrated CIOS loop advances product and reduction carries in one accumulator traversal, and a
two-bit simultaneous product table reduces DSA verification's conditional multiplications.

Eleven high-priority, single-processor runs against OpenSSL 3.6.4 produced median paired ratios of
0.364/0.266/0.610 for RSA and 0.605/0.653/0.479 for DSA key generation, signing, and verification.
RSA key-generation latency stayed effectively flat at 67.994 ms versus the prior 67.951 ms; its
paired ratio moved because independent random prime searches make that row much noisier.
The target is still open: generated code for the BMI2/ADX target uses `mulx` with ordinary carry chains and remains
well behind OpenSSL's hand-tuned Montgomery kernel.
