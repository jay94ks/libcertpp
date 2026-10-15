# Not planned

[한국어](not-planned.ko.md)

## Not planned

← [Roadmap](../PLANS.md)

- Revocation and full RFC 5280 policy-tree processing. `CPathValidator` now
  performs the documented core path checks against an explicit `CTrustStore`,
  but it deliberately returns `EPATH_REVOCATION_UNAVAILABLE` or
  `EPATH_POLICY_PROCESSING_UNAVAILABLE` when either additional capability is
  requested. Applications that require them must integrate a dedicated source
  of revocation state or a fuller policy engine.

### Sections

- [DES measured: the permutation was already unrolled, and the change broke a table](not-planned.md#des-measured-the-permutation-was-already-unrolled-and-the-change-broke-a-table)
- [ARIA re-examined: two hypotheses, both measured and both wrong](not-planned.md#aria-re-examined-two-hypotheses-both-measured-and-both-wrong)
- [ChaCha20-Poly1305 decomposed: Poly1305 is two thirds of it, and about 10x behind OpenSSL](not-planned.md#chacha20-poly1305-decomposed-poly1305-is-two-thirds-of-it-and-about-10x-behind-openssl)
- [The README's Performance section, trimmed: where its analysis now lives](not-planned.md#the-readmes-performance-section-trimmed-where-its-analysis-now-lives)
- [Why the gaps exist: instructions per byte, ours against OpenSSL](not-planned.md#why-the-gaps-exist-instructions-per-byte-ours-against-openssl)

## DES measured: the permutation was already unrolled, and the change broke a table

← [Not planned](not-planned.md#not-planned)

`examples/05_benchmark` puts DES-CBC at 5.2 MiB/s and 3DES-CBC at 1.7 MiB/s against AES-256-CBC
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

**So DES stays at 5.2 MiB/s, and the reason is now known rather than guessed.** The block is
~2,800 instructions at IPC 0.63, and the cost is the eight S-box lookups per round -- data-dependent
byte loads from a 512-byte table, 128 of them per block -- plus the permutations, both of which
the compiler has already shaped as well as this formulation allows. Closing it means bit-slicing,
which is a rewrite of the core rather than an optimisation of it, and DES is a legacy cipher kept
for PKCS#12 compatibility. Recorded and closed, the same shape as ARIA.

## ARIA re-examined: two hypotheses, both measured and both wrong

← [Not planned](not-planned.md#not-planned)

The 0.26x ARIA gap was recorded as "not closable" on the grounds that OpenSSL's is hand-written
assembly and portable C++ has nothing to reach for. With SHA-3 found to be hiding 484 wasted
instructions, ARIA was worth one more look.

Decomposed by instruction count. Per round, `diffusionLayer()` is 227 instructions against
`substitutionLayer()`'s 55 -- 76% of the round, sixteen outputs each a seven-input XOR. Two
hypotheses about where the 227 went, both tested against the generated code rather than reasoned
about:

1. **That each input byte was re-read from memory.** `diffusionLayer` showed 43 `movzbl`, and each
   input is referenced by up to seven different outputs, so re-reads looked likely. Loading the 16
   bytes into constants first changed the count from 229 to 227 -- nothing. Separating them shows
   30 of the 43 are loads from memory and 13 are register-to-register zero-extensions, so the
   hypothesis was simply wrong: GCC was already reading each byte once.

2. **That the zero-extensions were removable by wider intermediates.** The byte arithmetic keeps
   intermediates in 8-bit registers, each needing extension before the next XOR. Widening the
   inputs to `unsigned` produced bit-identical code -- 227 instructions, same mix. Also wrong.

So the 227 is the byte formulation's real cost: 96 XORs, 16 loads and 16 stores, with the
extensions and the memory operands the compiler chose under its own register allocation. The
remaining option is a different formulation -- a masked-broadcast SSE version, or the T-tables a
fast software cipher uses -- and both are a rewrite of the core rather than an optimisation of it.
ARIA is a 14-round cipher with a 128-bit diffusion layer and no hardware equivalent; the shape is
as closed as it was recorded.

Reverted in full. ARIA stays at 0.26x, now with the reason known rather than guessed, which is the
third item this session to end that way.

## ChaCha20-Poly1305 decomposed: Poly1305 is two thirds of it, and about 10x behind OpenSSL

← [Not planned](not-planned.md#not-planned)

The last unexamined item was ChaCha20-Poly1305, at 833 MiB/s against OpenSSL's 3,631. Decomposed
at 64 KiB so every figure is on the same scale -- measuring the two halves at 64-byte granularity
while the AEAD is measured at 64 KiB compares per-call overhead against throughput and reports
the AEAD as *faster* than one of its parts, which is how the first version of this probe read.
Re-measured 2026-10-13 as medians of 15 x 200 over three process invocations:

| | certpp | OpenSSL | ratio | 2026-10-11 |
|---|---|---|---|---|
| ChaCha20 `xorStream` | 2428 MiB/s | 6200 MiB/s | **0.39x** | 0.48x |
| Poly1305 MAC | 1537 MiB/s | 15017 MiB/s | **0.10x** | 0.09x |
| the AEAD | 912 MiB/s | 4355 MiB/s | **0.21x** | 0.23x |

So Poly1305 is two thirds of the AEAD's cost, and it is about 10x behind -- the largest gap found
in this whole survey, six times ARIA's and larger than Ed25519's. OpenSSL is using AVX512-IFMA
(`vpmadd52luq`/`vpmadd52huq`), and this machine has `avx512ifma`. **The roadmap's item 4 named the
right feature, which is a first.**

Two reproducibility notes, because both cost a wrong number to get past. OpenSSL 3.0.13 exposes
**no Poly1305 `EVP_MD` digest at all** -- `EVP_MD_fetch(NULL, "POLY1305", NULL)` returns NULL, as
does `EVP_get_digestbyname`. Poly1305 is reachable only inside the ChaCha20-Poly1305 AEAD or
through the `EVP_MAC` API, and a probe written against `EVP_poly1305()` measures nothing at all
while appearing to run. And the keystream row moved from 0.48x to 0.39x, which is the AVX-512
`xorStream16` path landing; the other two reproduce their earlier values to within 10%.

##### That 0.21x, corroborated by a second harness

The 0.21x above is the single most consequential number in this file, and it was measured with one
process and one loop shape. Corroborated on a different day by a second, unrelated harness:

| | certpp | OpenSSL | ratio |
|---|---|---|---|
| in-process, median of 15 x 200 | 812 MiB/s | 4080 MiB/s | **0.20x** |
| `openssl speed -evp`, 64 KiB | -- | 4000 MiB/s | -- |
| 2026-10-13, median of 15 x 200 | 912 MiB/s | 4355 MiB/s | **0.21x** |

Two harnesses that share no code agree on OpenSSL to within 2% (4080 in-process, 4000 from
`openssl speed`), and the certpp side reproduces across two sessions at 0.20x and 0.21x. The IFMA
premise is confirmed directly: `/proc/cpuinfo` and OpenSSL's own `OPENSSL_ia32cap` both carry
`avx512f`, `avx512ifma`, `avx512vl`, `gfni` and `vpclmulqdq`. **This gap is real and is not a
harness artefact**, which is the opposite of what the SHA-512 and Ed25519 rows turned out to be
earlier in this file.

The spread within a single run is worth recording, because it bounds what any of these numbers can
claim: median-to-max on one row reached **+521%** (5989..37200 ns on OpenSSL AES-256-GCM), and the
certpp ChaCha20-Poly1305 row moved 749..883 MiB/s across four process invocations. A ratio computed
from one unreplicated run is not a result. Anything quoted from here should be a median over
repeated batches, and the README's GCC column should be read with the same suspicion.

One harness trap, recorded because it cost a wrong conclusion and has no other symptom.
`CChaCha20Poly1305::seal()` requires `out` to be **exactly** `in.size()`; on a size mismatch it
fails closed, returns `false`, and leaves the output buffer untouched. A benchmark that passes
`size + 32` and discards the return value is timing the error path -- and reports **15,375,153
MiB/s** for a 64 KiB seal, a figure so absurd that it reads like a bug in the harness rather than
the obvious thing it is. The check belongs in the harness: run each body once and require the
ciphertext to actually change before its timing is trusted.

One thing to say about the arithmetic, because it cost a wrong conclusion on the way: these
instructions are not "52-bit multiply-add". `vpmadd52lo` gives bits 0..51 of `a*b + c`;
`vpmadd52huq` gives `((a*b) >> 52) + c` and does **not** mask its result to 52 bits -- a test that
expected masking reported the instruction as WRONG when the instruction was right and the
expectation was wrong. Verified against 128-bit arithmetic over the 26x26 case the algorithm
actually uses. The accumulator can therefore exceed 52 bits unless the algorithm keeps it in
range, which is exactly the constraint an implementation must respect.

Also measured and negative: hoisting `r[1..4] * 5` out of `absorbBlock()` changed nothing --
+1.3% on Poly1305 and +0.6% on the AEAD, both inside noise, and the instruction count went *up*
from 971 to 975 because GCC's loop-invariant code motion already moves those four multiplies out
of the block loop. Reverted. That is the fourth time in this session that a "recomputing a
constant" hypothesis turned out to be already handled by the compiler, after ARIA's byte loads,
ARIA's zero-extensions, and this.

So this is the item to take next, and it is a real implementation rather than a reformulation:
eight blocks at a time with `r^8 .. r^1` precomputed at key setup, the accumulator spread across
vector lanes in 26-bit limbs, and the carry propagation done in the vector form. It deserves its
own pass -- a MAC that is wrong only for some inputs is worse than one that is wrong for all of
them, and the KATs will not necessarily tell the difference between those two cases.

## The README's Performance section, trimmed: where its analysis now lives

← [Not planned](not-planned.md#not-planned)

The Performance section in `README.md` was carrying about four hundred lines, most of them
explanation rather than measurement. It now holds the tables, how they were taken, and a pointer
here. The reasoning that used to be in it:

**Two cross-toolchain gaps the section's own coverage surfaced.** Covering every algorithm found two
that had never been written down, and both are still open:

- **DSA-2048 is 2.7x slower to sign on GCC** -- 7.29 ms against 2.70 ms, and 18.1 ms against 6.6 ms
  to verify. That is a wider gap than RSA's ever was, and the only one large enough to read as a
  codegen defect rather than as noise. The backend is the same `CBigNum` RSA uses, so the cause is
  presumably the shape of thing `CMontgomery` fixed there -- but the profile has not been taken, so
  that is a hypothesis and nothing more.
- **Every GF(2^m) curve is 1.2--2.1x slower on GCC.** B-571 verify is 19.9 ms against 7.6 ms. Ten
  curves, all moving the same way, which argues for a shared cause in `CGf2m` rather than ten
  coincidences.

Both are recorded as items. The WSL2 caveat applies to both, and both should be re-measured on
bare metal before either is called a compiler defect.

**What the slower rows mean.** Not every row is a gap waiting to be closed:

- **DES and 3DES are ~1000x slower than AES**, which is the cipher itself being slow, not the
  library: 3DES runs three DES operations per block and DES has no acceleration on any x86.
- **ARIA runs ~45x slower than AES** for the opposite reason: AES-NI is a hardware instruction and
  ARIA has none, so the portable rounds are the whole implementation.
- **Signing beats verification on the prime curves** -- P-256 signs in 0.91 ms and verifies in
  2.43 ms -- because signing multiplies the *fixed* base point with a precomputed window table,
  while verification multiplies a caller-supplied point and cannot.
- **RSA-2048 is lopsided by design**: `e = 65537` makes verification three multiplies, while
  signing is a full CRT exponentiation.
- **AES-256-GCM sits below ChaCha20-Poly1305 despite AES-NI**, because GHASH rather than the cipher
  is the bottleneck and an AEAD composes as `1/total = 1/cipher + 1/mac`. (GHASH has since been
  worked on -- see the GFNI note above.)
- **The 64 B AEAD rows invert the 64 KiB ones.** AES-256-GCM is *faster* per record and *slower* in
  bulk, because AES-GCM encrypts one block where ChaCha20 encrypts two, and a small record cannot
  amortise the difference. A bulk sender and a per-record caller are looking at different winners.

Nanosecond figures are the noisiest in the set -- a gap under ~30% between two AEADs is unsettled.

**Two limits on the toolchain columns.** The GCC figures were taken **under WSL2** -- a real Linux
kernel inside a VM, not bare metal -- so that column reads as *this toolchain in this setup*, not
Linux in general. The harness is single-threaded and CPU-bound, so the hypervisor's share ought to
be small, but this run did not quantify it in either direction. And "Release" is not one setting:
CMake's defaults are `/O2` for MSVC and `-O3` for GCC, so toolchain and optimization level are
varied together.

## Why the gaps exist: instructions per byte, ours against OpenSSL

← [Not planned](not-planned.md#not-planned)

Every remaining ratio was explained by counting instructions rather than by timing, because a
throughput ratio on a machine with a competing job measures the machine. The count is a property of
the emitted code, so its ratio is the ceiling on what the implementation can explain, and anything
left over is the microarchitecture.

| | throughput ratio | instruction ratio | conclusion |
|---|---|---|---|
| SHA-256 | 1.04x | 1.09x | parity -- both call SHA-NI |
| SHA-1 | 0.92x | 1.28x | 28% more instructions, in the code |
| MD5 | 0.92x | 1.14x | 14% more instructions, in the code |
| **SHA-512** | 0.58x | **1.87x** | two causes, both measured |
| **ChaCha20** | 0.39x | **3.31x** | in the code |
| AES-256-CBC | 0.91x | -- | both call AES-NI |

Re-counted 2026-10-13. Instruction counts come from a two-point slope rather than a single run:
running the same body at 100 and 700 iterations and solving `b = (I(700) - I(100)) / 600` cancels
perf's startup, context creation and every other fixed cost exactly, without having to enumerate
them. The raw counts, in instructions per KiB:

| | certpp | OpenSSL | ratio |
|---|---|---|---|
| SHA-256 | 3041 | 2789 | 1.09x |
| SHA-1 | 2624 | 2050 | 1.28x |
| MD5 | 11192 | 9832 | 1.14x |
| SHA-512 | 36127 | 19341 | 1.87x |
| ChaCha20 keystream | 3968 | 1199 | 3.31x |

**Two rows here were stale and are now corrected.** SHA-512 was quoted at a 1.99x instruction
ratio, but that was measured at 38839 instructions/KiB -- the count *before* the BMI2 RORX work
landed. The shipped build measures 36127, which is within 0.02% of the 36135 this file records for
the post-RORX state, so 1.99x was double-counting an optimization already banked. ChaCha20 moved the
other way, 2.7x to 3.31x, because the AVX-512 path is wider and this is the count that says so.

For the hashes the instruction ratio and the throughput ratio now agree closely, so **the hashes'
gaps are in the code, not in the machine.** That is the answer to the question, and it is the same
for all of them.

##### SHA-512: two independent causes, separated by masking OpenSSL's capabilities

| OpenSSL's SHA-512 | instructions/KiB |
|---|---|
| as built | 19341 |
| `OPENSSL_ia32cap=0` -- vector features masked off | 28541 |
| **certpp** | **36127** |

Re-counted 2026-10-13; the 19342 and 28530 figures this table carried before reproduce to within
0.01% and 0.04%. The certpp figure does not, and the reason matters: it was 38839, which is the
count from *before* BMI2 RORX shipped. The build measures 36127 now, matching the 36135 recorded
below for the shipped state.

So the throughput ratio is two effects multiplying:

1. **1.32x -- OpenSSL vectorises the message schedule.** Masking its vector features costs it 48%
   more instructions (19341 -> 28541), and ours does not vectorise it at all.
2. **1.36x -- OpenSSL's portable C is 36% lighter than ours.** 3566 instructions per block against
   our 4855. Both are scalar C, so this is codegen and not hardware.

These two were quoted as 1.32x and 1.36x before; both survive re-measurement, with the vectorised
component's "32% more instructions" now measured at 48% off the re-counted baseline. The product is
1.87x against the throughput ratio of 0.58x, and the residue is microarchitecture.

Per 128-byte block against the algorithmic floor (80 rounds x ~19 ops plus 64 schedule words x ~10):

    certpp              4855    2.25x the floor
    OpenSSL scalar      3566    1.65x
    OpenSSL vector      2418    1.12x

OpenSSL's vector path is essentially at the floor. Ours is at 2.25x of it.

Where our extra 2695 instructions go: 89 of `transform()`'s 201 are `movq`, and a third of the round
body is copies of its own live word -- three `movq %rsi, %rXX` before three `rorq` of that same
register, because ROR is destructive and each rotate needs its own copy. It is not the `w[80]`
array, which is only 16% of the function's stack traffic.

##### The actionable finding: BMI2's RORX is worth 10.9% on SHA-512

RORX is three-operand and reads its source unmodified, so those copies should not exist. Measured:

    SHA-512, as built        38839 instructions/KiB
    SHA-512, with BMI2       34999 instructions/KiB     -9.9%

and it reaches the clock, interleaved over six rounds:

    SHA-512   348.1 -> 386.1 MiB/s    +10.9%
    SHA-256  1480.6 -> 1462.0          -1.3%   (noise; both sides call SHA-NI)
    SHA-1     1684.8 -> 1639.2          -2.7%   (noise)
    MD5        678.2 -> 676.3           -0.3%   (noise)

**Shipped: +7.5%, not +10.9%.** Implemented, RORX has to be inline assembly because `_rorx_u64()`
is only declared in a unit already built with BMI2 and this one deliberately is not, and an opaque
`__asm__` is something GCC can neither schedule around nor keep in registers. The dynamic
instruction count falls 7.0% (38839 -> 36135 per KiB) and throughput 7.5% by median of ten
alternating rounds, with SHA-256/SHA-1/MD5 at +1.2%/-0.1%/-0.6%. Capturing the rest means compiling
this one translation unit with `-mbmi2`, a build change rather than a code change. See the
changelog for the full account, including a gate that was wrong on the first attempt and would
have SIGILLed the fallback path.

**This corrects an earlier wrong conclusion in this file.** An earlier pass looked at the round
function, saw that its rotates were already single instructions (`ror`/`rol`), and concluded there
was nothing to gain. That was true of the rotate and wrong about what it cost -- the cost was the
copy the destructive form forces, which is not visible when looking at the rotate rather than at
what surrounds it. It is the second instruction-level finding this session that a count found and
an inspection did not.

The remaining 1.36x is OpenSSL's portable C being lighter than ours, and that is a different piece
of work -- register allocation and codegen, not a missing instruction.

##### What the others are

- **SHA-512's schedule**: Ours computes `w[80]` into a 640-byte array and reads it back. That is
  only 3% of the instructions, so it is not the reason OpenSSL's scalar path is lighter; the reason
  is the round body's copies above, and OpenSSL's schedule is vectorised on top of that.
- **ChaCha20 (historically 2.7x more instructions)**: This count came from the former eight-block
  AVX2 path. The current implementation also dispatches to a sixteen-block AVX-512F path; current
  throughput and the remaining gap are recorded in [`HISTORY.md`](../HISTORY.md) rather than
  treated as an open P3 item here.
- **AES-256-CBC and ARIA are excluded from the table above.** Counting them required an EVP stream
  on one side and a persistent transformer on the other, and the first version of that measurement
  put context creation inside the loop on the OpenSSL side -- reporting AES at 0.57x ours and ARIA
  at 3.40x, which measured the per-call setup rather than either cipher. Both sides call AES-NI for
  AES, so that row is parity; ARIA's gap is recorded and closed under ARIA.
