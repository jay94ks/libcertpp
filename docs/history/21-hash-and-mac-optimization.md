# Hash and MAC optimization

[한국어](21-hash-and-mac-optimization.ko.md)

## SHA-3/SHAKE: the state was being transposed byte-by-byte, and chi cost two instructions

← [History](../HISTORY.md)

SHA3-256 measured 0.72x OpenSSL and SHAKE-256 the same, the largest of the remaining gaps after
ARIA and Ed25519 had been closed. Decomposed by instruction count first, which is what said
which of two very different problems to fix.

`KeccakCore::permute()` was 892 instructions, of which `f1600()` -- the permutation itself -- is
408. The other ~484 were packing 25 lanes of 8 bytes in and unpacking them again, one byte at a
time. GCC does not leave that alone: it auto-vectorises it into an SSE transpose (`movdqu`,
`psrlw`, `packuswb`). But a transpose is the wrong shape for the job. Keccak lanes are
little-endian 64-bit words, so on a little-endian host a lane *is* the eight bytes as they sit in
memory -- one `memcpy` per lane, ~50 instructions.

So there are two paths, selected on the host's byte order: a copy where it is correct, and the
original loop where reversing is required. Both land on the same answer, held there by the
SHA-3/SHAKE known-answer vectors, so an endianness mistake fails the suite rather than producing
wrong digests. `permute()` went from 892 to 68 instructions; interleaved against OpenSSL with
SHA-256 and SHA-512 as controls, SHA3-256 306.9 -> 348.5 MiB/s (+13.6%) and SHAKE-128 +17.4%.

The second problem is the one that wanted assembly. `f1600`'s chi step computes
`a ^ (~b1 & b2)`, and the compiler emits `notq` then `andq` -- two instructions, and a NOT the
hardware has no other use for. BMI1's ANDN is that function in a single instruction.

First attempt: `__attribute__((target("bmi")))` on the helper itself. That made it 25 of 408
instructions' worth of calls, not one: GCC refuses to inline a function whose target attribute
does not match its caller's, and chi runs 25 times a round for 24 rounds. `f1600` went from 408
instructions to 861 and got slower. The fix is to put the attribute on the whole round loop,
templated on which chi to use, so the helper is compiled as part of a BMI-enabled instantiation
and inlines. `f1600`'s BMI path is now 361 instructions with 25 ANDN and no notq at all.

The ANDN is inline assembly rather than the compiler's own encoding of the expression, because
the instruction is the point and because AT&T reverses its operand order against Intel's: `%2`
is src1 and `%1` is src2. Verified against the plain expression over every discriminating pair
and 200,000 random pairs -- a swapped operand order is a different function that no commutative
identity would reveal.

Whether it was worth doing was not assumed. `f1600` is 136 stack loads and 136 stores deep,
because 25 lanes of live state do not fit in fifteen GPRs, so an operation bound on that might
not care about 25 fewer ALU instructions at all. Measured, it does care: `permute()` 460.2 ns ->
394.6 ns, -14.3%, tracking the -13.3% instruction count closely.

Combined, interleaved over 10 rounds with SHA-256/SHA-512/MD5/SHA-1 as controls, all four of
which held within 1%: **SHA3-256 +28.5%, SHA3-512 +28.4%, SHAKE-128 +26.5%, SHAKE-256 +28.6%.**
SHA3-256 moves from 0.72x to roughly 0.94x OpenSSL, and SHAKE-128 passes it.

`include/certpp/arch.hpp` gains `CERTPP_ARCH_HAS_ANDN`, the same shape as `CERTPP_ARCH_HAS_MULX`
beside it.

## Poly1305 on AVX512-IFMA: +20% on the MAC, +19% on ChaCha20-Poly1305

← [History](../HISTORY.md)

Roadmap item 4 said AVX512IFMA for Poly1305, and this is the one time a named mechanism in this
file turned out to be the actual bottleneck. Decomposed at 64 KiB, every part on the same scale:
ChaCha20's `xorStream` is 2492 MiB/s and Poly1305's MAC is 1196.9, so Poly1305 is two thirds of
the AEAD's cost. Against OpenSSL's 12633.4 -- the largest single gap in the survey, 0.09x.

Eight blocks at a time, eight lanes, one block per lane. The recurrence becomes

    a <- a * r^8 + sum_{i=1..8} n_i * r^{9-i}

so the eight multiplies the scalar path does serially happen in parallel, as twenty-five
`vpmadd52luq` for the 5x5 limb cross-products, then one horizontal sum per limb. Every limb
product stays under 2^52 -- 26 bits times 26 bits -- so the `luq` channel alone carries it; the
`huq` channel would give `((a*b)>>52) + c`, which for 26-bit operands is just `c`.

The powers r^2..r^8 are built the first time a whole group of eight turns up, not at reset():
seven 130-bit multiplies is real cost on a 64-byte record, and the vector path would never earn
it back there.

**Three bugs, all found by the new test and none by the published vectors.** The RFC 8439 2.5.2
message is 34 bytes, so every existing KAT stops short of the 128 bytes one push needs -- a
vector path that only runs on long input and is wrong on long input would have passed all of
them. The new test uses Python-generated expectations at lengths on and around the group
boundaries, and pushes each one in many chunk sizes so the two paths are held against each other:

1. The blocks were loaded without the 2^128 Poly1305 appends above a full block.
2. The lane-to-power map was reversed -- lane 0 carries the *oldest* block, which takes the
   *largest* power, so the index is `7 - j` and not `j`.
3. `reduce9` double-counted the low 26 bits of the top limb into the wrong place.

The first run of the vector path was also **slower than the scalar one, by 42.7%**, which is how
the third redundant-work pattern showed up again: `blockLimbs()` was called forty times per group
for the thirty-two limbs of eight blocks. Moving it out of the limb loop took that off, and the
remaining gap is the design's own -- nine horizontal sums and one scalar 130-bit multiply per
group -- which is why the gain is 20% rather than the 3x the instruction mix suggests.

Measured, interleaved over ten rounds with ChaCha20 as the control (it moved +0.5%):

    Poly1305 MAC             1087.6 -> 1312.6 MiB/s   +20.7%
    ChaCha20-Poly1305          715.2 ->  853.3 MiB/s   +19.3%

The arithmetic is worth recording because it cost a wrong conclusion earlier: these instructions
are not "52-bit multiply-add" with masking. `vpmadd52lo` gives bits 0..51 of `a*b + c` and
`vpmadd52hi` gives `((a*b)>>52) + c` **without** masking its result. Verified against 128-bit
arithmetic over the 26x26 case the algorithm uses, and the CPUID bit (leaf 7 sub-leaf 0, EBX bit
21) read off the machine rather than recalled -- leaf 7 sub-leaf 1 reports nothing here, and a
wrong bit either misses the feature or SIGILLs on a CPU without it.

`include/certpp/arch.hpp` gains `CERTPP_ARCH_HAS_IFMA_POLY1305`, a separate gate from
`CERTPP_ARCH_HAS_ANDN`'s because AVX512-IFMA is rare and independent of BMI1 -- one gate covering
both would SIGILL on the many CPUs with BMI1 and no IFMA.

130/130 on GCC Release+ASan, GCC ASan, MSVC Release and MSVC Debug.

## SHA-512 on BMI2's RORX: the copies the destructive rotate forced are gone

← [History](../HISTORY.md)

The investigation into why the gaps exist found that SHA-512's round body copies its live word
three times before its three rotates: `movq %rsi, %rXX` before `rorq` of that same register, because
ROR is destructive and each rotate needs its own copy. 89 of `transform()`'s 201 instructions are
movq and this is a third of the round body.

RORX is three-operate and reads its source unmodified, so those copies should not exist, and they
stop existing:

    instructions per KiB     38839 -> 36135    -7.0%
    throughput (median of 10 alternating rounds, spread 4.9%)

        SHA-512   353.7 -> 380.4 MiB/s    +7.5%
        SHA-256   1425.3 -> 1441.7       +1.2%    (noise -- both sides call SHA-NI)
        SHA-1      1644.2 -> 1641.8       -0.1%    (noise)
        MD5         676.9 -> 673.1       -0.6%    (noise)

Instruction counts are the load-bearing figure here; the machine had a competing GitHub Actions
runner for much of the window, and a single best-of-six throughput run had SHA-256 falling 19.5% on
a change that cannot touch it. The counts do not move with the machine, and the medians confirm
the direction.

**This captures 7 of the ~9.9 instruction points a whole-TU `-mbmi2` build gets, and the reason is
worth recording.** The rotate has to be inline assembly, because `_rorx_u64()` is only declared in a
translation unit already built with BMI2 and this file deliberately is not -- the library targets
baseline x86-64 and gains features at runtime. An opaque `__asm__` is something GCC can neither
schedule around nor keep in registers, and the static instruction count of the BMI2 instantiation
at first came out *higher* than the scalar one's (235 against 201) even though the dynamic count
fell. Capturing the rest would mean compiling this one translation unit with `-mbmi2`, which is a
build change rather than a code change.

**The construction, and a bug in the first version of it.** The attribute cannot sit on the rotate
helper: GCC refuses to inline a function whose target differs from its caller's, and at six rotates
a round for eighty rounds that is 480 calls a block -- the trap already hit on Keccak's ANDN. So
the compression function is a template on which rotate to use, the attribute sits on the BMI2
instantiation, and the CPUID check happens once per block.

The first version then gated the rotate on the *build macro* rather than on the template
parameter, which meant `transformRounds<false>` -- the path that exists for a CPU without BMI2 --
also emitted RORX. It was caught by diffing the two instantiations, which came out of the compiler
identical apart from label names. Fixed, and the property is now checked in the shipped object
rather than in the source: `transformRounds<true>` has 22 `rorx`, `transformRounds<false>` has none.

`arch.hpp` gains `CERTPP_ARCH_HAS_BMI2_ROTR`, beside `CERTPP_ARCH_HAS_ANDN`'s.

130/130 on GCC Release+ASan, GCC ASan, MSVC Release and MSVC Debug.
