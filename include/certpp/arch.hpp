#ifndef __INCLUDE_CERTPP_ARCH_HPP__
#define __INCLUDE_CERTPP_ARCH_HPP__

/*
 * The one place this directory decodes what architecture it is being built for.
 *
 * It exists because the question "does this target have a native 64x64->128 multiply?" decides
 * which representation Fe25519 can use, and answering it at each use site is how two
 * accelerations end up disagreeing about what the target supports. The ISA is named once, here;
 * the capability is derived from it once; and every user asks the capability rather than the ISA.
 *
 * The distinction that matters is not 32- versus 64-bit, it is whether one instruction produces
 * a full 128-bit product:
 *
 *   - x86-64   MUL r64, or MULX r64 under BMI2. One instruction, 128-bit result.
 *   - AArch64  UMULL/UMULH, or the SMULL/SMULH pair. One instruction, 128-bit result.
 *   - RISC-V64 MULH/MULHU give the high and low halves directly.
 *   - x86 (32) MUL r32 gives 32x32->64. There is no 64x64->128 instruction at all.
 *   - ARM (32) UMULL likewise gives 32x32->64.
 *
 * So a 64-bit target is not automatically capable, and neither is incapability implied by
 * 32 bits. The table is spelled out per architecture rather than inferred from a bit width,
 * because that inference is the mistake.
 *
 * MSVC is called out separately throughout: it has no __int128 on any architecture, x86-64
 * included, so it takes the "assembled from four 32-bit multiplies" route everywhere.
 */

#if defined(_M_X64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_AMD64_)
    #define CERTPP_ARCH_X86_64 1
    #if defined(__SIZEOF_INT128__)
        /* __int128 exists and GCC/Clang lower a 64x64->128 to a single MUL r64. */
        #define CERTPP_ARCH_NATIVE_64x64_TO_128 1
    #endif

#elif defined(_M_IX86) || defined(__i386__) || defined(_X86_)
    /* 32-bit x86. MUL r32 produces 32x32->64; there is no 64x64->128 instruction. */
    #define CERTPP_ARCH_X86 1

#elif defined(_M_ARM64) || defined(__aarch64__)
    #define CERTPP_ARCH_AARCH64 1
    #if defined(__SIZEOF_INT128__)
        /* __int128 exists and lowers to UMULL/UMULH. */
        #define CERTPP_ARCH_NATIVE_64x64_TO_128 1
    #endif

#elif defined(_M_ARM) || defined(__arm__) || defined(__thumb__)
    /* 32-bit ARM. UMULL produces 32x32->64; there is no 64x64->128 instruction. */
    #define CERTPP_ARCH_ARM32 1

#elif defined(__riscv)
    #define CERTPP_ARCH_RISCV 1
    #if (__riscv_xlen == 64) && defined(__SIZEOF_INT128__)
        #define CERTPP_ARCH_NATIVE_64x64_TO_128 1
    #endif

#else
    #define CERTPP_ARCH_UNKNOWN 1
#endif

/*
 * A BMI2 MULX under x86-64.
 *
 * MUL r64 always writes rdx:rax, while MULX permits two freely chosen destinations and leaves the
 * flags untouched. The radix-51 X25519 ladder uses this gate for a function-level BMI2/ADX/AVX2
 * target after a cached runtime feature check. That lets the compiler schedule its independent
 * field accumulators without imposing those instructions on the portable fallback.
 *
 * Gate mirrors bignum.hpp's and gf2m.hpp's exactly: the DISABLE option, and x86-64 only.
 */
#if defined(CERTPP_ARCH_X86_64) && !defined(CERTPP_DISABLE_HWACCEL_SIMD) && \
    (defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER)))
    #define CERTPP_ARCH_HAS_MULX 1
#endif

/*
 * BMI1 ANDN under x86-64: dest = (~src1) & src2, one instruction.
 *
 * SHA-3's chi step uses it for `a ^ (~b1 & b2)`, where the compiler otherwise emits `notq` then
 * `andq`. Measured on f1600: 408 instructions as the pair, 354 with ANDN, and permute() 460.2 ns
 * against 394.6 ns, -14.3%. MD5 also uses ANDN in its explicitly expanded scalar rounds; keeping
 * destructive ROL there measured faster than using BMI2 RORX for the same dependency chain.
 *
 * That the clock moves is the interesting part, and the reason this is written rather than assumed
 * without. The permutation is 25 lanes of live state against fifteen GPRs, so it spills -- 136
 * stack loads and 136 stores -- and an operation bound on that might not care about 25 fewer ALU
 * instructions at all. It does care, by 14%.
 *
 * The gate mirrors MULX's: x86-64 only, since ANDN is an x86 instruction. */
#if defined(CERTPP_ARCH_X86_64) && !defined(CERTPP_DISABLE_HWACCEL_SIMD)
    #define CERTPP_ARCH_HAS_ANDN 1
#endif

/*
 * BMI2's RORX under x86-64: dest = rot(src, imm), reading src unmodified.
 *
 * The same instruction class as ANDN above and measured the same way, but a different shape of win.
 * SHA-512's round function rotates its live word three times per round, and ROR is destructive, so
 * each of those needs its own copy of that word first -- 89 of transform()'s 201 instructions are
 * movq and a third of the round body is those copies. RORX's third operand reads its source
 * unchanged, so the copies stop existing: 38839 -> 34999 instructions per KiB, -9.9%, which reaches
 * the clock as +10.9% on SHA-512 (SHA-256, SHA-1 and MD5 moved -1.3%, -2.7% and -0.3%, noise).
 *
 * The construction is worth recording because the obvious way is wrong. `__attribute__((target("bmi2")))`
 * on the rotate itself makes GCC refuse to inline it into a caller with no such attribute, and at
 * six rotates a round for eighty rounds that is 480 calls a block -- the same trap as Keccak's ANDN,
 * solved the same way: the compression function is a template on which rotate to use, the attribute
 * sits on the BMI2 instantiation, and the CPUID check happens once per block. */
#if defined(CERTPP_ARCH_X86_64) && !defined(CERTPP_DISABLE_HWACCEL_SIMD)
    #define CERTPP_ARCH_HAS_BMI2_ROTR 1
#endif

/*
 * AVX512-IFMA under x86-64: vpmadd52luq/vpmadd52huq, 52-bit multiply-accumulate eight lanes wide.
 *
 * Used by Poly1305's wide block aggregation. Eight independent lanes form the block products;
 * long messages combine four groups before one horizontal reduction and scalar accumulator
 * update. The implementation extends its precomputed powers from r^16 to r^32 only when that
 * thirty-two-block path is reached.
 *
 * A separate gate from ANDN's even though both are x86-64 feature flags, because AVX512-IFMA is
 * rare and entirely independent: a CPU can have BMI1 without it -- most do -- and a CPU with
 * AVX512-IFMA effectively always has BMI1. One gate covering both would let the Poly1305 path on
 * a machine without IFMA and SIGILL on the first instruction. Each is checked at runtime, by the
 * code that uses it. */
#if defined(CERTPP_ARCH_X86_64) && !defined(CERTPP_DISABLE_HWACCEL_SIMD) && \
    !defined(CERTPP_DISABLE_HWACCEL_AVX512)
    #define CERTPP_ARCH_HAS_IFMA_POLY1305 1
#endif

/*
 * AVX-512F under x86-64: the foundation of the AVX-512 instruction set.
 * Used by ChaCha20's 16-block vector path, MD4/SHA-512 fixed rotates, and Keccak's expanded
 * register-file permutation. Individual implementations test any additional AVX2 or AVX-512VL
 * requirements in their runtime dispatch.
 * Gate mirrors the others: x86-64 only, not disabled, GCC/Clang only.
 */
#if defined(CERTPP_ARCH_X86_64) && !defined(CERTPP_DISABLE_HWACCEL_SIMD) && \
    !defined(CERTPP_DISABLE_HWACCEL_AVX512) && \
    (defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER)))
#  define CERTPP_ARCH_HAS_AVX512F 1
#endif

#endif // __INCLUDE_CERTPP_ARCH_HPP__
