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
 * Worth having because of what it is *not*: MUL r64 always writes rdx:rax and flags rdx as
 * clobbered, so a run of consecutive 64x64->128 products -- which is exactly what a 5x5 field
 * multiply is, twenty-five of them back to back -- has to spill and re-establish rdx around
 * every single one. MULX takes two freely-chosen destinations and clobbers neither, so the
 * compiler can keep the accumulators where it wants them.
 *
 * That argument is a hypothesis, and this library does not ship one: CBigNum's MULX/ADCX path
 * measured as worth nothing at all, because its multiply is long enough that the rdx traffic is
 * lost in the rest. Fe25519::mul is the opposite shape -- 25 products and almost nothing else --
 * so it is worth one measurement rather than either assumption. Whether it is kept is decided by
 * that measurement, not by this comment; see mulBmi251()'s own note.
 *
 * Gate mirrors bignum.hpp's and gf2m.hpp's exactly: the DISABLE option, and x86-64 only.
 */
#if defined(CERTPP_ARCH_X86_64) && !defined(CERTPP_DISABLE_HWACCEL_SIMD) && \
    (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER)
    #define CERTPP_ARCH_HAS_MULX 1
#endif

#endif // __INCLUDE_CERTPP_ARCH_HPP__