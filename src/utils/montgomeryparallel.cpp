#include "montgomeryparallel.hpp"
#include <cstring>

#if defined(__clang__) && (defined(__x86_64__) || defined(_M_X64))
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

#if defined(__clang__) && defined(__SIZEOF_INT128__) && defined(__ELF__) && \
    defined(__x86_64__) && !defined(CERTPP_DISABLE_HWACCEL_SIMD)
#define CERTPP_HAS_RAW16_ADX 1
extern "C" void certppMontgomeryRaw16Adx(
    const uint64_t* a, const uint64_t* b, const uint64_t* modulus,
    uint64_t n0inv, uint64_t* scratch);

/* The 1024-bit CRT kernel is emitted as one assembly function so CF and OF remain live across all
 * 16 columns. The first pass uses ADCX for multiplication carry and ADOX for accumulator carry;
 * the reduction pass assigns the two chains the same roles. Keeping each chain in a flag avoids
 * the SETcc materialization Clang emits for the equivalent unsigned-__int128 recurrence. */
#define CERTPP_STRINGIFY_INNER(value) #value
#define CERTPP_STRINGIFY(value) CERTPP_STRINGIFY_INNER(value)
#define CERTPP_MONT16_PRODUCT_COLUMN(offset) \
    "mulxq " CERTPP_STRINGIFY(offset) "(%r12),%rax,%rsi\n" \
    "adcxq %rax,%rcx\n" \
    "adoxq " CERTPP_STRINGIFY(offset) "(%r9),%rcx\n" \
    "movq %rcx," CERTPP_STRINGIFY(offset) "(%r9)\n" \
    "movq %rsi,%rcx\n"
#define CERTPP_MONT16_REDUCE_COLUMN(modulusOffset, sourceOffset, outputOffset) \
    "mulxq " CERTPP_STRINGIFY(modulusOffset) "(%r14),%rax,%rsi\n" \
    "adcxq %rax,%rcx\n" \
    "adoxq " CERTPP_STRINGIFY(sourceOffset) "(%r9),%rsi\n" \
    "movq %rcx," CERTPP_STRINGIFY(outputOffset) "(%r9)\n" \
    "movq %rsi,%rcx\n"

__asm__(
    ".text\n"
    ".p2align 5\n"
    ".globl certppMontgomeryRaw16Adx\n"
    ".hidden certppMontgomeryRaw16Adx\n"
    ".type certppMontgomeryRaw16Adx,@function\n"
    "certppMontgomeryRaw16Adx:\n"
    "pushq %rbx\n"
    "pushq %rbp\n"
    "pushq %r12\n"
    "pushq %r13\n"
    "pushq %r14\n"
    "pushq %r15\n"
    "movq %rdi,%r12\n"
    "movq %rsi,%r13\n"
    "movq %rdx,%r14\n"
    "movq %rcx,%r15\n"
    "movq %r8,%r9\n"
    "xorl %ebx,%ebx\n"
    ".p2align 5\n"
    ".Lcertpp_mont16_adx_outer:\n"
    "movq 0(%r13,%rbx,8),%r10\n"
    "movq %r10,%rdx\n"
    "xorl %ebp,%ebp\n"
    "mulxq 0(%r12),%rax,%rcx\n"
    "adoxq 0(%r9),%rax\n"
    "movq %rax,0(%r9)\n"
    CERTPP_MONT16_PRODUCT_COLUMN(8)
    CERTPP_MONT16_PRODUCT_COLUMN(16)
    CERTPP_MONT16_PRODUCT_COLUMN(24)
    CERTPP_MONT16_PRODUCT_COLUMN(32)
    CERTPP_MONT16_PRODUCT_COLUMN(40)
    CERTPP_MONT16_PRODUCT_COLUMN(48)
    CERTPP_MONT16_PRODUCT_COLUMN(56)
    CERTPP_MONT16_PRODUCT_COLUMN(64)
    CERTPP_MONT16_PRODUCT_COLUMN(72)
    CERTPP_MONT16_PRODUCT_COLUMN(80)
    CERTPP_MONT16_PRODUCT_COLUMN(88)
    CERTPP_MONT16_PRODUCT_COLUMN(96)
    CERTPP_MONT16_PRODUCT_COLUMN(104)
    CERTPP_MONT16_PRODUCT_COLUMN(112)
    CERTPP_MONT16_PRODUCT_COLUMN(120)
    "adcxq %rbp,%rcx\n"
    "adoxq 128(%r9),%rcx\n"
    "movq %rcx,128(%r9)\n"
    "movq 0(%r9),%r11\n"
    "imulq %r15,%r11\n"
    "movq %r11,%rdx\n"
    "xorl %ebp,%ebp\n"
    "mulxq 0(%r14),%rax,%rcx\n"
    "movq 0(%r9),%rdi\n"
    "adcxq %rax,%rdi\n"
    "adoxq 8(%r9),%rcx\n"
    CERTPP_MONT16_REDUCE_COLUMN(8, 16, 0)
    CERTPP_MONT16_REDUCE_COLUMN(16, 24, 8)
    CERTPP_MONT16_REDUCE_COLUMN(24, 32, 16)
    CERTPP_MONT16_REDUCE_COLUMN(32, 40, 24)
    CERTPP_MONT16_REDUCE_COLUMN(40, 48, 32)
    CERTPP_MONT16_REDUCE_COLUMN(48, 56, 40)
    CERTPP_MONT16_REDUCE_COLUMN(56, 64, 48)
    CERTPP_MONT16_REDUCE_COLUMN(64, 72, 56)
    CERTPP_MONT16_REDUCE_COLUMN(72, 80, 64)
    CERTPP_MONT16_REDUCE_COLUMN(80, 88, 72)
    CERTPP_MONT16_REDUCE_COLUMN(88, 96, 80)
    CERTPP_MONT16_REDUCE_COLUMN(96, 104, 88)
    CERTPP_MONT16_REDUCE_COLUMN(104, 112, 96)
    CERTPP_MONT16_REDUCE_COLUMN(112, 120, 104)
    CERTPP_MONT16_REDUCE_COLUMN(120, 128, 112)
    "adcxq %rbp,%rcx\n"
    "movq %rbp,%rsi\n"
    "adoxq %rbp,%rsi\n"
    "adcq $0,%rsi\n"
    "movq %rcx,120(%r9)\n"
    "movq %rsi,128(%r9)\n"
    "incq %rbx\n"
    "cmpq $16,%rbx\n"
    "jne .Lcertpp_mont16_adx_outer\n"
    "popq %r15\n"
    "popq %r14\n"
    "popq %r13\n"
    "popq %r12\n"
    "popq %rbp\n"
    "popq %rbx\n"
    "retq\n"
    ".size certppMontgomeryRaw16Adx,.-certppMontgomeryRaw16Adx\n"
);

#undef CERTPP_MONT16_REDUCE_COLUMN
#undef CERTPP_MONT16_PRODUCT_COLUMN
#undef CERTPP_STRINGIFY
#undef CERTPP_STRINGIFY_INNER
#endif

namespace certpp {

#if defined(__clang__) && defined(__SIZEOF_INT128__) && \
    (defined(__x86_64__) || defined(_M_X64))
    namespace {

        template<size_t Count>
        inline void finish(
            uint64_t* value, const uint64_t* modulus, uint64_t* out
        ) {
            auto compare = [modulus](const uint64_t* lhs) {
                for (size_t i = Count; i-- > 0; ) {
                    if (lhs[i] != modulus[i]) {
                        return lhs[i] < modulus[i] ? -1 : 1;
                    }
                }
                return 0;
            };

            while (value[Count] != 0 || compare(value) >= 0) {
                uint64_t borrow = 0;
                for (size_t i = 0; i < Count; ++i) {
                    const uint64_t first = value[i] - modulus[i];
                    const uint64_t borrow1 = value[i] < modulus[i];
                    const uint64_t second = first - borrow;
                    const uint64_t borrow2 = first < borrow;
                    value[i] = second;
                    borrow = borrow1 | borrow2;
                }
                value[Count] -= borrow;
            }

            std::memcpy(out, value, Count * sizeof(uint64_t));
        }

        template<size_t Count>
#if defined(__clang__)
        __attribute__((always_inline))
#endif
        inline void multiplyPairBody(
            const uint64_t* firstA, const uint64_t* firstB,
            const uint64_t* firstModulus, uint64_t firstN0inv,
            uint64_t* firstOut, uint64_t* firstScratch,
            const uint64_t* secondA, const uint64_t* secondB,
            const uint64_t* secondModulus, uint64_t secondN0inv,
            uint64_t* secondOut, uint64_t* secondScratch
        ) {
            using Wide = unsigned __int128;
            std::memset(firstScratch, 0, (Count + 2) * sizeof(uint64_t));
            std::memset(secondScratch, 0, (Count + 2) * sizeof(uint64_t));

            for (size_t i = 0; i < Count; ++i) {
                const uint64_t firstBi = firstB[i];
                const uint64_t secondBi = secondB[i];
                Wide firstProduct = Wide(firstScratch[0]) + Wide(firstA[0]) * firstBi;
                Wide secondProduct = Wide(secondScratch[0]) + Wide(secondA[0]) * secondBi;
                uint64_t firstDigit = uint64_t(firstProduct);
                uint64_t secondDigit = uint64_t(secondProduct);
                Wide firstProductCarry = firstProduct >> 64;
                Wide secondProductCarry = secondProduct >> 64;

                const uint64_t firstMultiplier = firstDigit * firstN0inv;
                const uint64_t secondMultiplier = secondDigit * secondN0inv;
                Wide firstReduction = Wide(firstDigit)
                    + Wide(firstMultiplier) * firstModulus[0];
                Wide secondReduction = Wide(secondDigit)
                    + Wide(secondMultiplier) * secondModulus[0];
                Wide firstReductionCarry = firstReduction >> 64;
                Wide secondReductionCarry = secondReduction >> 64;

#if defined(__clang__)
#pragma clang loop unroll_count(16)
#endif
                for (size_t j = 1; j < Count; ++j) {
                    firstProduct = Wide(firstScratch[j])
                        + Wide(firstA[j]) * firstBi + firstProductCarry;
                    secondProduct = Wide(secondScratch[j])
                        + Wide(secondA[j]) * secondBi + secondProductCarry;
                    firstDigit = uint64_t(firstProduct);
                    secondDigit = uint64_t(secondProduct);
                    firstProductCarry = firstProduct >> 64;
                    secondProductCarry = secondProduct >> 64;

                    firstReduction = Wide(firstDigit)
                        + Wide(firstMultiplier) * firstModulus[j] + firstReductionCarry;
                    secondReduction = Wide(secondDigit)
                        + Wide(secondMultiplier) * secondModulus[j] + secondReductionCarry;
                    firstScratch[j - 1] = uint64_t(firstReduction);
                    secondScratch[j - 1] = uint64_t(secondReduction);
                    firstReductionCarry = firstReduction >> 64;
                    secondReductionCarry = secondReduction >> 64;
                }

                const Wide firstTop = Wide(firstScratch[Count]) + firstProductCarry;
                const Wide secondTop = Wide(secondScratch[Count]) + secondProductCarry;
                const Wide firstReducedTop = Wide(uint64_t(firstTop)) + firstReductionCarry;
                const Wide secondReducedTop = Wide(uint64_t(secondTop)) + secondReductionCarry;
                firstScratch[Count - 1] = uint64_t(firstReducedTop);
                secondScratch[Count - 1] = uint64_t(secondReducedTop);
                firstScratch[Count] = uint64_t(firstTop >> 64)
                    + uint64_t(firstReducedTop >> 64);
                secondScratch[Count] = uint64_t(secondTop >> 64)
                    + uint64_t(secondReducedTop >> 64);
            }

            finish<Count>(firstScratch, firstModulus, firstOut);
            finish<Count>(secondScratch, secondModulus, secondOut);
        }

        using PairMultiply = void(*)(
            const uint64_t*, const uint64_t*, const uint64_t*, uint64_t,
            uint64_t*, uint64_t*,
            const uint64_t*, const uint64_t*, const uint64_t*, uint64_t,
            uint64_t*, uint64_t*);

        void multiplyPair16(
            const uint64_t* firstA, const uint64_t* firstB,
            const uint64_t* firstModulus, uint64_t firstN0inv,
            uint64_t* firstOut, uint64_t* firstScratch,
            const uint64_t* secondA, const uint64_t* secondB,
            const uint64_t* secondModulus, uint64_t secondN0inv,
            uint64_t* secondOut, uint64_t* secondScratch
        ) {
            multiplyPairBody<16>(
                firstA, firstB, firstModulus, firstN0inv, firstOut, firstScratch,
                secondA, secondB, secondModulus, secondN0inv, secondOut, secondScratch);
        }

#if !defined(CERTPP_DISABLE_HWACCEL_SIMD)
        __attribute__((target("bmi2,adx")))
        void multiplyPair16Accelerated(
            const uint64_t* firstA, const uint64_t* firstB,
            const uint64_t* firstModulus, uint64_t firstN0inv,
            uint64_t* firstOut, uint64_t* firstScratch,
            const uint64_t* secondA, const uint64_t* secondB,
            const uint64_t* secondModulus, uint64_t secondN0inv,
            uint64_t* secondOut, uint64_t* secondScratch
        ) {
#if defined(CERTPP_HAS_RAW16_ADX)
            std::memset(firstScratch, 0, 18 * sizeof(uint64_t));
            std::memset(secondScratch, 0, 18 * sizeof(uint64_t));
            certppMontgomeryRaw16Adx(
                firstA, firstB, firstModulus, firstN0inv, firstScratch);
            certppMontgomeryRaw16Adx(
                secondA, secondB, secondModulus, secondN0inv, secondScratch);
            finish<16>(firstScratch, firstModulus, firstOut);
            finish<16>(secondScratch, secondModulus, secondOut);
#else
            multiplyPairBody<16>(
                firstA, firstB, firstModulus, firstN0inv, firstOut, firstScratch,
                secondA, secondB, secondModulus, secondN0inv, secondOut, secondScratch);
#endif
        }

        bool hasAdxBmi2() {
#if defined(_MSC_VER)
            int info[4] = { 0, 0, 0, 0 };
            __cpuid(info, 0);
            if (info[0] < 7) {
                return false;
            }
            __cpuidex(info, 7, 0);
            return ((info[1] & (1 << 8)) != 0) && ((info[1] & (1 << 19)) != 0);
#else
            unsigned int eax, ebx, ecx, edx;
            return __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)
                && ((ebx & (1u << 8)) != 0) && ((ebx & (1u << 19)) != 0);
#endif
        }
#endif

        PairMultiply selectPairMultiply() {
            PairMultiply result = multiplyPair16;
#if !defined(CERTPP_DISABLE_HWACCEL_SIMD)
            if (hasAdxBmi2()) {
                result = multiplyPair16Accelerated;
            }
#endif
            return result;
        }

    } // namespace
#endif

    /* Advances two 1024-bit exponentiations through one fixed-window schedule. */
    bool MontgomeryParallel::modExp(
        const CMontgomery& firstMontgomery,
        const CBigNum& firstBase,
        const CBigNum& firstExponent,
        CBigNum& firstResult,
        const CMontgomery& secondMontgomery,
        const CBigNum& secondBase,
        const CBigNum& secondExponent,
        CBigNum& secondResult
    ) {
#if defined(__clang__) && defined(__SIZEOF_INT128__) && \
    (defined(__x86_64__) || defined(_M_X64))
        constexpr size_t COUNT = 16;
        constexpr size_t WINDOW = 5;
        constexpr size_t TABLE_SIZE = size_t(1) << WINDOW;
        if (!firstMontgomery._valid || !secondMontgomery._valid
            || firstMontgomery._wideCount != COUNT || secondMontgomery._wideCount != COUNT
            || firstExponent.bitLength() > COUNT * 64
            || secondExponent.bitLength() > COUNT * 64) {
            return false;
        }

        const CBigNum firstMont = firstMontgomery.toMont(firstBase);
        const CBigNum secondMont = secondMontgomery.toMont(secondBase);
        uint64_t firstTable[TABLE_SIZE * COUNT];
        uint64_t secondTable[TABLE_SIZE * COUNT];
        uint64_t firstValue[COUNT], secondValue[COUNT];
        uint64_t firstScratch[COUNT + 2], secondScratch[COUNT + 2];
        uint64_t ordinaryOne[COUNT] = { 0 };
        ordinaryOne[0] = 1;

        auto pack = [](const CBigNum& value, uint64_t* out) {
            for (size_t i = 0; i < COUNT; ++i) {
                const size_t lo = 2 * i;
                uint64_t digit = lo < value._limbs.size() ? uint64_t(value._limbs[lo]) : 0;
                if (lo + 1 < value._limbs.size()) {
                    digit |= uint64_t(value._limbs[lo + 1]) << 32;
                }
                out[i] = digit;
            }
        };
        auto unpack = [](const uint64_t* value, CBigNum& out) {
            if (!out._limbs.resize(2 * COUNT)) {
                return false;
            }
            for (size_t i = 0; i < COUNT; ++i) {
                out._limbs[2 * i] = uint32_t(value[i]);
                out._limbs[2 * i + 1] = uint32_t(value[i] >> 32);
            }
            size_t used = out._limbs.size();
            while (used != 0 && out._limbs[used - 1] == 0) {
                --used;
            }
            return out._limbs.resize(used);
        };

        pack(firstMontgomery._one, firstTable);
        pack(secondMontgomery._one, secondTable);
        pack(firstMont, firstTable + COUNT);
        pack(secondMont, secondTable + COUNT);
        const PairMultiply multiply = selectPairMultiply();
        for (size_t i = 2; i < TABLE_SIZE; ++i) {
            multiply(
                firstTable + (i - 1) * COUNT, firstTable + COUNT,
                firstMontgomery._modulus64.begin(), firstMontgomery._n0inv64,
                firstTable + i * COUNT, firstScratch,
                secondTable + (i - 1) * COUNT, secondTable + COUNT,
                secondMontgomery._modulus64.begin(), secondMontgomery._n0inv64,
                secondTable + i * COUNT, secondScratch);
        }

        std::memcpy(firstValue, firstTable, sizeof(firstValue));
        std::memcpy(secondValue, secondTable, sizeof(secondValue));
        size_t cursor = firstExponent.bitLength();
        const size_t secondBits = secondExponent.bitLength();
        if (secondBits > cursor) {
            cursor = secondBits;
        }
        size_t width = cursor % WINDOW;
        if (width == 0 && cursor != 0) {
            width = WINDOW;
        }

        while (cursor != 0) {
            const size_t bottom = cursor - width;
            size_t firstDigit = 0;
            size_t secondDigit = 0;
            for (size_t bit = cursor; bit-- > bottom; ) {
                firstDigit = (firstDigit << 1) | size_t(firstExponent.testBit(bit));
                secondDigit = (secondDigit << 1) | size_t(secondExponent.testBit(bit));
                multiply(
                    firstValue, firstValue,
                    firstMontgomery._modulus64.begin(), firstMontgomery._n0inv64,
                    firstValue, firstScratch,
                    secondValue, secondValue,
                    secondMontgomery._modulus64.begin(), secondMontgomery._n0inv64,
                    secondValue, secondScratch);
            }
            multiply(
                firstValue, firstTable + firstDigit * COUNT,
                firstMontgomery._modulus64.begin(), firstMontgomery._n0inv64,
                firstValue, firstScratch,
                secondValue, secondTable + secondDigit * COUNT,
                secondMontgomery._modulus64.begin(), secondMontgomery._n0inv64,
                secondValue, secondScratch);
            cursor = bottom;
            width = cursor < WINDOW ? cursor : WINDOW;
        }

        multiply(
            firstValue, ordinaryOne,
            firstMontgomery._modulus64.begin(), firstMontgomery._n0inv64,
            firstValue, firstScratch,
            secondValue, ordinaryOne,
            secondMontgomery._modulus64.begin(), secondMontgomery._n0inv64,
            secondValue, secondScratch);
        return unpack(firstValue, firstResult) && unpack(secondValue, secondResult);
#else
        (void)firstMontgomery;
        (void)firstBase;
        (void)firstExponent;
        (void)firstResult;
        (void)secondMontgomery;
        (void)secondBase;
        (void)secondExponent;
        (void)secondResult;
        return false;
#endif
    }

} // namespace certpp
