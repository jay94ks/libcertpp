#include "montgomeryparallel.hpp"
#include <cstring>

#if defined(__clang__) && (defined(__x86_64__) || defined(_M_X64))
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
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
            multiplyPairBody<16>(
                firstA, firstB, firstModulus, firstN0inv, firstOut, firstScratch,
                secondA, secondB, secondModulus, secondN0inv, secondOut, secondScratch);
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
