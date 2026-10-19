#ifndef __SRC_UTILS_MONTGOMERYPARALLEL_HPP__
#define __SRC_UTILS_MONTGOMERYPARALLEL_HPP__

#include <certpp/utils/montgomery.hpp>

namespace certpp {

    /* Internal paired exponentiation used by RSA CRT to expose two independent carry chains to
     * the compiler. Unsupported widths return false so the caller can retain the ordinary path. */
    struct MontgomeryParallel {
        static constexpr size_t PREPARED_DIGITS = 20;

        struct Prepared {
            alignas(64) uint64_t firstModulus[PREPARED_DIGITS] = {};
            alignas(64) uint64_t secondModulus[PREPARED_DIGITS] = {};
            alignas(64) uint64_t firstRr[PREPARED_DIGITS] = {};
            alignas(64) uint64_t secondRr[PREPARED_DIGITS] = {};
            alignas(64) uint64_t firstOne[PREPARED_DIGITS] = {};
            alignas(64) uint64_t secondOne[PREPARED_DIGITS] = {};
            bool valid = false;
        };

        static void prepare(
            const CMontgomery& firstMontgomery,
            const CMontgomery& secondMontgomery,
            Prepared& prepared
        );

        static bool modExp(
            const CMontgomery& firstMontgomery,
            const CBigNum& firstBase,
            const CBigNum& firstExponent,
            CBigNum& firstResult,
            const CMontgomery& secondMontgomery,
            const CBigNum& secondBase,
            const CBigNum& secondExponent,
            CBigNum& secondResult,
            const Prepared* prepared = nullptr
        );
    };

} // namespace certpp

#endif
