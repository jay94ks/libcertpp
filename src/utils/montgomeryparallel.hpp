#ifndef __SRC_UTILS_MONTGOMERYPARALLEL_HPP__
#define __SRC_UTILS_MONTGOMERYPARALLEL_HPP__

#include <certpp/utils/montgomery.hpp>

namespace certpp {

    /* Internal paired exponentiation used by RSA CRT to expose two independent carry chains to
     * the compiler. Unsupported widths return false so the caller can retain the ordinary path. */
    struct MontgomeryParallel {
        static bool modExp(
            const CMontgomery& firstMontgomery,
            const CBigNum& firstBase,
            const CBigNum& firstExponent,
            CBigNum& firstResult,
            const CMontgomery& secondMontgomery,
            const CBigNum& secondBase,
            const CBigNum& secondExponent,
            CBigNum& secondResult
        );
    };

} // namespace certpp

#endif
