#ifndef __SRC_CRYPTO_FASTPRIMEFIELD_HPP__
#define __SRC_CRYPTO_FASTPRIMEFIELD_HPP__

#include <certpp/crypto/eccurve.hpp>

namespace certpp {
namespace crypto {

    /* Inverts a non-zero residue modulo a known prime. The accelerated implementation shares
     * eccurve.cpp's fixed-width Montgomery engine; unsupported targets use CBigNum's generic
     * extended-Euclidean implementation. This is an internal primitive: callers must establish
     * that prime really is prime before using Fermat's exponent prime-2. */
    bool FastPrimeInverse(
        const CBigNum& value, const CBigNum& prime, CBigNum& out);

    /* Builds the sixteen affine odd multiples used by the width-six public verification window.
     * The native path batch-normalizes them with one inversion. */
    bool PreparePrimeWnafTable(
        const CEcCurve& curve, const SEcPoint& point, TArray<SEcPoint>& out);

    /* Uses two tables prepared by PreparePrimeWnafTable() for a public two-scalar product. Returns
     * false when the fixed-width engine is unavailable or either table is malformed. */
    bool FastPrimeLinearCombinationPrepared(
        const CEcCurve& curve,
        const CBigNum& firstScalar, const TArray<SEcPoint>& firstTable,
        const CBigNum& secondScalar, const TArray<SEcPoint>& secondTable,
        SEcPoint& out);

} // namespace crypto
} // namespace certpp

#endif
