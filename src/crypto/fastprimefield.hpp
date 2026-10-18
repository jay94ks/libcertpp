#ifndef __SRC_CRYPTO_FASTPRIMEFIELD_HPP__
#define __SRC_CRYPTO_FASTPRIMEFIELD_HPP__

#include <certpp/crypto/eccurve.hpp>

namespace certpp {
namespace crypto {

    struct FastPrimeWnafTable {
        static constexpr size_t TABLE_SIZE = 64;

        TArray<uint64_t> coordinates;
        size_t limbCount = 0;

        void clear() {
            coordinates.resize(0);
            limbCount = 0;
        }

        bool resize(size_t count) {
            clear();
            if (count == 0 || !coordinates.resize(TABLE_SIZE * 2 * count)) {
                return false;
            }
            limbCount = count;
            return true;
        }

        bool validFor(size_t count) const {
            return limbCount == count && coordinates.size() == TABLE_SIZE * 2 * count;
        }

        uint64_t* x(size_t index) {
            return coordinates.begin() + index * 2 * limbCount;
        }

        const uint64_t* x(size_t index) const {
            return coordinates.begin() + index * 2 * limbCount;
        }

        uint64_t* y(size_t index) {
            return x(index) + limbCount;
        }

        const uint64_t* y(size_t index) const {
            return x(index) + limbCount;
        }
    };

    /* Inverts a non-zero residue modulo a known prime. The accelerated implementation shares
     * eccurve.cpp's fixed-width Montgomery engine; unsupported targets use CBigNum's generic
     * extended-Euclidean implementation. This is an internal primitive: callers must establish
     * that prime really is prime before using Fermat's exponent prime-2. */
    bool FastPrimeInverse(
        const CBigNum& value, const CBigNum& prime, CBigNum& out);

    /* Builds the sixty-four affine odd multiples used by the width-eight public verification window.
     * The native path batch-normalizes them with one inversion and retains Montgomery limbs so a
     * reusable verification context does not reconvert every coordinate for every signature. */
    bool PreparePrimeWnafTable(
        const CEcCurve& curve, const SEcPoint& point, FastPrimeWnafTable& out);

    /* Uses two tables prepared by PreparePrimeWnafTable() for a public two-scalar product. Returns
     * false when the fixed-width engine is unavailable or either table is malformed. */
    bool FastPrimeLinearCombinationPrepared(
        const CEcCurve& curve,
        const CBigNum& firstScalar, const FastPrimeWnafTable& firstTable,
        const CBigNum& secondScalar, const FastPrimeWnafTable& secondTable,
        SEcPoint& out);

} // namespace crypto
} // namespace certpp

#endif
