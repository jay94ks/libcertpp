#ifndef __SRC_CRYPTO_FASTPRIMEFIELD_HPP__
#define __SRC_CRYPTO_FASTPRIMEFIELD_HPP__

#include <certpp/crypto/eccurve.hpp>

namespace certpp {
namespace crypto {

    struct FastPrimeVerifyTable {
        static constexpr size_t WNAF_ENTRIES = 64;
        static constexpr size_t P256_COMB_WINDOW_BITS = 4;
        static constexpr size_t P256_COMB_ROWS = 256 / P256_COMB_WINDOW_BITS;
        static constexpr size_t P256_COMB_ENTRIES =
            (size_t(1) << P256_COMB_WINDOW_BITS) - 1;

        TArray<uint64_t> coordinates;
        size_t limbCount = 0;
        bool p256Comb = false;
        const uint64_t* sharedCoordinates = nullptr;
        size_t sharedCoordinateCount = 0;

        void clear() {
            coordinates.resize(0);
            limbCount = 0;
            p256Comb = false;
            sharedCoordinates = nullptr;
            sharedCoordinateCount = 0;
        }

        bool resizeWnaf(size_t count) {
            clear();
            if (count == 0 || !coordinates.resize(WNAF_ENTRIES * 2 * count)) {
                return false;
            }
            limbCount = count;
            return true;
        }

        bool resizeP256Comb(size_t count) {
            clear();
            if (count == 0 || !coordinates.resize(
                    P256_COMB_ROWS * P256_COMB_ENTRIES * 2 * count)) {
                return false;
            }
            limbCount = count;
            p256Comb = true;
            return true;
        }

        void reference(const FastPrimeVerifyTable& source) {
            clear();
            limbCount = source.limbCount;
            p256Comb = source.p256Comb;
            sharedCoordinates = source.sharedCoordinates
                ? source.sharedCoordinates : source.coordinates.begin();
            sharedCoordinateCount = source.sharedCoordinates
                ? source.sharedCoordinateCount : source.coordinates.size();
        }

        bool validFor(size_t count) const {
            const size_t pointCount = p256Comb
                ? P256_COMB_ROWS * P256_COMB_ENTRIES : WNAF_ENTRIES;
            const size_t coordinateCount = sharedCoordinates
                ? sharedCoordinateCount : coordinates.size();
            return limbCount == count && coordinateCount == pointCount * 2 * count;
        }

        uint64_t* x(size_t index) {
            return coordinates.begin() + index * 2 * limbCount;
        }

        const uint64_t* x(size_t index) const {
            const uint64_t* data = sharedCoordinates
                ? sharedCoordinates : coordinates.begin();
            return data + index * 2 * limbCount;
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

    /* Builds a reusable affine table for public verification scalars. Standard P-256 uses a
     * position-dependent four-bit comb; other prime curves retain sixty-four odd multiples for a
     * width-eight wNAF. The native path batch-normalizes with one inversion and retains Montgomery
     * limbs so verification does not reconvert every coordinate for every signature. */
    bool PreparePrimeVerifyTable(
        const CEcCurve& curve, const SEcPoint& point, FastPrimeVerifyTable& out);

    /* Uses two tables prepared by PreparePrimeVerifyTable() for a public two-scalar product. Returns
     * false when the fixed-width engine is unavailable or either table is malformed. */
    bool FastPrimeLinearCombinationPrepared(
        const CEcCurve& curve,
        const CBigNum& firstScalar, const FastPrimeVerifyTable& firstTable,
        const CBigNum& secondScalar, const FastPrimeVerifyTable& secondTable,
        SEcPoint& out);

} // namespace crypto
} // namespace certpp

#endif
