#ifndef __SRC_CRYPTO_ASYMS_MLDSAPARAMS_HPP__
#define __SRC_CRYPTO_ASYMS_MLDSAPARAMS_HPP__

#include <certpp/common.hpp>
#include "mldsaring.hpp"

namespace certpp {
namespace crypto {

    /**
     * One of ML-DSA's three parameter sets (FIPS 204 Table 1), with every size it implies.
     * Private to the ML-DSA implementation, so no type prefix.
     *
     * Only the tabulated parameters are stored; every length is derived from them, and
     * `tests/crypto/asyms/mldsaparams.cpp` asserts the derived figures against FIPS 204 Table 2
     * at compile time. That is the same discipline `SMlKemParams` follows, for the same reason: a
     * mistyped key or signature length stays internally consistent -- an implementation using
     * the wrong `sk` length throughout still round-trips with itself -- and is caught only by an
     * external vector or by checking against the published table.
     *
     * Two values in the table do not behave the way a reader expects, and both are worth knowing
     * before reading any code that uses them:
     *
     * - **eta is not monotone in security level.** ML-DSA-44 uses 2, ML-DSA-65 uses 4, and
     *   ML-DSA-87 goes back to 2. Assuming it rises with the parameter set gives ML-DSA-87 the
     *   wrong private-key range and the wrong `sk` length.
     * - **gamma1 is shared between two sets.** ML-DSA-44 uses 2^17 while both ML-DSA-65 and
     *   ML-DSA-87 use 2^19, so gamma1 cannot be used to tell the latter two apart.
     *
     * beta is tau * eta, stored rather than derived only because FIPS 204 tabulates it; the test
     * checks the product.
     */
    struct MlDsaParams {
        size_t tau;        /**< Number of +/-1 coefficients in the challenge c. */
        size_t lambda;     /**< Collision strength of c-tilde, in bits; c-tilde is lambda/4 bytes. */
        uint32_t gamma1;   /**< Coefficient range of the masking vector y; a power of two. */
        int32_t gamma2;    /**< Low-order rounding range; (q-1)/88 or (q-1)/32. */
        size_t k;          /**< Rows of A, and the length of s2/t0/t1/w1/h. */
        size_t l;          /**< Columns of A, and the length of s1/y/z. */
        size_t eta;        /**< Private-key coefficient range; 2 or 4, and not monotone. */
        size_t beta;       /**< tau * eta, the signing loop's rejection bound. */
        size_t omega;      /**< Maximum number of set coefficients across the whole hint. */

        /**
         * The number of bits a t1 coefficient occupies: bitlen(q-1) - d, which is 10 for every
         * parameter set. SimpleBitPack relies on b + 1 being a power of two here, which is what
         * makes the public key's decode range-safe.
         * @return 10.
         */
        static constexpr size_t t1BitWidth() { return 23 - 13; }

        /**
         * c-tilde's length: lambda/4 bytes (32, 48 or 64).
         * @return The size in bytes.
         */
        constexpr size_t commitmentBytes() const { return lambda / 4; }

        /**
         * Public key size: rho (32 bytes) plus k packed t1 polynomials.
         * @return The size in bytes (1312, 1952 or 2592).
         */
        constexpr size_t publicKeyBytes() const { return 32 + 32 * k * t1BitWidth(); }

        /**
         * Private key size: rho || K || tr (128 bytes together), then s1, s2 and t0 packed.
         * @return The size in bytes (2560, 4032 or 4896).
         */
        constexpr size_t privateKeyBytes() const {
            return 128 + 32 * etaBitWidth() * (k + l) + 32 * 13 * k;
        }

        /**
         * Signature size: c-tilde, then z packed, then the hint.
         * @return The size in bytes (2420, 3309 or 4627).
         */
        constexpr size_t signatureBytes() const {
            return commitmentBytes() + l * 32 * (1 + gamma1BitWidth()) + omega + k;
        }

        /**
         * The bit width BitPack uses for an s1/s2 coefficient: bitlen(2*eta), so 3 at eta = 2
         * and 4 at eta = 4.
         *
         * Note that 2*eta + 1 is 5 or 9 -- neither a power of two -- which is exactly why
         * decoding s1/s2 cannot guarantee the range and `skDecode` has to check it. See
         * MlDsaCodec's doc comment.
         * @return 3 or 4.
         */
        constexpr size_t etaBitWidth() const { return eta == 2 ? 3 : 4; }

        /**
         * bitlen(gamma1 - 1): 17 at gamma1 = 2^17, 19 at 2^19. BitPack uses one more bit than
         * this, since the range is [-gamma1 + 1, gamma1].
         * @return 17 or 19.
         */
        constexpr size_t gamma1BitWidth() const { return gamma1 == (1u << 17) ? 17 : 19; }

        /**
         * The number of distinct high-bit values, (q-1)/(2*gamma2): 44 or 16. This is what w1's
         * coefficients range over, and the modulus UseHint wraps within.
         * @return 44 or 16.
         */
        constexpr size_t highBitsRange() const {
            return size_t((MlDsaRing::Q - 1) / (2 * gamma2));
        }

        /**
         * ML-DSA-44 (tau=39, lambda=128, gamma1=2^17, (k,l)=(4,4), eta=2, omega=80).
         * @return The parameter set.
         */
        static constexpr MlDsaParams mlDsa44() {
            return MlDsaParams{ 39, 128, 1u << 17, (MlDsaRing::Q - 1) / 88, 4, 4, 2, 78, 80 };
        }

        /**
         * ML-DSA-65 (tau=49, lambda=192, gamma1=2^19, (k,l)=(6,5), eta=4, omega=55).
         * @return The parameter set.
         */
        static constexpr MlDsaParams mlDsa65() {
            return MlDsaParams{ 49, 192, 1u << 19, (MlDsaRing::Q - 1) / 32, 6, 5, 4, 196, 55 };
        }

        /**
         * ML-DSA-87 (tau=60, lambda=256, gamma1=2^19, (k,l)=(8,7), eta=2, omega=75).
         *
         * Note eta = 2, not 4 -- see this struct's doc comment.
         * @return The parameter set.
         */
        static constexpr MlDsaParams mlDsa87() {
            return MlDsaParams{ 60, 256, 1u << 19, (MlDsaRing::Q - 1) / 32, 8, 7, 2, 120, 75 };
        }

        /**
         * Field-by-field equality.
         * @param other The parameter set to compare against.
         * @return true if every parameter matches.
         */
        constexpr bool equals(const MlDsaParams& other) const {
            return tau == other.tau && lambda == other.lambda && gamma1 == other.gamma1
                && gamma2 == other.gamma2 && k == other.k && l == other.l
                && eta == other.eta && beta == other.beta && omega == other.omega;
        }

        /**
         * Reports whether this is one of FIPS 204's three parameter sets.
         *
         * Every entry point that takes an MlDsaParams checks this first, for the same reason
         * CMlKem does: the implementation sizes fixed-capacity buffers from MAX_K/MAX_L, so a
         * hand-built set with a larger k would overflow them, and the standard defines no fourth
         * set to accommodate.
         * @return true if this equals mlDsa44(), mlDsa65() or mlDsa87().
         */
        constexpr bool isValid() const {
            return equals(mlDsa44()) || equals(mlDsa65()) || equals(mlDsa87());
        }

        /** The largest k any parameter set uses (ML-DSA-87). */
        static constexpr size_t MAX_K = 8;

        /** The largest l any parameter set uses (ML-DSA-87). */
        static constexpr size_t MAX_L = 7;

        /**
         * The largest signature any parameter set produces, for sizing fixed-capacity buffers.
         *
         * Derived from ML-DSA-87 rather than written out. 4627 bytes -- note this is the final
         * standard's figure; 4595 was the initial public draft's, and still circulates.
         * @return 4627 bytes.
         */
        static constexpr size_t maxSignatureBytes() { return mlDsa87().signatureBytes(); }

        /**
         * The largest private key any parameter set produces.
         * @return 4896 bytes.
         */
        static constexpr size_t maxPrivateKeyBytes() { return mlDsa87().privateKeyBytes(); }

        /**
         * The largest public key any parameter set produces.
         * @return 2592 bytes.
         */
        static constexpr size_t maxPublicKeyBytes() { return mlDsa87().publicKeyBytes(); }
    };

} // namespace crypto
} // namespace certpp

#endif
