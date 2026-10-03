#include "mldsarounding.hpp"

namespace certpp {
namespace crypto {

    /* FIPS 204 2.3's mod-plus-minus, for an even modulus. */
    int32_t MlDsaRounding::modPm(int32_t value, int32_t modulus) {
        int32_t r = value % modulus;

        if (r < 0) {
            r += modulus;
        }

        // Even modulus, so the representative range is (-m/2, m/2] and m/2 stays positive --
        // strictly greater, not >=. Getting this boundary wrong shifts one coefficient value in
        // every 2*gamma2 into the wrong high bucket, which no round-trip test would notice.
        if (r > modulus / 2) {
            r -= modulus;
        }

        return r;
    }

    /* Power2Round (FIPS 204 Algorithm 35). */
    void MlDsaRounding::power2Round(int32_t r, int32_t& r1, int32_t& r0) {
        int32_t rp = r % MlDsaRing::Q;
        if (rp < 0) {
            rp += MlDsaRing::Q;
        }

        r0 = modPm(rp, int32_t(1) << D);

        // rp - r0 is a multiple of 2^d by construction, so this shift is exact rather than a
        // truncation -- and the identity r == r1*2^d + r0 holds on the nose.
        r1 = (rp - r0) >> D;
    }

    /* Decompose (FIPS 204 Algorithm 36). */
    void MlDsaRounding::decompose(int32_t r, int32_t gamma2, int32_t& r1, int32_t& r0) {
        int32_t rp = r % MlDsaRing::Q;
        if (rp < 0) {
            rp += MlDsaRing::Q;
        }

        r0 = modPm(rp, 2 * gamma2);

        // --> The carve-out, written exactly as the standard states it. This is NOT equivalent to
        // `rp == Q - 1`: the condition holds across the whole top band of width gamma2 (95232
        // values at gamma2 = (q-1)/88, 261888 at (q-1)/32), and the "obvious" simplification to a
        // single point would put every other value in that band one bucket too high. Without the
        // branch, r1 would come out as (q-1)/(2*gamma2), one past the top of its range.
        if (rp - r0 == MlDsaRing::Q - 1) {
            r1 = 0;
            r0 -= 1;
        }
        else {
            r1 = (rp - r0) / (2 * gamma2);
        }
    }

    /* HighBits (FIPS 204 Algorithm 37). */
    int32_t MlDsaRounding::highBits(int32_t r, int32_t gamma2) {
        int32_t r1 = 0;
        int32_t r0 = 0;
        decompose(r, gamma2, r1, r0);
        return r1;
    }

    /* LowBits (FIPS 204 Algorithm 38). */
    int32_t MlDsaRounding::lowBits(int32_t r, int32_t gamma2) {
        int32_t r1 = 0;
        int32_t r0 = 0;
        decompose(r, gamma2, r1, r0);
        return r0;
    }

    /* MakeHint (FIPS 204 Algorithm 39). */
    uint8_t MlDsaRounding::makeHint(int32_t z, int32_t r, int32_t gamma2) {
        // r + z is taken mod q before comparing: z is a centered perturbation, so the sum can be
        // negative, and highBits() would otherwise be asked about a value outside [0, q).
        int32_t sum = (r + z) % MlDsaRing::Q;
        if (sum < 0) {
            sum += MlDsaRing::Q;
        }

        return highBits(r, gamma2) != highBits(sum, gamma2) ? uint8_t(1) : uint8_t(0);
    }

    /* UseHint (FIPS 204 Algorithm 40). */
    int32_t MlDsaRounding::useHint(uint8_t hint, int32_t r, int32_t gamma2) {
        const int32_t m = highBitsRange(gamma2);

        int32_t r1 = 0;
        int32_t r0 = 0;
        decompose(r, gamma2, r1, r0);

        if (hint == 0) {
            return r1;
        }

        // --> The direction is decided by the *sign of r0*, which is why decompose() must return
        // a centered low part rather than a non-negative one. Note r0 == 0 counts as "not
        // positive" and steps down: the standard's condition is r0 > 0 for up and r0 <= 0 for
        // down, and splitting the tie the other way breaks the inversion for exactly the
        // coefficients that sit on a bucket boundary.
        if (r0 > 0) {
            return (r1 + 1) % m;
        }

        // r1 is in [0, m), so r1 - 1 reaches -1 at most; the + m keeps the result non-negative
        // without a second modulo.
        return (r1 - 1 + m) % m;
    }

    /* Per-coefficient power2Round over a polynomial. */
    void MlDsaRounding::power2Round(const Poly& poly, Poly& high, Poly& low) {
        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            // Read first, so high or low may alias poly.
            const int32_t value = poly.coeffs[i];

            int32_t r1 = 0;
            int32_t r0 = 0;
            power2Round(value, r1, r0);

            high.coeffs[i] = r1;
            low.coeffs[i] = r0;
        }
    }

    /* Per-coefficient decompose over a polynomial. */
    void MlDsaRounding::decompose(const Poly& poly, int32_t gamma2, Poly& high, Poly& low) {
        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            const int32_t value = poly.coeffs[i];

            int32_t r1 = 0;
            int32_t r0 = 0;
            decompose(value, gamma2, r1, r0);

            high.coeffs[i] = r1;
            low.coeffs[i] = r0;
        }
    }

    /* (q-1)/(2*gamma2): 44 for ML-DSA-44, 16 for ML-DSA-65/87. */
    int32_t MlDsaRounding::highBitsRange(int32_t gamma2) {
        return (MlDsaRing::Q - 1) / (2 * gamma2);
    }

} // namespace crypto
} // namespace certpp
