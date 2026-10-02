#include "mlkemring.hpp"

namespace certpp {
namespace crypto {

    /* Reverses the low 7 bits of index. */
    size_t MlKemRing::bitRev7(size_t index) {
        size_t out = 0;

        for (size_t bit = 0; bit < 7; ++bit) {
            out = (out << 1) | ((index >> bit) & 1u);
        }

        return out;
    }

    /* Returns the NTT layer twiddles, zetas[i] = ZETA^BitRev7(i) mod Q. */
    const int16_t* MlKemRing::zetas() {
        // --> Computed once from ZETA's defining property rather than pasted in as 128 magic
        // numbers. A transcription slip in a twiddle table is exactly the kind of bug that still
        // round-trips through the inverse transform while silently producing a non-standard
        // representation, so there is deliberately nothing here to mistype. Function-local
        // static, so it is built on first use regardless of translation-unit initialization order
        // (the same reasoning CGf2m::knownFieldsTable() documents).
        static const struct Table {
            int16_t values[128];

            Table() {
                for (size_t i = 0; i < 128; ++i) {
                    int32_t acc = 1;
                    size_t exponent = bitRev7(i);

                    for (size_t step = 0; step < exponent; ++step) {
                        acc = (acc * ZETA) % Q;
                    }

                    values[i] = int16_t(acc);
                }
            }
        } table;

        return table.values;
    }

    /* Returns the base-case multiply twiddles, gammas[i] = ZETA^(2*BitRev7(i) + 1) mod Q. */
    const int16_t* MlKemRing::gammas() {
        static const struct Table {
            int16_t values[128];

            Table() {
                const int16_t* z = zetas();

                for (size_t i = 0; i < 128; ++i) {
                    // gamma = ZETA^(2*BitRev7(i) + 1) == zetas[i]^2 * ZETA.
                    int32_t squared = (int32_t(z[i]) * int32_t(z[i])) % Q;
                    values[i] = int16_t((squared * ZETA) % Q);
                }
            }
        } table;

        return table.values;
    }

    /* Reduces value into [0, Q). */
    int16_t MlKemRing::reduce(int32_t value) {
        int32_t r = value % Q;

        if (r < 0) {
            r += Q;
        }

        return int16_t(r);
    }

    /* Zeroes every coefficient. */
    void MlKemRing::setZero(Poly& out) {
        for (size_t i = 0; i < N; ++i) {
            out.coeffs[i] = 0;
        }
    }

    /* out = a + b. */
    void MlKemRing::add(Poly& out, const Poly& a, const Poly& b) {
        for (size_t i = 0; i < N; ++i) {
            out.coeffs[i] = reduce(int32_t(a.coeffs[i]) + int32_t(b.coeffs[i]));
        }
    }

    /* out = a - b. */
    void MlKemRing::sub(Poly& out, const Poly& a, const Poly& b) {
        for (size_t i = 0; i < N; ++i) {
            out.coeffs[i] = reduce(int32_t(a.coeffs[i]) - int32_t(b.coeffs[i]));
        }
    }

    /* Forward NTT, in place (FIPS 203 Algorithm 9). */
    void MlKemRing::ntt(Poly& poly) {
        const int16_t* z = zetas();
        int16_t* f = poly.coeffs;

        // --> Cooley-Tukey, 7 layers, halving the butterfly span each time. The twiddle index k
        // simply increments across the whole transform rather than being derived from the layer:
        // that is what the bit-reversed zetas table is for, and it is the detail that has to match
        // FIPS 203 exactly for the NTT-domain *representation* (not just the round trip) to agree
        // with every other implementation.
        size_t k = 1;

        for (size_t length = 128; length >= 2; length >>= 1) {
            for (size_t start = 0; start < N; start += 2 * length) {
                const int32_t zeta = int32_t(z[k]);
                ++k;

                for (size_t j = start; j < start + length; ++j) {
                    const int32_t t = (zeta * int32_t(f[j + length])) % Q;

                    f[j + length] = reduce(int32_t(f[j]) - t);
                    f[j] = reduce(int32_t(f[j]) + t);
                }
            }
        }
    }

    /* Inverse NTT, in place (FIPS 203 Algorithm 10). */
    void MlKemRing::inverseNtt(Poly& poly) {
        const int16_t* z = zetas();
        int16_t* f = poly.coeffs;

        // Gentleman-Sande, walking the same twiddle table backwards.
        size_t k = 127;

        for (size_t length = 2; length <= 128; length <<= 1) {
            for (size_t start = 0; start < N; start += 2 * length) {
                const int32_t zeta = int32_t(z[k]);
                --k;

                for (size_t j = start; j < start + length; ++j) {
                    const int32_t t = int32_t(f[j]);

                    f[j] = reduce(t + int32_t(f[j + length]));
                    f[j + length] = reduce(zeta * (int32_t(f[j + length]) - t));
                }
            }
        }

        // --> 128^-1 mod 3329 == 3303. Stated as the inverse rather than as the literal so the
        // relationship is checkable by eye; the test asserts 128 * 3303 == 1 (mod Q).
        constexpr int32_t INV_128 = 3303;

        for (size_t i = 0; i < N; ++i) {
            f[i] = reduce(int32_t(f[i]) * INV_128);
        }
    }

    /* out = a * b, both in the NTT domain (FIPS 203 Algorithms 11/12). */
    void MlKemRing::multiplyNtt(Poly& out, const Poly& a, const Poly& b) {
        const int16_t* g = gammas();

        // --> The NTT here is the *incomplete* one FIPS 203 specifies: 7 layers rather than 8,
        // leaving 128 degree-1 polynomials instead of 256 scalars. So this is not a pointwise
        // product -- each block is a 2x2 multiply in Z_q[X]/(X^2 - gamma_i), which is why the
        // gammas table exists at all. Written to read from a/b before writing out, so out may
        // alias either.
        for (size_t i = 0; i < N / 2; ++i) {
            const int32_t a0 = int32_t(a.coeffs[2 * i]);
            const int32_t a1 = int32_t(a.coeffs[2 * i + 1]);
            const int32_t b0 = int32_t(b.coeffs[2 * i]);
            const int32_t b1 = int32_t(b.coeffs[2 * i + 1]);
            const int32_t gamma = int32_t(g[i]);

            const int32_t c0 = (a0 * b0 + ((a1 * b1) % Q) * gamma) % Q;
            const int32_t c1 = (a0 * b1 + a1 * b0) % Q;

            out.coeffs[2 * i] = reduce(c0);
            out.coeffs[2 * i + 1] = reduce(c1);
        }
    }

    /* out = a * b in R_q, by the definition. */
    void MlKemRing::multiplySchoolbook(Poly& out, const Poly& a, const Poly& b) {
        int32_t acc[N] = { 0 };

        for (size_t i = 0; i < N; ++i) {
            const int32_t ai = int32_t(a.coeffs[i]);
            if (ai == 0) {
                continue;
            }

            for (size_t j = 0; j < N; ++j) {
                const int32_t bj = int32_t(b.coeffs[j]);
                if (bj == 0) {
                    continue;
                }

                const int32_t product = (ai * bj) % Q;
                const size_t k = i + j;

                // --> X^256 == -1: anything past degree 255 wraps round *negated*. Getting this
                // sign wrong is the classic way to produce a plausible-looking but wrong ring.
                if (k < N) {
                    acc[k] = (acc[k] + product) % Q;
                } else {
                    acc[k - N] = (acc[k - N] - product) % Q;
                }
            }
        }

        for (size_t i = 0; i < N; ++i) {
            out.coeffs[i] = reduce(acc[i]);
        }
    }

} // namespace crypto
} // namespace certpp
