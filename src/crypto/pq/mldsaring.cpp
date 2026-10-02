#include "mldsaring.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    /* Reverses the low 8 bits of index. */
    size_t MlDsaRing::bitRev8(size_t index) {
        size_t out = 0;

        for (size_t bit = 0; bit < 8; ++bit) {
            out = (out << 1) | ((index >> bit) & 1u);
        }

        return out;
    }

    /* Returns the NTT layer twiddles, zetas[k] = ZETA^BitRev8(k) mod Q. */
    const int32_t* MlDsaRing::zetas() {
        // --> Computed from ZETA's defining property rather than pasted in as 255 magic numbers.
        // FIPS 204 Appendix B does print the whole table, and the test checks against it, but a
        // transcribed table is exactly the kind of thing that still round-trips through the
        // inverse transform while producing a non-standard representation -- so there is
        // deliberately nothing here to mistype. Function-local static, so it is built on first
        // use regardless of translation-unit initialization order.
        static const struct Table {
            int32_t values[N];

            Table() {
                for (size_t k = 0; k < N; ++k) {
                    // --> int64_t, not int32_t as MlKemRing's equivalent uses: ZETA * acc reaches
                    // 1753 * 8380416, about 1.5e10, which overflows int32_t. In ML-KEM's ring the
                    // same product fits comfortably, and carrying that assumption across is a
                    // wraparound bug rather than a style difference.
                    int64_t acc = 1;
                    const size_t exponent = bitRev8(k);

                    for (size_t step = 0; step < exponent; ++step) {
                        acc = (acc * ZETA) % Q;
                    }

                    values[k] = int32_t(acc);
                }
            }
        } table;

        return table.values;
    }

    /* Reduces value into [0, Q). */
    int32_t MlDsaRing::reduce(int64_t value) {
        int64_t r = value % Q;

        if (r < 0) {
            r += Q;
        }

        return int32_t(r);
    }

    /* Reduces value to its centered representative in (-Q/2, Q/2]. */
    int32_t MlDsaRing::centered(int32_t value) {
        // FIPS 204 2.3's mod±: the representative is taken in (-q/2, q/2], so with q odd the
        // split is at (Q - 1) / 2 -- a coefficient equal to that stays positive, and the next one
        // up becomes negative.
        int32_t r = value % Q;

        if (r < 0) {
            r += Q;
        }

        if (r > (Q - 1) / 2) {
            r -= Q;
        }

        return r;
    }

    /* The infinity norm, the largest absolute centered coefficient. */
    int32_t MlDsaRing::infinityNorm(const Poly& poly) {
        int32_t norm = 0;

        for (size_t i = 0; i < N; ++i) {
            int32_t value = centered(poly.coeffs[i]);

            if (value < 0) {
                value = -value;
            }

            if (value > norm) {
                norm = value;
            }
        }

        return norm;
    }

    /* Zeroes every coefficient. */
    void MlDsaRing::setZero(Poly& out) {
        std::memset(out.coeffs, 0, sizeof(out.coeffs));
    }

    /* out = a + b. */
    void MlDsaRing::add(Poly& out, const Poly& a, const Poly& b) {
        for (size_t i = 0; i < N; ++i) {
            out.coeffs[i] = reduce(int64_t(a.coeffs[i]) + int64_t(b.coeffs[i]));
        }
    }

    /* out = a - b. */
    void MlDsaRing::sub(Poly& out, const Poly& a, const Poly& b) {
        for (size_t i = 0; i < N; ++i) {
            out.coeffs[i] = reduce(int64_t(a.coeffs[i]) - int64_t(b.coeffs[i]));
        }
    }

    /* Forward NTT, in place (FIPS 204 Algorithm 41). */
    void MlDsaRing::ntt(Poly& poly) {
        const int32_t* z = zetas();
        int32_t* f = poly.coeffs;

        // --> Cooley-Tukey, and unlike ML-KEM's this runs all the way down to length 1: eight
        // layers, ending with 256 independent evaluation points rather than 128 degree-1 blocks.
        // The twiddle index increments across the whole transform rather than being derived from
        // the layer -- that is what the bit-reversed table is for, and it is the detail that has
        // to match FIPS 204 exactly for the NTT-domain *representation*, not merely the round
        // trip, to agree with other implementations.
        size_t m = 0;

        for (size_t length = 128; length >= 1; length >>= 1) {
            for (size_t start = 0; start < N; start += 2 * length) {
                ++m;
                const int64_t zeta = int64_t(z[m]);

                for (size_t j = start; j < start + length; ++j) {
                    const int64_t t = (zeta * int64_t(f[j + length])) % Q;

                    f[j + length] = reduce(int64_t(f[j]) - t);
                    f[j] = reduce(int64_t(f[j]) + t);
                }
            }
        }
    }

    /* Inverse NTT, in place (FIPS 204 Algorithm 42). */
    void MlDsaRing::inverseNtt(Poly& poly) {
        const int32_t* z = zetas();
        int32_t* f = poly.coeffs;

        // Gentleman-Sande, walking the same twiddle table backwards and negating each entry.
        size_t m = N;

        for (size_t length = 1; length < N; length <<= 1) {
            for (size_t start = 0; start < N; start += 2 * length) {
                --m;
                const int64_t zeta = -int64_t(z[m]);

                for (size_t j = start; j < start + length; ++j) {
                    const int64_t t = int64_t(f[j]);
                    const int64_t u = int64_t(f[j + length]);

                    f[j] = reduce(t + u);
                    f[j + length] = reduce(zeta * (t - u));
                }
            }
        }

        for (size_t i = 0; i < N; ++i) {
            f[i] = reduce(int64_t(f[i]) * int64_t(N_INVERSE));
        }
    }

    /* out = a * b, both in the NTT domain (FIPS 204 Algorithm 45). */
    void MlDsaRing::multiplyNtt(Poly& out, const Poly& a, const Poly& b) {
        // --> Genuinely pointwise, because ZETA's order is 512 and the transform above is
        // complete. ML-KEM's equivalent needs a 2x2 multiply per block in Z_q[X]/(X^2 - gamma_i)
        // and a second twiddle table; neither exists here, and expecting one is the easiest way
        // to misread this ring as the other.
        for (size_t i = 0; i < N; ++i) {
            out.coeffs[i] = reduce(int64_t(a.coeffs[i]) * int64_t(b.coeffs[i]));
        }
    }

    /* out = a * b in R_q, by the definition. */
    void MlDsaRing::multiplySchoolbook(Poly& out, const Poly& a, const Poly& b) {
        int64_t acc[N] = { 0 };

        for (size_t i = 0; i < N; ++i) {
            const int64_t ai = int64_t(a.coeffs[i]);
            if (ai == 0) {
                continue;
            }

            for (size_t j = 0; j < N; ++j) {
                const int64_t bj = int64_t(b.coeffs[j]);
                if (bj == 0) {
                    continue;
                }

                const int64_t product = (ai * bj) % Q;
                const size_t k = i + j;

                // --> X^256 == -1: anything past degree 255 wraps round *negated*. Getting this
                // sign wrong produces a plausible-looking but wrong ring, which is why the tests
                // assert (X^128)^2 == -1 directly rather than inferring it.
                if (k < N) {
                    acc[k] = (acc[k] + product) % Q;
                }
                else {
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
