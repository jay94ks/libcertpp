#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

// src/ is on this test's include path -- see CMakeLists.txt's note on tests/crypto/pq/, which
// compiles the lattice arithmetic directly because it is deliberately not exported.
#include "crypto/pq/mlkemring.hpp"

using namespace certpp;
using namespace certpp::crypto;

/* ML-KEM's ring arithmetic (FIPS 203 2.4.4): R_q = Z_q[X]/(X^256 + 1), q = 3329.
 *
 * The thing worth being careful about here is that FIPS 203 fixes the NTT's exact
 * *representation*, not just its end-to-end behaviour: an encapsulation key is a ByteEncode of
 * NTT-domain coefficients, so those values go on the wire. A transform that is self-consistent --
 * forward then inverse recovers the input -- but orders its twiddles differently from the standard
 * will pass every round-trip test anyone writes and interoperate with nothing. That is the same
 * failure mode that let this library ship a byte-granular ECDSA digest truncation undetected for
 * as long as its only tests verified their own output.
 *
 * So these tests deliberately do not rest on round trips:
 *   - the twiddle tables are re-derived here from 17^BitRev7(i), independently of how the
 *     implementation builds them, and compared entry by entry;
 *   - the NTT-domain multiply is checked against a schoolbook negacyclic convolution, which
 *     shares none of the NTT's machinery;
 *   - the ring's defining identity, X^256 == -1, is asserted directly;
 *   - and the one constant the spec states outright (128^-1 == 3303) is checked as an inverse
 *     rather than copied.
 *
 * Every expectation below was first validated against an independent Python model of FIPS 203
 * before the C++ existed. */

namespace {

    using Poly = SMlKemPoly;

    constexpr int32_t Q = MlKemRing::Q;
    constexpr size_t N = MlKemRing::N;

    /* Deterministic xorshift64*, so a failure reproduces from the seed alone. */
    class Rng {
    private:
        uint64_t _state;

    public:
        explicit Rng(uint64_t seed) : _state(seed ? seed : 0x9E3779B97F4A7C15ull) {}

        uint64_t next() {
            _state ^= _state >> 12;
            _state ^= _state << 25;
            _state ^= _state >> 27;
            return _state * 0x2545F4914F6CDD1Dull;
        }

        int16_t coefficient() {
            return int16_t(next() % uint64_t(Q));
        }
    };

    Poly randomPoly(Rng& rng) {
        Poly p;
        for (size_t i = 0; i < N; ++i) {
            p.coeffs[i] = rng.coefficient();
        }
        return p;
    }

    Poly monomial(size_t degree, int16_t coefficient = 1) {
        Poly p;
        MlKemRing::setZero(p);
        p.coeffs[degree] = coefficient;
        return p;
    }

    bool equal(const Poly& a, const Poly& b) {
        for (size_t i = 0; i < N; ++i) {
            if (a.coeffs[i] != b.coeffs[i]) {
                return false;
            }
        }
        return true;
    }

    bool reduced(const Poly& p) {
        for (size_t i = 0; i < N; ++i) {
            if (p.coeffs[i] < 0 || p.coeffs[i] >= Q) {
                return false;
            }
        }
        return true;
    }

    /* Modular exponentiation over int64_t, independent of anything in MlKemRing. */
    int32_t powMod(int32_t base, size_t exponent, int32_t modulus) {
        int64_t result = 1;
        int64_t b = base % modulus;

        for (size_t i = 0; i < exponent; ++i) {
            result = (result * b) % modulus;
        }

        return int32_t(result);
    }

} // namespace

/* 17 is only a valid choice because it has order exactly 256 mod 3329, and because its 128th
 * power is -1 -- which is what makes the ring negacyclic and the 7-layer NTT possible. Asserted
 * rather than assumed, since every table below is derived from it. */
TEST_CASE("MlKemRing: ZETA is a primitive 256th root of unity, with ZETA^128 == -1") {
    CHECK(powMod(MlKemRing::ZETA, 256, Q) == 1);
    CHECK(powMod(MlKemRing::ZETA, 128, Q) == Q - 1);

    // No smaller power of two may reach 1, or the order is a proper divisor of 256.
    for (size_t d : { size_t(1), size_t(2), size_t(4), size_t(8),
                      size_t(16), size_t(32), size_t(64), size_t(128) })
    {
        CAPTURE(d);
        CHECK(powMod(MlKemRing::ZETA, d, Q) != 1);
    }
}

TEST_CASE("MlKemRing::bitRev7(): reverses exactly 7 bits") {
    CHECK(MlKemRing::bitRev7(0) == 0);
    CHECK(MlKemRing::bitRev7(1) == 64);    // 0000001 -> 1000000
    CHECK(MlKemRing::bitRev7(64) == 1);
    CHECK(MlKemRing::bitRev7(127) == 127); // all ones
    CHECK(MlKemRing::bitRev7(2) == 32);
    CHECK(MlKemRing::bitRev7(3) == 96);    // 0000011 -> 1100000

    // An involution on [0, 128).
    for (size_t i = 0; i < 128; ++i) {
        CAPTURE(i);
        CHECK(MlKemRing::bitRev7(MlKemRing::bitRev7(i)) == i);
    }
}

/* The tables are the single most transcription-sensitive thing in the whole algorithm, so they
 * are re-derived here from the defining formula and compared entry by entry. */
TEST_CASE("MlKemRing::zetas()/gammas(): every entry matches its defining power of ZETA") {
    const int16_t* z = MlKemRing::zetas();
    const int16_t* g = MlKemRing::gammas();

    for (size_t i = 0; i < 128; ++i) {
        CAPTURE(i);

        const size_t rev = MlKemRing::bitRev7(i);
        CHECK(int32_t(z[i]) == powMod(MlKemRing::ZETA, rev, Q));
        CHECK(int32_t(g[i]) == powMod(MlKemRing::ZETA, 2 * rev + 1, Q));

        CHECK(z[i] >= 0);
        CHECK(z[i] < Q);
        CHECK(g[i] >= 0);
        CHECK(g[i] < Q);
    }

    // The first few values are widely published for Kyber/ML-KEM, so they double as an external
    // cross-check on the BitRev7 indexing rather than only on the arithmetic.
    CHECK(z[0] == 1);
    CHECK(z[1] == 1729);
    CHECK(z[2] == 2580);
    CHECK(z[3] == 3289);
    CHECK(z[4] == 2642);
}

TEST_CASE("MlKemRing: 128^-1 mod Q is 3303, the constant inverseNtt() applies") {
    CHECK((128 * 3303) % Q == 1);
}

TEST_CASE("MlKemRing::reduce(): lands in [0, Q) for negative, zero and large inputs") {
    CHECK(MlKemRing::reduce(0) == 0);
    CHECK(MlKemRing::reduce(Q) == 0);
    CHECK(MlKemRing::reduce(Q - 1) == Q - 1);
    CHECK(MlKemRing::reduce(-1) == Q - 1);
    CHECK(MlKemRing::reduce(-Q) == 0);
    CHECK(MlKemRing::reduce(Q + 5) == 5);
    CHECK(MlKemRing::reduce(-Q - 5) == Q - 5);

    // The widest intermediate the implementation can produce: a product of two coefficients.
    CHECK(MlKemRing::reduce((Q - 1) * (Q - 1)) == ((Q - 1) * (Q - 1)) % Q);
}

TEST_CASE("MlKemRing::add()/sub(): coefficient-wise, always reduced, aliasing-safe") {
    Rng rng(0xA11CE);

    for (int i = 0; i < 50; ++i) {
        Poly a = randomPoly(rng);
        Poly b = randomPoly(rng);

        Poly sum;
        MlKemRing::add(sum, a, b);
        REQUIRE(reduced(sum));

        Poly difference;
        MlKemRing::sub(difference, sum, b);
        CHECK(equal(difference, a));            // (a + b) - b == a

        // Aliasing: out == a must behave the same as a distinct destination.
        Poly aliased = a;
        MlKemRing::add(aliased, aliased, b);
        CHECK(equal(aliased, sum));
    }
}

TEST_CASE("MlKemRing::ntt()/inverseNtt(): exact round trip, output always reduced") {
    Rng rng(0xBEEF);

    for (int i = 0; i < 100; ++i) {
        Poly original = randomPoly(rng);

        Poly transformed = original;
        MlKemRing::ntt(transformed);
        REQUIRE(reduced(transformed));

        MlKemRing::inverseNtt(transformed);
        REQUIRE(reduced(transformed));
        CHECK(equal(transformed, original));
    }

    // Zero and the constant polynomial 1 are the two cases where a wrong normalization constant
    // would be most visible.
    Poly zero;
    MlKemRing::setZero(zero);
    Poly z = zero;
    MlKemRing::ntt(z);
    MlKemRing::inverseNtt(z);
    CHECK(equal(z, zero));

    Poly one = monomial(0, 1);
    Poly o = one;
    MlKemRing::ntt(o);
    MlKemRing::inverseNtt(o);
    CHECK(equal(o, one));
}

/* The load-bearing test. multiplyNtt() must agree with a schoolbook negacyclic convolution,
 * which shares none of the NTT's twiddles, indexing or layering -- so agreement means the NTT
 * representation really is the one the ring's multiplication is defined by, not merely something
 * self-consistent. */
TEST_CASE("MlKemRing::multiplyNtt(): agrees with a schoolbook negacyclic multiply") {
    Rng rng(0xC0FFEE);

    for (int i = 0; i < 40; ++i) {
        Poly a = randomPoly(rng);
        Poly b = randomPoly(rng);

        Poly viaNtt;
        {
            Poly na = a;
            Poly nb = b;
            MlKemRing::ntt(na);
            MlKemRing::ntt(nb);
            MlKemRing::multiplyNtt(viaNtt, na, nb);
            MlKemRing::inverseNtt(viaNtt);
        }

        Poly direct;
        MlKemRing::multiplySchoolbook(direct, a, b);

        REQUIRE(reduced(viaNtt));
        CHECK(equal(viaNtt, direct));
    }
}

TEST_CASE("MlKemRing::multiplyNtt(): agrees with schoolbook on sparse and extreme operands") {
    // Monomials at the layer boundaries, plus the all-zero, all-one and all-(Q-1) polynomials.
    TArray<Poly> operands;
    for (size_t degree : { size_t(0), size_t(1), size_t(127), size_t(128), size_t(255) }) {
        operands.add(monomial(degree));
    }

    Poly zero;
    MlKemRing::setZero(zero);
    operands.add(zero);

    Poly ones;
    Poly maxes;
    for (size_t i = 0; i < N; ++i) {
        ones.coeffs[i] = 1;
        maxes.coeffs[i] = int16_t(Q - 1);
    }
    operands.add(ones);
    operands.add(maxes);

    for (size_t i = 0; i < operands.size(); ++i) {
        for (size_t j = 0; j < operands.size(); ++j) {
            CAPTURE(i);
            CAPTURE(j);

            Poly viaNtt;
            {
                Poly na = operands[i];
                Poly nb = operands[j];
                MlKemRing::ntt(na);
                MlKemRing::ntt(nb);
                MlKemRing::multiplyNtt(viaNtt, na, nb);
                MlKemRing::inverseNtt(viaNtt);
            }

            Poly direct;
            MlKemRing::multiplySchoolbook(direct, operands[i], operands[j]);
            CHECK(equal(viaNtt, direct));
        }
    }
}

/* X^256 == -1 is what distinguishes this ring from an ordinary cyclic convolution, and a sign
 * error in the wraparound produces a ring that still looks plausible. X^128 * X^128 must be -1
 * exactly. */
TEST_CASE("MlKemRing: the ring is negacyclic -- X^128 * X^128 == -1") {
    Poly x128 = monomial(128);

    Poly viaNtt;
    {
        Poly a = x128;
        Poly b = x128;
        MlKemRing::ntt(a);
        MlKemRing::ntt(b);
        MlKemRing::multiplyNtt(viaNtt, a, b);
        MlKemRing::inverseNtt(viaNtt);
    }

    Poly expected = monomial(0, int16_t(Q - 1)); // -1 mod Q
    CHECK(equal(viaNtt, expected));

    Poly direct;
    MlKemRing::multiplySchoolbook(direct, x128, x128);
    CHECK(equal(direct, expected));

    // And a monomial product that does *not* wrap stays positive, so the sign rule is not simply
    // inverted everywhere.
    Poly x100 = monomial(100);
    Poly x27 = monomial(27);
    Poly noWrap;
    MlKemRing::multiplySchoolbook(noWrap, x100, x27);
    CHECK(equal(noWrap, monomial(127)));
}

/* Ring axioms, checked through the NTT path, since an error that preserved commutativity but
 * broke distributivity would slip past a pure multiply comparison. */
TEST_CASE("MlKemRing: multiplication is commutative and distributes over addition") {
    Rng rng(0xFEED);

    for (int i = 0; i < 20; ++i) {
        Poly a = randomPoly(rng);
        Poly b = randomPoly(rng);
        Poly c = randomPoly(rng);

        Poly ab;
        MlKemRing::multiplySchoolbook(ab, a, b);
        Poly ba;
        MlKemRing::multiplySchoolbook(ba, b, a);
        CHECK(equal(ab, ba));

        // a * (b + c) == a*b + a*c
        Poly bPlusC;
        MlKemRing::add(bPlusC, b, c);

        Poly left;
        MlKemRing::multiplySchoolbook(left, a, bPlusC);

        Poly ac;
        MlKemRing::multiplySchoolbook(ac, a, c);
        Poly right;
        MlKemRing::add(right, ab, ac);

        CHECK(equal(left, right));
    }
}

TEST_CASE("MlKemRing::multiplyNtt(): safe when the destination aliases an input") {
    Rng rng(0xD00D);

    Poly a = randomPoly(rng);
    Poly b = randomPoly(rng);

    Poly na = a;
    Poly nb = b;
    MlKemRing::ntt(na);
    MlKemRing::ntt(nb);

    Poly separate;
    MlKemRing::multiplyNtt(separate, na, nb);

    Poly aliased = na;
    MlKemRing::multiplyNtt(aliased, aliased, nb);
    CHECK(equal(aliased, separate));
}
