// FIPS 204 7.1-7.2's bit packing and hint encoding.
//
// Round trips are the easy half and prove little on their own -- a packer and unpacker that are
// wrong in matching ways round-trip perfectly. So the tests below also pin the byte layout
// directly (bits little-endian within each byte), check the ranges the spec warns are *not*
// guaranteed by decoding, and spend most of their effort on hintBitUnpack's three rejection
// conditions, which are what stand between this and malleable signatures.
//
// Validated in Python against the specification text first, and cross-checked against
// dilithium-py 1.4.0: pack agreed on 2400 polynomials across every (a, b) ML-DSA uses, unpack on
// 1500.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include "crypto/asyms/mldsacodec.hpp"

#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    using Poly = MlDsaCodec::Poly;

    constexpr size_t N = MlDsaRing::N;

    struct Lcg {
        uint64_t state;
        explicit Lcg(uint64_t seed) : state(seed) { }

        uint32_t next() {
            state = state * 6364136223846793005ull + 1442695040888963407ull;
            return uint32_t(state >> 33);
        }

        int32_t inRange(int32_t low, int32_t high) {
            return low + int32_t(uint64_t(next()) % uint64_t(int64_t(high) - low + 1));
        }
    };

    Poly polyOf(Lcg& rng, int32_t low, int32_t high) {
        Poly p;
        for (size_t i = 0; i < N; ++i) {
            p.coeffs[i] = rng.inRange(low, high);
        }
        return p;
    }

    bool equalPoly(const Poly& a, const Poly& b) {
        for (size_t i = 0; i < N; ++i) {
            if (a.coeffs[i] != b.coeffs[i]) {
                return false;
            }
        }
        return true;
    }
}

TEST_CASE("MlDsaCodec: bitLength is the binary width") {
    CHECK(MlDsaCodec::bitLength(0) == 0);
    CHECK(MlDsaCodec::bitLength(1) == 1);
    CHECK(MlDsaCodec::bitLength(2) == 2);
    CHECK(MlDsaCodec::bitLength(3) == 2);
    CHECK(MlDsaCodec::bitLength(4) == 3);
    CHECK(MlDsaCodec::bitLength(15) == 4);
    CHECK(MlDsaCodec::bitLength(16) == 5);
    CHECK(MlDsaCodec::bitLength(43) == 6);
    CHECK(MlDsaCodec::bitLength((1u << 10) - 1) == 10);
    CHECK(MlDsaCodec::bitLength(1u << 19) == 20);

    for (uint32_t v = 1; v < 5000; ++v) {
        size_t expected = 0;
        for (uint32_t t = v; t != 0; t >>= 1) {
            ++expected;
        }
        REQUIRE(MlDsaCodec::bitLength(v) == expected);
    }
}

// The byte layout is wire format, so it is pinned against a hand-computed expectation rather
// than only against the decoder. Bits run little-endian within each byte (FIPS 204 Algorithm
// 12); packing them the other way round still round-trips and interoperates with nothing.
TEST_CASE("MlDsaCodec: simpleBitPack lays bits out little-endian within each byte") {
    Poly p;
    for (size_t i = 0; i < N; ++i) {
        p.coeffs[i] = 0;
    }

    // Four coefficients of 2 bits each fill one byte. With b = 3 (2 bits) and coefficients
    // 1, 2, 3, 0 the first byte is 0b00111001 = 0x39: coefficient 0 in bits 0-1, 1 in bits 2-3,
    // and so on upward.
    p.coeffs[0] = 1;
    p.coeffs[1] = 2;
    p.coeffs[2] = 3;
    p.coeffs[3] = 0;

    std::vector<uint8_t> packed(32 * 2);
    REQUIRE(MlDsaCodec::simpleBitPack(p, 3, SByteSpan(packed.data(), packed.size())));
    CHECK(packed[0] == 0x39);

    // A single 10-bit coefficient straddles a byte boundary, which is where an endianness slip
    // actually shows. 0x3FF in bits 0-9 gives 0xFF then the low two bits of the next byte.
    Poly wide;
    for (size_t i = 0; i < N; ++i) {
        wide.coeffs[i] = 0;
    }
    wide.coeffs[0] = (1 << 10) - 1;

    std::vector<uint8_t> widePacked(32 * 10);
    REQUIRE(MlDsaCodec::simpleBitPack(wide, (1u << 10) - 1,
                                      SByteSpan(widePacked.data(), widePacked.size())));
    CHECK(widePacked[0] == 0xFF);
    CHECK(widePacked[1] == 0x03);
    CHECK(widePacked[2] == 0x00);
}

TEST_CASE("MlDsaCodec: simpleBitPack round-trips every b ML-DSA uses") {
    Lcg rng(0x51B9);

    // t1's 10-bit range, and w1's two bucket counts (43 at gamma2 = (q-1)/88, 15 at (q-1)/32).
    const uint32_t bounds[] = { 1, 3, 15, 43, (1u << 10) - 1 };

    for (uint32_t b : bounds) {
        const size_t width = MlDsaCodec::bitLength(b);
        std::vector<uint8_t> packed(32 * width);

        for (int trial = 0; trial < 50; ++trial) {
            const Poly original = polyOf(rng, 0, int32_t(b));

            REQUIRE(MlDsaCodec::simpleBitPack(original, b,
                                              SByteSpan(packed.data(), packed.size())));

            Poly decoded;
            REQUIRE(MlDsaCodec::simpleBitUnpack(
                SReadOnlyByteSpan(packed.data(), packed.size()), b, decoded));
            REQUIRE(equalPoly(decoded, original));
        }

        // A wrong output size is refused rather than silently truncating.
        std::vector<uint8_t> wrong(32 * width - 1);
        Poly any = polyOf(rng, 0, int32_t(b));
        CHECK_FALSE(MlDsaCodec::simpleBitPack(any, b, SByteSpan(wrong.data(), wrong.size())));

        Poly decoded;
        CHECK_FALSE(MlDsaCodec::simpleBitUnpack(
            SReadOnlyByteSpan(packed.data(), packed.size() - 1), b, decoded));
    }
}

TEST_CASE("MlDsaCodec: bitPack round-trips every (a, b) ML-DSA uses") {
    Lcg rng(0xB17A);

    struct Case { uint32_t a; uint32_t b; };
    const Case cases[] = {
        { 2, 2 },                               // s1/s2 at eta = 2
        { 4, 4 },                               // s1/s2 at eta = 4
        { (1u << 12) - 1, 1u << 12 },           // t0
        { (1u << 17) - 1, 1u << 17 },           // z at gamma1 = 2^17
        { (1u << 19) - 1, 1u << 19 },           // z at gamma1 = 2^19
    };

    for (const Case& c : cases) {
        const size_t width = MlDsaCodec::bitLength(c.a + c.b);
        std::vector<uint8_t> packed(32 * width);

        for (int trial = 0; trial < 30; ++trial) {
            const Poly original = polyOf(rng, -int32_t(c.a), int32_t(c.b));

            REQUIRE(MlDsaCodec::bitPack(original, c.a, c.b,
                                        SByteSpan(packed.data(), packed.size())));

            Poly decoded;
            REQUIRE(MlDsaCodec::bitUnpack(
                SReadOnlyByteSpan(packed.data(), packed.size()), c.a, c.b, decoded));
            REQUIRE(equalPoly(decoded, original));
        }

        // The endpoints specifically -- b maps to field 0 and -a to the largest field, so an
        // off-by-one in the b - w_i mapping shows here before it shows anywhere else.
        Poly edges;
        for (size_t i = 0; i < N; ++i) {
            edges.coeffs[i] = (i % 2) ? int32_t(c.b) : -int32_t(c.a);
        }
        REQUIRE(MlDsaCodec::bitPack(edges, c.a, c.b, SByteSpan(packed.data(), packed.size())));

        Poly decoded;
        REQUIRE(MlDsaCodec::bitUnpack(
            SReadOnlyByteSpan(packed.data(), packed.size()), c.a, c.b, decoded));
        CHECK(equalPoly(decoded, edges));

        // Out-of-range coefficients are refused by the packer.
        Poly tooHigh = edges;
        tooHigh.coeffs[0] = int32_t(c.b) + 1;
        CHECK_FALSE(MlDsaCodec::bitPack(tooHigh, c.a, c.b,
                                        SByteSpan(packed.data(), packed.size())));

        Poly tooLow = edges;
        tooLow.coeffs[0] = -int32_t(c.a) - 1;
        CHECK_FALSE(MlDsaCodec::bitPack(tooLow, c.a, c.b,
                                        SByteSpan(packed.data(), packed.size())));
    }
}

// FIPS 204 warns, right under Algorithm 17, that for some (a, b) a malformed byte string decodes
// to coefficients outside the nominal range. This records exactly which of ML-DSA's uses are
// affected, because the answer decides where a caller must range-check: s1/s2 must, t0/t1/z need
// not, and w1 is never decoded at all.
TEST_CASE("MlDsaCodec: decoding does not imply the range, for the (a, b) where it cannot") {
    // All-ones input, the worst case for every field.
    auto allOnes = [](size_t bytes) { return std::vector<uint8_t>(bytes, 0xFF); };

    // s1/s2 at eta = 2: three bits, so the field reaches 7 and the coefficient 2 - 7 = -5.
    {
        std::vector<uint8_t> in = allOnes(32 * 3);
        Poly decoded;
        REQUIRE(MlDsaCodec::bitUnpack(SReadOnlyByteSpan(in.data(), in.size()), 2, 2, decoded));
        CHECK(decoded.coeffs[0] == -5);
        CHECK_FALSE(MlDsaCodec::inRange(decoded, -2, 2));
    }

    // eta = 4: four bits, reaching 4 - 15 = -11.
    {
        std::vector<uint8_t> in = allOnes(32 * 4);
        Poly decoded;
        REQUIRE(MlDsaCodec::bitUnpack(SReadOnlyByteSpan(in.data(), in.size()), 4, 4, decoded));
        CHECK(decoded.coeffs[0] == -11);
        CHECK_FALSE(MlDsaCodec::inRange(decoded, -4, 4));
    }

    // w1 at gamma2 = (q-1)/88: b = 43 needs six bits, which reach 63.
    {
        std::vector<uint8_t> in = allOnes(32 * 6);
        Poly decoded;
        REQUIRE(MlDsaCodec::simpleBitUnpack(SReadOnlyByteSpan(in.data(), in.size()), 43, decoded));
        CHECK(decoded.coeffs[0] == 63);
        CHECK_FALSE(MlDsaCodec::inRange(decoded, 0, 43));
    }

    // t1, t0 and z are safe: the range exactly fills the bit width, so every encoding is valid.
    {
        std::vector<uint8_t> in = allOnes(32 * 10);
        Poly decoded;
        REQUIRE(MlDsaCodec::simpleBitUnpack(
            SReadOnlyByteSpan(in.data(), in.size()), (1u << 10) - 1, decoded));
        CHECK(MlDsaCodec::inRange(decoded, 0, (1 << 10) - 1));
    }
    {
        std::vector<uint8_t> in = allOnes(32 * 13);
        Poly decoded;
        REQUIRE(MlDsaCodec::bitUnpack(
            SReadOnlyByteSpan(in.data(), in.size()), (1u << 12) - 1, 1u << 12, decoded));
        CHECK(MlDsaCodec::inRange(decoded, -((1 << 12) - 1), 1 << 12));
    }
    {
        std::vector<uint8_t> in = allOnes(32 * 20);
        Poly decoded;
        REQUIRE(MlDsaCodec::bitUnpack(
            SReadOnlyByteSpan(in.data(), in.size()), (1u << 19) - 1, 1u << 19, decoded));
        CHECK(MlDsaCodec::inRange(decoded, -((1 << 19) - 1), 1 << 19));
    }
}

namespace {
    /* Builds a hint vector with the given set positions per polynomial. */
    std::vector<Poly> hintsOf(const std::vector<std::vector<int>>& positions) {
        std::vector<Poly> hints(positions.size());
        for (size_t i = 0; i < positions.size(); ++i) {
            for (size_t j = 0; j < N; ++j) {
                hints[i].coeffs[j] = 0;
            }
            for (int p : positions[i]) {
                hints[i].coeffs[p] = 1;
            }
        }
        return hints;
    }
}

TEST_CASE("MlDsaCodec: hint pack/unpack round-trips for every parameter set's (k, omega)") {
    struct Set { size_t k; size_t omega; };
    const Set sets[] = { { 4, 80 }, { 6, 55 }, { 8, 75 } };  // ML-DSA-44, -65, -87

    Lcg rng(0x81A7);

    for (const Set& s : sets) {
        std::vector<uint8_t> packed(s.omega + s.k);

        for (int trial = 0; trial < 300; ++trial) {
            // Spread a random number of set positions across the polynomials.
            std::vector<std::vector<int>> positions(s.k);
            size_t remaining = size_t(rng.inRange(0, int32_t(s.omega)));

            for (size_t i = 0; i < s.k && remaining > 0; ++i) {
                const size_t take = size_t(rng.inRange(0, int32_t(remaining)));
                std::vector<bool> used(N, false);

                for (size_t t = 0; t < take; ++t) {
                    int pos = rng.inRange(0, int32_t(N) - 1);
                    while (used[size_t(pos)]) {
                        pos = (pos + 1) % int32_t(N);
                    }
                    used[size_t(pos)] = true;
                    positions[i].push_back(pos);
                }
                remaining -= take;
            }

            const std::vector<Poly> hints = hintsOf(positions);

            REQUIRE(MlDsaCodec::hintBitPack(hints.data(), s.k, s.omega,
                                            SByteSpan(packed.data(), packed.size())));

            std::vector<Poly> decoded(s.k);
            REQUIRE(MlDsaCodec::hintBitUnpack(
                SReadOnlyByteSpan(packed.data(), packed.size()), s.k, s.omega, decoded.data()));

            for (size_t i = 0; i < s.k; ++i) {
                REQUIRE(equalPoly(decoded[i], hints[i]));
            }
        }
    }
}

// The three rejection conditions, each triggered on its own. Implement fewer than all three and
// malformed signatures are accepted -- which is exactly what ACVP's "modified signature - hint"
// cases are for.
TEST_CASE("MlDsaCodec: hintBitUnpack rejects on all three of its conditions") {
    const size_t k = 4;
    const size_t omega = 80;

    // h[0] = {3, 9, 200}, h[1] = {0}, h[2] = {}, h[3] = {7, 8}. Note h[0] ends at 200 and h[3]
    // starts at 7: positions legitimately *decrease* across a polynomial boundary.
    const std::vector<Poly> hints = hintsOf({ { 3, 9, 200 }, { 0 }, { }, { 7, 8 } });

    std::vector<uint8_t> good(omega + k);
    REQUIRE(MlDsaCodec::hintBitPack(hints.data(), k, omega,
                                    SByteSpan(good.data(), good.size())));

    std::vector<Poly> decoded(k);
    REQUIRE(MlDsaCodec::hintBitUnpack(
        SReadOnlyByteSpan(good.data(), good.size()), k, omega, decoded.data()));
    for (size_t i = 0; i < k; ++i) {
        REQUIRE(equalPoly(decoded[i], hints[i]));
    }

    // The running totals are 3, 4, 4, 6 -- and the decreasing step from 200 to 7 is accepted,
    // which an implementation checking monotonicity across the whole array would reject.
    CHECK(good[omega + 0] == 3);
    CHECK(good[omega + 1] == 4);
    CHECK(good[omega + 2] == 4);
    CHECK(good[omega + 3] == 6);

    auto rejects = [&](const std::vector<uint8_t>& bytes) {
        std::vector<Poly> out(k);
        return !MlDsaCodec::hintBitUnpack(
            SReadOnlyByteSpan(bytes.data(), bytes.size()), k, omega, out.data());
    };

    SUBCASE("(1) the cumulative index moves backwards") {
        std::vector<uint8_t> bad = good;
        bad[omega + 1] = 0;             // was 4, now less than the 3 already consumed
        CHECK(rejects(bad));
    }

    SUBCASE("(1) the cumulative index exceeds omega") {
        std::vector<uint8_t> bad = good;
        bad[omega + 3] = uint8_t(omega + 1);
        CHECK(rejects(bad));
    }

    SUBCASE("(2) positions are not strictly increasing within a polynomial") {
        std::vector<uint8_t> swapped = good;
        const uint8_t tmp = swapped[0];
        swapped[0] = swapped[1];
        swapped[1] = tmp;               // 3, 9 -> 9, 3
        CHECK(rejects(swapped));

        // Equal positions are rejected too, not merely decreasing ones -- otherwise one
        // coefficient could be named twice and two encodings would mean the same hint.
        std::vector<uint8_t> repeated = good;
        repeated[1] = repeated[0];
        CHECK(rejects(repeated));
    }

    SUBCASE("(3) a leftover byte is non-zero") {
        std::vector<uint8_t> bad = good;
        bad[omega - 1] = 1;             // past the last position read, must be zero
        CHECK(rejects(bad));

        // Anywhere in the tail, not just the last byte.
        std::vector<uint8_t> middle = good;
        middle[10] = 42;
        CHECK(rejects(middle));
    }

    SUBCASE("a rejected decode leaves the caller's polynomials untouched") {
        std::vector<Poly> out(k);
        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < N; ++j) {
                out[i].coeffs[j] = 0x5A;
            }
        }

        std::vector<uint8_t> bad = good;
        bad[omega - 1] = 1;

        CHECK_FALSE(MlDsaCodec::hintBitUnpack(
            SReadOnlyByteSpan(bad.data(), bad.size()), k, omega, out.data()));

        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < N; ++j) {
                REQUIRE(out[i].coeffs[j] == 0x5A);
            }
        }
    }

    SUBCASE("a wrong input length is refused") {
        std::vector<uint8_t> shortened(good.begin(), good.end() - 1);
        std::vector<Poly> out(k);
        CHECK_FALSE(MlDsaCodec::hintBitUnpack(
            SReadOnlyByteSpan(shortened.data(), shortened.size()), k, omega, out.data()));
    }
}

TEST_CASE("MlDsaCodec: hintBitPack refuses more hints than the budget, and non-binary input") {
    const size_t k = 4;
    const size_t omega = 8;

    // Nine set coefficients against a budget of eight.
    std::vector<std::vector<int>> positions(k);
    for (int i = 0; i < 9; ++i) {
        positions[0].push_back(i);
    }
    const std::vector<Poly> tooMany = hintsOf(positions);

    std::vector<uint8_t> packed(omega + k);
    CHECK_FALSE(MlDsaCodec::hintBitPack(tooMany.data(), k, omega,
                                        SByteSpan(packed.data(), packed.size())));

    // Exactly the budget is fine.
    positions[0].pop_back();
    const std::vector<Poly> exact = hintsOf(positions);
    CHECK(MlDsaCodec::hintBitPack(exact.data(), k, omega,
                                  SByteSpan(packed.data(), packed.size())));

    // A coefficient that is neither 0 nor 1 is not a hint.
    std::vector<Poly> nonBinary = exact;
    nonBinary[1].coeffs[5] = 2;
    CHECK_FALSE(MlDsaCodec::hintBitPack(nonBinary.data(), k, omega,
                                        SByteSpan(packed.data(), packed.size())));
}

TEST_CASE("MlDsaCodec: an all-zero hint vector encodes and decodes") {
    const size_t k = 6;
    const size_t omega = 55;

    const std::vector<Poly> empty = hintsOf({ {}, {}, {}, {}, {}, {} });

    std::vector<uint8_t> packed(omega + k);
    REQUIRE(MlDsaCodec::hintBitPack(empty.data(), k, omega,
                                    SByteSpan(packed.data(), packed.size())));

    // Every byte is zero: no positions, and every running total is zero.
    for (size_t i = 0; i < packed.size(); ++i) {
        REQUIRE(packed[i] == 0);
    }

    std::vector<Poly> decoded(k);
    REQUIRE(MlDsaCodec::hintBitUnpack(
        SReadOnlyByteSpan(packed.data(), packed.size()), k, omega, decoded.data()));

    for (size_t i = 0; i < k; ++i) {
        REQUIRE(equalPoly(decoded[i], empty[i]));
    }
}
