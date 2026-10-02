#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

// src/ is on this test's include path -- see CMakeLists.txt's note on private test sources.
#include "crypto/kems/mlkemcodec.hpp"

using namespace certpp;
using namespace certpp::crypto;

/* ML-KEM's wire encoding (FIPS 203 Alg. 3-6) and its two samplers (Alg. 7-8).
 *
 * Everything here decides what an ML-KEM key or ciphertext looks like as bytes, so a mistake is
 * purely an interoperability failure: it round-trips through this library perfectly and agrees
 * with nothing else. The expected values below therefore come from an independent Python model
 * built directly from FIPS 203's text, written and validated before any of this C++ existed --
 * not from the C++ being described. Where a whole 256-coefficient array is being pinned, it is
 * pinned by checksum plus explicit endpoints, so a transposition anywhere in the array fails. */

namespace {

    using Poly = SMlKemPoly;
    constexpr int32_t Q = MlKemRing::Q;
    constexpr size_t N = MlKemRing::N;

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
    };

    /* CRC-32 (the usual reflected polynomial) over the coefficients as little-endian uint16, so
     * one number pins the whole array including its order. */
    uint32_t crc32Of(const Poly& poly) {
        uint32_t crc = 0xFFFFFFFFu;

        for (size_t i = 0; i < N; ++i) {
            const uint8_t bytes[2] = {
                uint8_t(uint16_t(poly.coeffs[i]) & 0xFFu),
                uint8_t((uint16_t(poly.coeffs[i]) >> 8) & 0xFFu)
            };

            for (size_t b = 0; b < 2; ++b) {
                crc ^= bytes[b];
                for (int bit = 0; bit < 8; ++bit) {
                    crc = (crc >> 1) ^ (0xEDB88320u & uint32_t(-int32_t(crc & 1u)));
                }
            }
        }

        return ~crc;
    }

    /* The 32-byte seed 00 01 02 ... 1f, which the reference values were generated from. */
    void fillSeed(uint8_t (&seed)[32]) {
        for (size_t i = 0; i < 32; ++i) {
            seed[i] = uint8_t(i);
        }
    }

} // namespace

TEST_CASE("MlKemCodec::byteEncode()/byteDecode(): round trip at every width, exact length") {
    Rng rng(0xC0DEC);

    for (size_t d : { size_t(1), size_t(4), size_t(5), size_t(10), size_t(11), size_t(12) }) {
        CAPTURE(d);

        const int32_t modulus = (d < 12) ? (int32_t(1) << d) : Q;

        Poly original;
        for (size_t i = 0; i < N; ++i) {
            original.coeffs[i] = int16_t(rng.next() % uint64_t(modulus));
        }

        CBuffer encoded(32 * d);
        REQUIRE(encoded.size() == 32 * d);
        REQUIRE(MlKemCodec::byteEncode(d, original, encoded.toSpan()));

        Poly decoded;
        REQUIRE(MlKemCodec::byteDecode(d, encoded.toSpan(), decoded));

        for (size_t i = 0; i < N; ++i) {
            CAPTURE(i);
            REQUIRE(decoded.coeffs[i] == original.coeffs[i]);
        }
    }
}

TEST_CASE("MlKemCodec::byteEncode(): rejects a wrong-sized destination and an out-of-range d") {
    Poly poly;
    MlKemRing::setZero(poly);

    CBuffer tooSmall(32 * 4 - 1);
    CHECK_FALSE(MlKemCodec::byteEncode(4, poly, tooSmall.toSpan()));

    CBuffer tooBig(32 * 4 + 1);
    CHECK_FALSE(MlKemCodec::byteEncode(4, poly, tooBig.toSpan()));

    CBuffer right(32 * 4);
    CHECK(MlKemCodec::byteEncode(4, poly, right.toSpan()));

    CHECK_FALSE(MlKemCodec::byteEncode(0, poly, right.toSpan()));
    CHECK_FALSE(MlKemCodec::byteEncode(13, poly, right.toSpan()));
    CHECK_FALSE(MlKemCodec::byteDecode(0, right.toSpan(), poly));
    CHECK_FALSE(MlKemCodec::byteDecode(13, right.toSpan(), poly));
}

/* The bit order is the thing a plausible-looking implementation gets wrong. FIPS 203's own worked
 * example of BitsToBytes is the bit string 11010001 -> byte 2^0 + 2^1 + 2^3 + 2^7 = 139, i.e.
 * little-endian within the byte. With d = 1 each coefficient *is* one bit, so that example can be
 * reproduced exactly. */
TEST_CASE("MlKemCodec: bits are packed little-endian within each byte") {
    Poly bits;
    MlKemRing::setZero(bits);

    // 1,1,0,1,0,0,0,1 as the first eight coefficients.
    const int16_t pattern[8] = { 1, 1, 0, 1, 0, 0, 0, 1 };
    for (size_t i = 0; i < 8; ++i) {
        bits.coeffs[i] = pattern[i];
    }

    CBuffer encoded(32);
    REQUIRE(MlKemCodec::byteEncode(1, bits, encoded.toSpan()));
    CHECK(encoded.toPtr()[0] == 139);

    // And a single high bit of a d=12 coefficient must land in the *next* byte, not the same one,
    // since coefficients are contiguous rather than byte-aligned.
    Poly wide;
    MlKemRing::setZero(wide);
    wide.coeffs[0] = int16_t(1 << 11);

    CBuffer wideEncoded(32 * 12);
    REQUIRE(MlKemCodec::byteEncode(12, wide, wideEncoded.toSpan()));
    CHECK(wideEncoded.toPtr()[0] == 0x00);
    CHECK(wideEncoded.toPtr()[1] == 0x08);  // bit 11 -> byte 1, position 3
}

/* d = 12 reduces mod Q, so it is deliberately not injective -- and that asymmetry is exactly
 * what ML-KEM's encapsulation-key validity check tests. */
TEST_CASE("MlKemCodec: d=12 decoding folds out-of-range segments, and isCanonical12() catches them") {
    Poly inRange;
    MlKemRing::setZero(inRange);
    inRange.coeffs[0] = int16_t(Q - 1);

    CBuffer canonical(384);
    REQUIRE(MlKemCodec::byteEncode(12, inRange, canonical.toSpan()));
    CHECK(MlKemCodec::isCanonical12(canonical.toSpan()));

    // Now hand-build an encoding whose first segment is Q itself -- representable in 12 bits, but
    // not a field element.
    Poly outOfRange;
    MlKemRing::setZero(outOfRange);
    CBuffer bad(384);
    REQUIRE(MlKemCodec::byteEncode(12, outOfRange, bad.toSpan()));
    bad.toPtr()[0] = uint8_t(Q & 0xFF);
    bad.toPtr()[1] = uint8_t((Q >> 8) & 0x0F);

    CHECK_FALSE(MlKemCodec::isCanonical12(bad.toSpan()));

    // byteDecode still succeeds, folding Q to 0 -- which is why the check above has to exist
    // separately rather than being left to the decoder.
    Poly folded;
    REQUIRE(MlKemCodec::byteDecode(12, bad.toSpan(), folded));
    CHECK(folded.coeffs[0] == 0);

    // 4095, the largest 12-bit value, folds to 4095 - 3329.
    CBuffer maxSegment(384);
    REQUIRE(MlKemCodec::byteEncode(12, outOfRange, maxSegment.toSpan()));
    maxSegment.toPtr()[0] = 0xFF;
    maxSegment.toPtr()[1] = uint8_t(maxSegment.toPtr()[1] | 0x0F);
    CHECK_FALSE(MlKemCodec::isCanonical12(maxSegment.toSpan()));

    Poly foldedMax;
    REQUIRE(MlKemCodec::byteDecode(12, maxSegment.toSpan(), foldedMax));
    CHECK(foldedMax.coeffs[0] == int16_t(4095 - Q));
}

/* Compress/Decompress are lossy by design, so the test is the error bound rather than equality.
 * Both directions were checked exhaustively against the exact rational definition for every
 * coefficient in [0, Q) and every d, in the model; here the bound is what gets asserted. */
TEST_CASE("MlKemCodec::compress()/decompress(): error stays inside the rounding bound") {
    for (size_t d : { size_t(1), size_t(4), size_t(5), size_t(10), size_t(11) }) {
        CAPTURE(d);

        int32_t worst = 0;

        for (int32_t x = 0; x < Q; ++x) {
            Poly p;
            MlKemRing::setZero(p);
            p.coeffs[0] = int16_t(x);

            REQUIRE(MlKemCodec::compress(d, p));
            REQUIRE(p.coeffs[0] >= 0);
            REQUIRE(p.coeffs[0] < (int32_t(1) << d));

            REQUIRE(MlKemCodec::decompress(d, p));
            REQUIRE(p.coeffs[0] >= 0);
            REQUIRE(p.coeffs[0] < Q);

            const int32_t back = int32_t(p.coeffs[0]);
            const int32_t forward = (x - back + Q) % Q;
            const int32_t backward = (back - x + Q) % Q;
            worst = worst > (forward < backward ? forward : backward)
                ? worst : (forward < backward ? forward : backward);
        }

        // The bound FIPS 203's decryption-failure analysis budgets for: ceil(q / 2^(d+1)).
        const int32_t bound = (Q / (int32_t(1) << (d + 1))) + 1;
        CAPTURE(worst);
        CAPTURE(bound);
        CHECK(worst <= bound);
    }

    Poly p;
    MlKemRing::setZero(p);
    CHECK_FALSE(MlKemCodec::compress(0, p));
    CHECK_FALSE(MlKemCodec::compress(12, p));   // compression only goes up to 11
    CHECK_FALSE(MlKemCodec::decompress(0, p));
    CHECK_FALSE(MlKemCodec::decompress(12, p));
}

/* SampleNTT is the first consumer of SHAKE128::squeeze(), and the amount of stream it needs is
 * seed-dependent -- 474, 453 and 498 bytes for the three cases below. Pinned against the Python
 * model, by checksum over the whole array plus explicit endpoints. */
TEST_CASE("CMlKemSampler::sampleNtt(): matches the reference model") {
    uint8_t seed[32];
    fillSeed(seed);
    const SReadOnlyByteSpan seedSpan(seed, sizeof(seed));

    struct Case {
        uint8_t i;
        uint8_t j;
        uint32_t crc;
        int16_t first;
        int16_t second;
        int16_t last;
    };

    const Case cases[] = {
        { 0, 0, 0x62D594A8u,  481, 1919, 3216 },
        { 1, 2, 0x7D877765u, 1642, 1316, 1454 },
        { 3, 7, 0xCDE11E17u,  714,  554, 2540 },
    };

    for (const Case& c : cases) {
        CAPTURE(c.i);
        CAPTURE(c.j);

        Poly out;
        REQUIRE(CMlKemSampler::sampleNtt(seedSpan, c.i, c.j, out));

        for (size_t k = 0; k < N; ++k) {
            REQUIRE(out.coeffs[k] >= 0);
            REQUIRE(out.coeffs[k] < Q);
        }

        CHECK(out.coeffs[0] == c.first);
        CHECK(out.coeffs[1] == c.second);
        CHECK(out.coeffs[N - 1] == c.last);
        CHECK(crc32Of(out) == c.crc);
    }
}

/* The index bytes are appended in the order given, and that order is part of the wire format --
 * FIPS 203's matrix expansion deliberately passes them transposed. Swapping them must change the
 * result, or a transposed call would be undetectable. */
TEST_CASE("CMlKemSampler::sampleNtt(): the index order is significant, and it is deterministic") {
    uint8_t seed[32];
    fillSeed(seed);
    const SReadOnlyByteSpan seedSpan(seed, sizeof(seed));

    Poly a;
    Poly b;
    REQUIRE(CMlKemSampler::sampleNtt(seedSpan, 1, 2, a));
    REQUIRE(CMlKemSampler::sampleNtt(seedSpan, 2, 1, b));
    CHECK(crc32Of(a) != crc32Of(b));

    Poly again;
    REQUIRE(CMlKemSampler::sampleNtt(seedSpan, 1, 2, again));
    CHECK(crc32Of(again) == crc32Of(a));

    // A different seed must give a different polynomial too.
    uint8_t other[32];
    fillSeed(other);
    other[31] ^= 0x01;

    Poly shifted;
    REQUIRE(CMlKemSampler::sampleNtt(SReadOnlyByteSpan(other, sizeof(other)), 1, 2, shifted));
    CHECK(crc32Of(shifted) != crc32Of(a));
}

TEST_CASE("CMlKemSampler::sampleNtt(): rejects a seed that isn't 32 bytes") {
    uint8_t shortSeed[31] = { 0 };
    Poly out;
    CHECK_FALSE(CMlKemSampler::sampleNtt(SReadOnlyByteSpan(shortSeed, sizeof(shortSeed)), 0, 0, out));
    CHECK_FALSE(CMlKemSampler::sampleNtt(SReadOnlyByteSpan(nullptr, 32), 0, 0, out));
}

/* SamplePolyCBD's PRF input here is SHAKE256(eta || seed), which is not how ML-KEM derives it --
 * ML-KEM uses PRF_eta(s, b). It does not matter for this test: the point is to pin the
 * bit-unpacking and the x - y arithmetic against the model, using a PRF output both sides can
 * reproduce. */
TEST_CASE("CMlKemSampler::samplePolyCbd(): matches the reference model and stays in range") {
    uint8_t seed[32];
    fillSeed(seed);

    struct Case { size_t eta; uint32_t crc; const char* prfPrefix; };
    const Case cases[] = {
        { 2, 0xE4D51883u, "8c33e1f101198779" },
        { 3, 0x49F6B496u, "7e536053180720d0" },
    };

    for (const Case& c : cases) {
        CAPTURE(c.eta);

        // PRF = SHAKE256(eta || seed), squeezed to 64*eta bytes.
        uint8_t input[33];
        input[0] = uint8_t(c.eta);
        std::memcpy(input + 1, seed, 32);

        SHAKE256 prf;
        REQUIRE(prf.push(SReadOnlyByteSpan(input, sizeof(input))) == sizeof(input));

        CBuffer prfOut(64 * c.eta);
        REQUIRE(prf.squeeze(prfOut.toSpan()));

        // Confirms this test is feeding the same bytes the model did.
        TArray<uint8_t> expectedPrefix;
        REQUIRE(CHex::decode(c.prfPrefix, expectedPrefix));
        CHECK(std::memcmp(prfOut.toPtr(), expectedPrefix.begin(), expectedPrefix.size()) == 0);

        Poly out;
        REQUIRE(CMlKemSampler::samplePolyCbd(c.eta, prfOut.toSpan(), out));

        // Every coefficient must be a centered value in [-eta, eta], reduced into [0, Q).
        for (size_t i = 0; i < N; ++i) {
            const int32_t centered = (out.coeffs[i] <= Q / 2)
                ? int32_t(out.coeffs[i])
                : int32_t(out.coeffs[i]) - Q;

            REQUIRE(centered >= -int32_t(c.eta));
            REQUIRE(centered <= int32_t(c.eta));
        }

        CHECK(crc32Of(out) == c.crc);
    }
}

TEST_CASE("CMlKemSampler::samplePolyCbd(): rejects a wrong-sized PRF output or eta") {
    CBuffer buf(128);
    Poly out;

    CHECK(CMlKemSampler::samplePolyCbd(2, buf.toSpan(), out));   // 64*2 == 128

    CBuffer wrong(127);
    CHECK_FALSE(CMlKemSampler::samplePolyCbd(2, wrong.toSpan(), out));
    CHECK_FALSE(CMlKemSampler::samplePolyCbd(3, buf.toSpan(), out));  // needs 192
    CHECK_FALSE(CMlKemSampler::samplePolyCbd(0, buf.toSpan(), out));
    CHECK_FALSE(CMlKemSampler::samplePolyCbd(4, buf.toSpan(), out));
}
