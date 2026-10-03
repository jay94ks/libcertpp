// GHASH's GF(2^128) multiplication and accumulator, from the inside.
//
// GHASH has no publicly published multiplication vectors of its own -- the GCM spec publishes the
// subkey H and the finished tag, both of which tests/crypto/aeads/aesgcm.cpp checks end to end.
// What that cannot see is which of the two multiply implementations ran: the accelerated one is
// chosen per call behind a CPUID check, so on a machine that has PCLMULQDQ the published vectors
// only ever exercise that path, and on one that does not they only ever exercise the other. So the
// two are held against one another directly here, over lengths and bit patterns no published
// vector reaches.
//
// The field identities below are the part that catches a dropped bit reflection. GCM numbers a
// block's bits so that the *most significant* bit of the *first* byte is the x^0 coefficient, which
// makes the field's multiplicative identity the block 80 00 ... 00 -- not 00 ... 00 01, and not
// 00 ... 00 80. An implementation that reads the block in the ordinary polynomial-basis convention
// is still a perfectly good field: it is commutative, associative and distributive, and it is not
// GHASH. Multiplying by 80 00 ... 00 is the cheapest question that tells them apart.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include "crypto/aeads/ghash.hpp"

#include <cstring>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    using SBlock = std::vector<uint8_t>;

    SBlock zeroBlock() {
        return SBlock(16, 0x00);
    }

    // GCM's multiplicative identity: the x^0 coefficient is the most significant bit of the first
    // byte, so "one" is 0x80 followed by fifteen zeroes.
    SBlock oneBlock() {
        SBlock b = zeroBlock();
        b[0] = 0x80;
        return b;
    }

    // And "x" is the next bit along: the second-most-significant bit of the first byte.
    SBlock xBlock() {
        SBlock b = zeroBlock();
        b[0] = 0x40;
        return b;
    }

    // A deterministic, reproducible bit pattern -- a simple 64-bit xorshift, so a failure can be
    // reproduced from the seed alone rather than depending on the platform's RNG.
    class Pattern {
    private:
        uint64_t _state;

    public:
        explicit Pattern(uint64_t seed) : _state(seed ? seed : 0x9E3779B97F4A7C15ULL) { }

        uint8_t byte() {
            _state ^= _state << 13;
            _state ^= _state >> 7;
            _state ^= _state << 17;
            return uint8_t(_state >> 24);
        }

        SBlock block() {
            SBlock b(16);
            for (size_t i = 0; i < 16; ++i) {
                b[i] = byte();
            }
            return b;
        }

        std::vector<uint8_t> bytes(size_t length) {
            std::vector<uint8_t> v(length);
            for (size_t i = 0; i < length; ++i) {
                v[i] = byte();
            }
            return v;
        }
    };

    SBlock multiplied(const SBlock& left, const SBlock& right) {
        SBlock out = left;
        Ghash::multiply(out.data(), right.data());
        return out;
    }

    // Multiplication by x, worked out independently of the implementation: shift the whole block
    // right by one bit (GCM's bit 0 is the first byte's most significant, so "towards higher
    // degree" is towards the end of the block), and if the bit that fell off the end was set, XOR
    // the reduction polynomial's low terms back in as the block E1 00 ... 00.
    SBlock timesXByHand(const SBlock& in) {
        SBlock out(16, 0x00);
        uint8_t carry = 0;
        for (size_t i = 0; i < 16; ++i) {
            out[i] = uint8_t((in[i] >> 1) | (carry << 7));
            carry = uint8_t(in[i] & 1);
        }
        if (carry) {
            out[0] ^= 0xE1;
        }
        return out;
    }
}

TEST_CASE("Ghash: multiplication behaves as GCM's field, in GCM's bit order") {
    Pattern pattern(0xC0FFEE123456789ULL);

    const SBlock one = oneBlock();
    const SBlock zero = zeroBlock();

    for (int i = 0; i < 64; ++i) {
        const SBlock a = pattern.block();
        const SBlock b = pattern.block();
        const SBlock c = pattern.block();

        // The identity is 80 00 ... 00 and nothing else. This is the reflection test: in the
        // ordinary polynomial-basis reading, 80 00 ... 00 is x^127, so an unreflected multiply
        // fails here however self-consistent it is elsewhere.
        CHECK(multiplied(a, one) == a);
        CHECK(multiplied(one, a) == a);

        CHECK(multiplied(a, zero) == zero);

        CHECK(multiplied(a, b) == multiplied(b, a));
        CHECK(multiplied(multiplied(a, b), c) == multiplied(a, multiplied(b, c)));

        // Distributivity over XOR, which is the field's addition.
        SBlock sum(16);
        for (size_t j = 0; j < 16; ++j) {
            sum[j] = uint8_t(b[j] ^ c[j]);
        }
        const SBlock left = multiplied(a, sum);
        const SBlock viaParts = [&] {
            const SBlock ab = multiplied(a, b);
            const SBlock ac = multiplied(a, c);
            SBlock r(16);
            for (size_t j = 0; j < 16; ++j) {
                r[j] = uint8_t(ab[j] ^ ac[j]);
            }
            return r;
        }();
        CHECK(left == viaParts);
    }
}

TEST_CASE("Ghash: multiplying by x agrees with the shift it is defined as") {
    Pattern pattern(0x1234567890ABCDEFULL);
    const SBlock x = xBlock();

    for (int i = 0; i < 128; ++i) {
        const SBlock a = pattern.block();
        CHECK(multiplied(a, x) == timesXByHand(a));
    }

    // Including the two edges the carry depends on: a block whose last bit is set (so the shift
    // wraps) and one whose last bit is clear (so it does not).
    SBlock low = zeroBlock();
    low[15] = 0x01;
    CHECK(multiplied(low, x) == timesXByHand(low));

    SBlock high = zeroBlock();
    high[0] = 0x80;
    CHECK(multiplied(high, x) == timesXByHand(high));
    CHECK(multiplied(high, x) == xBlock());   // 1 * x == x
}

TEST_CASE("Ghash: the accumulator is independent of how its input is chunked") {
    Pattern pattern(0xFEEDFACEDEADBEEFULL);

    const SBlock h = pattern.block();

    for (size_t length : { size_t(0), size_t(1), size_t(15), size_t(16), size_t(17),
                           size_t(48), size_t(100) }) {
        const std::vector<uint8_t> data = pattern.bytes(length);

        Ghash whole;
        whole.reset(h.data());
        whole.push(data.data(), data.size());

        uint8_t expected[16];
        whole.finish(expected);

        for (size_t chunk : { size_t(1), size_t(3), size_t(16), size_t(17), size_t(64) }) {
            Ghash streamed;
            streamed.reset(h.data());

            size_t offset = 0;
            while (offset < data.size()) {
                const size_t take = (data.size() - offset < chunk) ? (data.size() - offset) : chunk;
                streamed.push(data.data() + offset, take);
                offset += take;
            }

            uint8_t got[16];
            streamed.finish(got);
            CHECK(std::memcmp(got, expected, 16) == 0);
        }
    }
}

TEST_CASE("Ghash: padToBlock() closes a block rather than extending the message") {
    Pattern pattern(0x0BADC0DE0BADC0DEULL);
    const SBlock h = pattern.block();

    // Pushing five bytes and then padding must equal pushing those five bytes followed by eleven
    // explicit zeroes -- and must *not* equal pushing a further sixteen zeroes, which is what
    // "pad with zeros until the next block" degenerates into if the partial block is mishandled.
    const std::vector<uint8_t> five = pattern.bytes(5);

    Ghash padded;
    padded.reset(h.data());
    padded.push(five.data(), five.size());
    padded.padToBlock();
    uint8_t a[16];
    padded.finish(a);

    std::vector<uint8_t> explicitZeros = five;
    explicitZeros.resize(16, 0x00);

    Ghash spelled;
    spelled.reset(h.data());
    spelled.push(explicitZeros.data(), explicitZeros.size());
    uint8_t b[16];
    spelled.finish(b);

    CHECK(std::memcmp(a, b, 16) == 0);

    std::vector<uint8_t> overlong = five;
    overlong.resize(32, 0x00);

    Ghash tooMuch;
    tooMuch.reset(h.data());
    tooMuch.push(overlong.data(), overlong.size());
    uint8_t c[16];
    tooMuch.finish(c);

    CHECK(std::memcmp(a, c, 16) != 0);

    // On a boundary there is nothing to close, so padToBlock() must do nothing at all.
    const std::vector<uint8_t> sixteen = pattern.bytes(16);

    Ghash plain;
    plain.reset(h.data());
    plain.push(sixteen.data(), sixteen.size());
    uint8_t d[16];
    plain.finish(d);

    Ghash alsoPadded;
    alsoPadded.reset(h.data());
    alsoPadded.push(sixteen.data(), sixteen.size());
    alsoPadded.padToBlock();
    uint8_t e[16];
    alsoPadded.finish(e);

    CHECK(std::memcmp(d, e, 16) == 0);
}

#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
TEST_CASE("Ghash: the PCLMULQDQ path agrees with the portable one byte for byte") {
    if (!Ghash::accelerated()) {
        // Built with the path available but running on a CPU without the instruction: there is
        // nothing to compare, and emitting PCLMULQDQ here would be a SIGILL rather than a failure.
        MESSAGE("this CPU has no PCLMULQDQ, so the accelerated path was not compared");
        return;
    }

    Pattern pattern(0xABCDEF0123456789ULL);

    for (int i = 0; i < 2048; ++i) {
        const SBlock a = pattern.block();
        const SBlock b = pattern.block();

        SBlock viaPortable = a;
        Ghash::multiplyPortable(viaPortable.data(), b.data());

        SBlock viaAccelerated = a;
        Ghash::multiplyAccelerated(viaAccelerated.data(), b.data());

        REQUIRE(viaPortable == viaAccelerated);
    }

    // And the structured cases a random pattern will not produce in 2048 tries: zero, one, every
    // single-bit block (each of which drives the reduction a different distance), and all ones.
    std::vector<SBlock> special;
    special.push_back(zeroBlock());
    special.push_back(oneBlock());
    special.push_back(SBlock(16, 0xFF));
    for (size_t bit = 0; bit < 128; ++bit) {
        SBlock b = zeroBlock();
        b[bit / 8] = uint8_t(0x80 >> (bit % 8));
        special.push_back(b);
    }

    for (const SBlock& a : special) {
        for (const SBlock& b : special) {
            SBlock viaPortable = a;
            Ghash::multiplyPortable(viaPortable.data(), b.data());

            SBlock viaAccelerated = a;
            Ghash::multiplyAccelerated(viaAccelerated.data(), b.data());

            REQUIRE(viaPortable == viaAccelerated);
        }
    }
}
#endif
