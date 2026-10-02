#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

/* SHA3-256 and SHA3-512 (FIPS 202 6.1). Added because ML-KEM needs them as FIPS 203's H and G
 * functions, but they are ordinary hashers and tested as such.
 *
 * The one byte worth being careful about is the domain separator: SHA-3 appends 0x06 where SHAKE
 * appends 0x1F, and that single byte is the entire difference between a SHA-3 digest and a SHAKE
 * output of the same length over the same sponge. Every other part of the construction -- the
 * Keccak-f[1600] permutation, the absorption, the 0x80 terminator -- is already shared with the
 * SHAKE implementations, so if the permutation were wrong the SHAKE tests would have caught it.
 * What these tests add is that the rate and the padding byte are right.
 *
 * The rate is also where off-by-ones hide, so the inputs below include lengths exactly one below,
 * at, and one above each algorithm's rate, plus two whole blocks -- 136 bytes for SHA3-256 and 72
 * for SHA3-512. Expected digests come from Python's hashlib; the empty-message and "abc" values
 * are additionally the widely published FIPS 202 examples, so they double as an external check
 * rather than resting on one source. */

namespace {

    bool digestOf(EHashers which, const SReadOnlyByteSpan& input, CBuffer& out) {
        IHasherPtr hasher;
        if (IHasher::create(which, hasher) != ERET_OK || !hasher) {
            return false;
        }

        if (!out.resize(hasher->byteWidth())) {
            return false;
        }

        if (!input.empty() && hasher->push(input) != input.size) {
            return false;
        }

        SByteSpan span = out.toSpan();
        return hasher->finish(span);
    }

    bool matchesHex(const CBuffer& actual, const char* expectedHex) {
        TArray<uint8_t> expected;
        if (!CHex::decode(expectedHex, expected)) {
            return false;
        }

        if (expected.size() != actual.size()) {
            return false;
        }

        return std::memcmp(actual.toPtr(), expected.begin(), expected.size()) == 0;
    }

    CBuffer repeated(char c, size_t count) {
        CBuffer buf(count);
        if (count) {
            std::memset(buf.toPtr(), uint8_t(c), count);
        }
        return buf;
    }

} // namespace

TEST_CASE("SHA3-256: known-answer vectors, including the rate boundary") {
    struct Case { const char* label; const char* text; const char* expected; };
    const Case cases[] = {
        { "empty", "",
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" },
        { "abc", "abc",
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
        { "FIPS 202 long message", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376" },
    };

    for (const Case& c : cases) {
        CAPTURE(c.label);

        CBuffer out;
        REQUIRE(digestOf(EHASH_SHA3_256,
            SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(c.text), std::strlen(c.text)),
            out));
        CHECK(out.size() == 32);
        CHECK(matchesHex(out, c.expected));
    }

    // The rate is 136 bytes: one short, exact, one over, and two whole blocks.
    struct Boundary { size_t length; const char* expected; };
    const Boundary boundaries[] = {
        { 135, "8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9" },
        { 136, "3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1" },
        { 137, "f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614" },
        { 272, "a490357b9b3fb39d0a89a117734e5b020b1f33c7bf3fa3575c396425432003d3" },
    };

    for (const Boundary& b : boundaries) {
        CAPTURE(b.length);

        CBuffer input = repeated('a', b.length);
        CBuffer out;
        REQUIRE(digestOf(EHASH_SHA3_256, input.toSpan(), out));
        CHECK(matchesHex(out, b.expected));
    }
}

TEST_CASE("SHA3-512: known-answer vectors, including the rate boundary") {
    struct Case { const char* label; const char* text; const char* expected; };
    const Case cases[] = {
        { "empty", "",
          "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
          "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" },
        { "abc", "abc",
          "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
          "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
        { "FIPS 202 long message", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d"
          "ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e" },
    };

    for (const Case& c : cases) {
        CAPTURE(c.label);

        CBuffer out;
        REQUIRE(digestOf(EHASH_SHA3_512,
            SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(c.text), std::strlen(c.text)),
            out));
        CHECK(out.size() == 64);
        CHECK(matchesHex(out, c.expected));
    }

    // The rate is 72 bytes.
    struct Boundary { size_t length; const char* expected; };
    const Boundary boundaries[] = {
        { 71, "070faf98d2a8fddf8ed886408744dc06456096c2e045f26f3c7b010530e6bbb3"
              "db535a54d636856f4e0e1e982461cb9a7e8e57ff8895cff1619af9f0e486e28c" },
        { 72, "a8ae722a78e10cbbc413886c02eb5b369a03f6560084aff566bd597bb7ad8c1c"
              "cd86e81296852359bf2faddb5153c0a7445722987875e74287adac21adebe952" },
        { 73, "23e6a8815f8201dbbf6a5463be8dcadb1acea9df5f8998954e59ac9565cf6d29"
              "b17aa27a5e8b0fc06343db6122d6e544d27583ddc78504d08203217e7e65b6bd" },
        { 144, "446cd4d7ba19510dcc776b21045bc68d424b5b840e14685e149bb238b5f473c0"
               "356b69e04f0f5785eefce20ff09e678b080d8aac64568c5edf001cd32b2ed7a8" },
    };

    for (const Boundary& b : boundaries) {
        CAPTURE(b.length);

        CBuffer input = repeated('a', b.length);
        CBuffer out;
        REQUIRE(digestOf(EHASH_SHA3_512, input.toSpan(), out));
        CHECK(matchesHex(out, b.expected));
    }
}

/* The million-'a' stress vector drives absorption across thousands of blocks, which is the only
 * thing here that exercises the buffering loop at scale. */
TEST_CASE("SHA3-256/SHA3-512: the million-'a' stress vector") {
    CBuffer input = repeated('a', 1000000);

    CBuffer out256;
    REQUIRE(digestOf(EHASH_SHA3_256, input.toSpan(), out256));
    CHECK(matchesHex(out256,
        "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"));

    CBuffer out512;
    REQUIRE(digestOf(EHASH_SHA3_512, input.toSpan(), out512));
    CHECK(matchesHex(out512,
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859"
        "ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"));
}

/* Absorption must be chunk-invariant: the same message split differently has to hash the same.
 * Splits at and either side of the rate are where a buffering bug would surface. */
TEST_CASE("SHA3-256/SHA3-512: chunked input hashes identically to one-shot input") {
    CBuffer message(500);
    for (size_t i = 0; i < message.size(); ++i) {
        message.toPtr()[i] = uint8_t(i * 7 + 3);
    }

    for (EHashers which : { EHASH_SHA3_256, EHASH_SHA3_512 }) {
        CBuffer oneShot;
        REQUIRE(digestOf(which, message.toSpan(), oneShot));

        for (size_t chunk : { size_t(1), size_t(13), size_t(71), size_t(72), size_t(73),
                              size_t(135), size_t(136), size_t(137), size_t(499) })
        {
            CAPTURE(chunk);

            IHasherPtr hasher;
            REQUIRE(IHasher::create(which, hasher) == ERET_OK);

            size_t offset = 0;
            while (offset < message.size()) {
                size_t take = chunk;
                if (take > message.size() - offset) {
                    take = message.size() - offset;
                }

                const SReadOnlyByteSpan piece(message.toPtr() + offset, take);
                REQUIRE(hasher->push(piece) == take);
                offset += take;
            }

            CBuffer chunked(hasher->byteWidth());
            SByteSpan span = chunked.toSpan();
            REQUIRE(hasher->finish(span));
            CHECK(std::memcmp(chunked.toPtr(), oneShot.toPtr(), oneShot.size()) == 0);
        }
    }
}

/* finish() is a query here, matching the SHA-2 family rather than the XOFs: the sponge is left
 * alone, so the digest repeats and absorption can continue afterwards. */
TEST_CASE("SHA3-256: finish() is repeatable and does not stop absorption") {
    IHasherPtr hasher;
    REQUIRE(IHasher::create(EHASH_SHA3_256, hasher) == ERET_OK);

    const uint8_t ab[2] = { 'a', 'b' };
    REQUIRE(hasher->push(SReadOnlyByteSpan(ab, 2)) == 2);

    CBuffer first(32);
    SByteSpan firstSpan = first.toSpan();
    REQUIRE(hasher->finish(firstSpan));

    CBuffer again(32);
    SByteSpan againSpan = again.toSpan();
    REQUIRE(hasher->finish(againSpan));
    CHECK(std::memcmp(first.toPtr(), again.toPtr(), 32) == 0);

    // Absorbing the third byte must now give the digest of "abc".
    const uint8_t c[1] = { 'c' };
    REQUIRE(hasher->push(SReadOnlyByteSpan(c, 1)) == 1);

    CBuffer abc(32);
    SByteSpan abcSpan = abc.toSpan();
    REQUIRE(hasher->finish(abcSpan));
    CHECK(matchesHex(abc, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
}

TEST_CASE("SHA3-256: reset() returns the hasher to its initial state") {
    IHasherPtr hasher;
    REQUIRE(IHasher::create(EHASH_SHA3_256, hasher) == ERET_OK);

    const uint8_t junk[5] = { 1, 2, 3, 4, 5 };
    REQUIRE(hasher->push(SReadOnlyByteSpan(junk, sizeof(junk))) == sizeof(junk));
    hasher->reset();

    CBuffer out(32);
    SByteSpan span = out.toSpan();
    REQUIRE(hasher->finish(span));
    CHECK(matchesHex(out, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
}

/* SHA-3 and SHAKE share the whole sponge and differ only in the domain byte, so a digest that
 * accidentally used SHAKE's 0x1F would still look well-formed. Asserting they differ at the same
 * output length is what makes that mistake detectable. */
TEST_CASE("SHA3-256 and SHAKE256 differ despite sharing the sponge") {
    CBuffer sha3;
    REQUIRE(digestOf(EHASH_SHA3_256, SReadOnlyByteSpan(nullptr, 0), sha3));

    SHAKE256 shake(32);
    CBuffer shakeOut(32);
    SByteSpan shakeSpan = shakeOut.toSpan();
    REQUIRE(shake.finish(shakeSpan));

    REQUIRE(sha3.size() == shakeOut.size());
    CHECK(std::memcmp(sha3.toPtr(), shakeOut.toPtr(), sha3.size()) != 0);
}

TEST_CASE("SHA3-256/SHA3-512: byteWidth() and a too-small destination") {
    IHasherPtr h256;
    REQUIRE(IHasher::create(EHASH_SHA3_256, h256) == ERET_OK);
    CHECK(h256->byteWidth() == 32);

    IHasherPtr h512;
    REQUIRE(IHasher::create(EHASH_SHA3_512, h512) == ERET_OK);
    CHECK(h512->byteWidth() == 64);

    uint8_t tooSmall[31] = { 0 };
    SByteSpan span(tooSmall, sizeof(tooSmall));
    CHECK_FALSE(h256->finish(span));
}
