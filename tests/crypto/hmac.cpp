// HMAC (RFC 2104), against RFC 4231's published test vectors.
//
// RFC 4231 is the authority here rather than a round-trip: HMAC has no inverse to round-trip
// against, and an implementation that swapped ipad and opad, or hashed an over-long key the wrong
// way, would be perfectly self-consistent. The vectors below are transcribed from RFC 4231 4.2
// through 4.7, all seven cases, for SHA-256 (the one cskcwk's HKDF needs) plus SHA-1, SHA-384 and
// SHA-512 to exercise both block sizes.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    std::vector<uint8_t> fromHex(const char* hex) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') { return c - '0'; }
            if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
            if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
            return -1;
        };

        std::vector<uint8_t> out;
        for (const char* p = hex; *p && *(p + 1); p += 2) {
            out.push_back(uint8_t((nibble(p[0]) << 4) | nibble(p[1])));
        }
        return out;
    }

    std::vector<uint8_t> repeated(uint8_t value, size_t count) {
        return std::vector<uint8_t>(count, value);
    }

    std::vector<uint8_t> ascii(const char* text) {
        std::vector<uint8_t> out;
        for (const char* p = text; *p; ++p) {
            out.push_back(uint8_t(*p));
        }
        return out;
    }

    SReadOnlyByteSpan spanOf(const std::vector<uint8_t>& v) {
        return SReadOnlyByteSpan(v.data(), v.size());
    }

    /* Runs one vector through both the one-shot and the streaming path. */
    void checkVector(
        EHashers alg, const std::vector<uint8_t>& key, const std::vector<uint8_t>& message,
        const char* expectedHex
    ) {
        const std::vector<uint8_t> expected = fromHex(expectedHex);

        CHmac mac;
        REQUIRE(mac.reset(alg, spanOf(key)) == ERET_OK);
        REQUIRE(mac.byteWidth() == expected.size());

        std::vector<uint8_t> oneShot(expected.size());
        REQUIRE(CHmac::compute(
            alg, spanOf(key), spanOf(message),
            SByteSpan(oneShot.data(), oneShot.size())) == ERET_OK);
        CHECK(oneShot == expected);

        // The streaming path must agree, and pushing in arbitrary pieces must not change the
        // answer -- which is what makes it usable over a record stream.
        for (size_t chunk : { size_t(1), size_t(7), size_t(64), size_t(1000) }) {
            CHmac streamed;
            REQUIRE(streamed.reset(alg, spanOf(key)) == ERET_OK);

            size_t offset = 0;
            while (offset < message.size()) {
                const size_t take = (message.size() - offset < chunk)
                    ? (message.size() - offset) : chunk;
                REQUIRE(streamed.push(SReadOnlyByteSpan(message.data() + offset, take)) == take);
                offset += take;
            }

            std::vector<uint8_t> tag(expected.size());
            REQUIRE(streamed.finish(SByteSpan(tag.data(), tag.size())));
            REQUIRE(tag == expected);
        }

        // verify() must accept the real tag and reject a one-bit change anywhere in it.
        CHECK(CHmac::verify(alg, spanOf(key), spanOf(message), spanOf(expected)));

        for (size_t i = 0; i < expected.size(); ++i) {
            std::vector<uint8_t> tampered = expected;
            tampered[i] ^= 0x01;
            REQUIRE_FALSE(CHmac::verify(alg, spanOf(key), spanOf(message), spanOf(tampered)));
        }
    }
}

TEST_CASE("CHmac: the RFC 2104 block sizes, and what HMAC is not defined over") {
    CHECK(CHmac::blockBytesOf(EHASH_MD5) == 64);
    CHECK(CHmac::blockBytesOf(EHASH_SHA1) == 64);
    CHECK(CHmac::blockBytesOf(EHASH_SHA224) == 64);
    CHECK(CHmac::blockBytesOf(EHASH_SHA256) == 64);
    CHECK(CHmac::blockBytesOf(EHASH_SHA384) == 128);
    CHECK(CHmac::blockBytesOf(EHASH_SHA512) == 128);

    // SHA-3's block size for HMAC is its sponge rate, which differs per output length rather
    // than being shared the way SHA-2's 64/128 split is.
    CHECK(CHmac::blockBytesOf(EHASH_SHA3_256) == 136);
    CHECK(CHmac::blockBytesOf(EHASH_SHA3_512) == 72);

    // BLAKE2s is 16 32-bit words per block, the same 64 bytes SHA-256 uses. Missing this entry
    // would have made HMAC-BLAKE2s simply unsupported -- which is the point of returning 0 for an
    // unknown hash rather than guessing a block size.
    CHECK(CHmac::blockBytesOf(EHASH_BLAKE2S) == 64);

    // SHAKE is an XOF: HMAC is defined over a fixed-output hash, so it is refused rather than
    // given a guessed block size.
    CHECK(CHmac::blockBytesOf(EHASH_SHAKE128) == 0);
    CHECK(CHmac::blockBytesOf(EHASH_SHAKE256) == 0);
    CHECK(CHmac::blockBytesOf(EHASH_UNKNOWN) == 0);

    // Every supported block fits the fixed key buffer.
    CHECK(CHmac::blockBytesOf(EHASH_SHA3_256) == CHmac::MAX_BLOCK_BYTES);

    CHmac mac;
    const std::vector<uint8_t> key = repeated(0x0B, 20);
    CHECK(mac.reset(EHASH_SHAKE256, spanOf(key)) == ERET_NOTSUP);
    CHECK(mac.reset(EHASH_UNKNOWN, spanOf(key)) == ERET_NOTSUP);

    // Unkeyed, nothing works -- but nothing crashes either.
    CHmac unkeyed;
    CHECK(unkeyed.byteWidth() == 0);
    CHECK(unkeyed.push(spanOf(key)) == 0);
    uint8_t tag[32];
    CHECK_FALSE(unkeyed.finish(SByteSpan(tag, sizeof(tag))));
}

// RFC 4231 4.2: a 20-byte key, short message.
TEST_CASE("CHmac: RFC 4231 test case 1") {
    const std::vector<uint8_t> key = repeated(0x0B, 20);
    const std::vector<uint8_t> message = ascii("Hi There");

    checkVector(EHASH_SHA256, key, message,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    checkVector(EHASH_SHA1, key, message,
        "b617318655057264e28bc0b6fb378c8ef146be00");
    checkVector(EHASH_SHA384, key, message,
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
        "faea9ea9076ede7f4af152e8b2fa9cb6");
    checkVector(EHASH_SHA512, key, message,
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
}

// RFC 4231 4.3: the key is shorter than the digest, the message longer than one block's worth of
// nothing in particular -- "what do ya want for nothing?".
TEST_CASE("CHmac: RFC 4231 test case 2") {
    const std::vector<uint8_t> key = ascii("Jefe");
    const std::vector<uint8_t> message = ascii("what do ya want for nothing?");

    checkVector(EHASH_SHA256, key, message,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    checkVector(EHASH_SHA1, key, message,
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    checkVector(EHASH_SHA512, key, message,
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
}

// RFC 4231 4.4: 50 bytes of 0xDD, which crosses a block boundary for SHA-256.
TEST_CASE("CHmac: RFC 4231 test case 3") {
    const std::vector<uint8_t> key = repeated(0xAA, 20);
    const std::vector<uint8_t> message = repeated(0xDD, 50);

    checkVector(EHASH_SHA256, key, message,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    checkVector(EHASH_SHA512, key, message,
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
        "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
}

// RFC 4231 4.5: a 25-byte key of ascending bytes.
TEST_CASE("CHmac: RFC 4231 test case 4") {
    const std::vector<uint8_t> key = fromHex("0102030405060708090a0b0c0d0e0f10111213141516171819");
    const std::vector<uint8_t> message = repeated(0xCD, 50);

    checkVector(EHASH_SHA256, key, message,
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    checkVector(EHASH_SHA512, key, message,
        "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
        "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
}

// RFC 4231 4.6: a truncated 128-bit tag. This is the case that exercises verify()'s handling of
// a tag shorter than the hash's own output (RFC 2104 4's truncation).
TEST_CASE("CHmac: RFC 4231 test case 5, with a truncated tag") {
    const std::vector<uint8_t> key = repeated(0x0C, 20);
    const std::vector<uint8_t> message = ascii("Test With Truncation");

    uint8_t full[32];
    REQUIRE(CHmac::compute(
        EHASH_SHA256, spanOf(key), spanOf(message), SByteSpan(full, sizeof(full))) == ERET_OK);

    const std::vector<uint8_t> expected128 = fromHex("a3b6167473100ee06e0c796c2955552b");
    REQUIRE(expected128.size() == 16);

    // The truncated tag is the leading 16 bytes of the full one.
    CHECK(std::memcmp(full, expected128.data(), 16) == 0);

    // verify() accepts it at that length, and still rejects a flipped bit.
    CHECK(CHmac::verify(EHASH_SHA256, spanOf(key), spanOf(message), spanOf(expected128)));

    std::vector<uint8_t> tampered = expected128;
    tampered[15] ^= 0x80;
    CHECK_FALSE(CHmac::verify(EHASH_SHA256, spanOf(key), spanOf(message), spanOf(tampered)));

    // A tag longer than the hash's output cannot match anything and is refused rather than
    // compared against uninitialized bytes.
    std::vector<uint8_t> tooLong(33, 0x00);
    CHECK_FALSE(CHmac::verify(EHASH_SHA256, spanOf(key), spanOf(message), spanOf(tooLong)));

    // An empty tag is not a match for everything.
    CHECK_FALSE(CHmac::verify(EHASH_SHA256, spanOf(key), spanOf(message),
                              SReadOnlyByteSpan(full, 0)));
}

// RFC 4231 4.7 and 4.8: a 131-byte key, which is longer than SHA-256's 64-byte block and so must
// be hashed down first. This is the case an implementation gets wrong by zero-padding a long key
// instead of hashing it -- and it still produces consistent tags, just not RFC 2104's.
TEST_CASE("CHmac: RFC 4231 test cases 6 and 7, over-long keys") {
    const std::vector<uint8_t> key = repeated(0xAA, 131);

    checkVector(EHASH_SHA256, key,
        ascii("Test Using Larger Than Block-Size Key - Hash Key First"),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    checkVector(EHASH_SHA256, key,
        ascii("This is a test using a larger than block-size key and a larger than "
              "block-size data. The key needs to be hashed before being used by the HMAC "
              "algorithm."),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");

    checkVector(EHASH_SHA512, key,
        ascii("Test Using Larger Than Block-Size Key - Hash Key First"),
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
        "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");

    // A key of exactly the block size takes neither path -- it is used as is, with no padding
    // and no hashing. Worth pinning, since it sits between the two branches.
    const std::vector<uint8_t> exactKey = repeated(0xAA, 64);
    uint8_t exactTag[32];
    CHECK(CHmac::compute(EHASH_SHA256, spanOf(exactKey), spanOf(ascii("boundary")),
                         SByteSpan(exactTag, sizeof(exactTag))) == ERET_OK);

    // And a 65-byte key does get hashed, so the two must differ.
    const std::vector<uint8_t> overKey = repeated(0xAA, 65);
    uint8_t overTag[32];
    CHECK(CHmac::compute(EHASH_SHA256, spanOf(overKey), spanOf(ascii("boundary")),
                         SByteSpan(overTag, sizeof(overTag))) == ERET_OK);
    CHECK(std::memcmp(exactTag, overTag, 32) != 0);
}

TEST_CASE("CHmac: an empty key and an empty message are both legal") {
    const std::vector<uint8_t> empty;

    uint8_t tag[32];
    CHECK(CHmac::compute(EHASH_SHA256, SReadOnlyByteSpan(nullptr, 0),
                         SReadOnlyByteSpan(nullptr, 0),
                         SByteSpan(tag, sizeof(tag))) == ERET_OK);

    // HMAC with an empty key is HMAC with 64 zero bytes, so it is a well-defined value rather
    // than an error -- and it must differ from the same message under a non-empty key.
    uint8_t keyed[32];
    const std::vector<uint8_t> key = ascii("k");
    CHECK(CHmac::compute(EHASH_SHA256, spanOf(key), SReadOnlyByteSpan(nullptr, 0),
                         SByteSpan(keyed, sizeof(keyed))) == ERET_OK);
    CHECK(std::memcmp(tag, keyed, 32) != 0);
}

TEST_CASE("CHmac: finish() is a query, and re-keying reuses the instance") {
    const std::vector<uint8_t> key = repeated(0x0B, 20);
    const std::vector<uint8_t> message = ascii("Hi There");

    CHmac mac;
    REQUIRE(mac.reset(EHASH_SHA256, spanOf(key)) == ERET_OK);
    REQUIRE(mac.push(spanOf(message)) == message.size());

    // Like IHasher::finish(), calling it twice gives the same answer and absorption can
    // continue afterwards.
    uint8_t first[32];
    uint8_t second[32];
    REQUIRE(mac.finish(SByteSpan(first, sizeof(first))));
    REQUIRE(mac.finish(SByteSpan(second, sizeof(second))));
    CHECK(std::memcmp(first, second, 32) == 0);

    REQUIRE(mac.push(spanOf(ascii("!"))) == 1);
    uint8_t extended[32];
    REQUIRE(mac.finish(SByteSpan(extended, sizeof(extended))));
    CHECK(std::memcmp(first, extended, 32) != 0);

    // Re-keying the same instance starts a fresh message, and must give the same answer as a
    // freshly constructed one -- this is the path HKDF's expand loop takes per block.
    const std::vector<uint8_t> otherKey = ascii("Jefe");
    REQUIRE(mac.reset(EHASH_SHA256, spanOf(otherKey)) == ERET_OK);
    REQUIRE(mac.push(spanOf(ascii("what do ya want for nothing?")))
            == std::strlen("what do ya want for nothing?"));

    uint8_t rekeyed[32];
    REQUIRE(mac.finish(SByteSpan(rekeyed, sizeof(rekeyed))));

    const std::vector<uint8_t> expected =
        fromHex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    CHECK(std::memcmp(rekeyed, expected.data(), 32) == 0);

    // Switching algorithm on the same instance also works, and changes the tag length.
    REQUIRE(mac.reset(EHASH_SHA512, spanOf(key)) == ERET_OK);
    CHECK(mac.byteWidth() == 64);

    // A wrongly sized output is refused rather than truncated.
    uint8_t tooSmall[32];
    CHECK_FALSE(mac.finish(SByteSpan(tooSmall, sizeof(tooSmall))));
}

// HMAC-BLAKE2s: the generic RFC 2104 construction over BLAKE2s, which is what WireGuard's HKDF
// uses -- as opposed to BLAKE2's own keyed mode (CBlake2sMac), which is a different function and
// is what its MAC() uses. RFC 4231 publishes vectors for the SHA-2 family only, so these are the
// same RFC 4231 key/message pairs run through HMAC-BLAKE2s, with expected tags machine-generated
// from Python's hmac.new(key, msg, hashlib.blake2s) and cross-checked against an independent
// from-RFC-2104 implementation over an independent from-RFC-7693 BLAKE2s.
//
// Cases 6 and 7 carry the 131-byte key, which is longer than BLAKE2s's 64-byte block and so must
// be hashed down to 32 bytes first; that is the case a wrong block-size entry in blockBytesOf()
// would get wrong, and the only one that could not be caught by a round-trip.
TEST_CASE("CHmac: HMAC-BLAKE2s") {
    struct Vector {
        const char* key;
        const char* message;
        const char* tag;
    };

    static const Vector VECTORS[] = {
        // Case 1: 20-byte key, 8-byte message.
        { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
          "4869205468657265",
          "65a8b7c5cc9136d424e82c37e2707e74e913c0655b99c75f40edf387453a3260" },
        // Case 2: 4-byte key, 28-byte message.
        { "4a656665",
          "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
          "90b6281e2f3038c9056af0b4a7e763cae6fe5d9eb4386a0ec95237890c104ff0" },
        // Case 3: 20-byte key, 50-byte message.
        { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
          "dddd",
          "fcc4f59529502e34c3d8da3ffdab82966a2cb637ff5e9bd701135c2e9469e790" },
        // Case 4: 25-byte key, 50-byte message.
        { "0102030405060708090a0b0c0d0e0f10111213141516171819",
          "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
          "cdcd",
          "464434dcbece095d456a1d62d6ec56f898e625a39e5c52bdf94daf111bad83aa" },
        // Case 5: 20-byte key, 20-byte message.
        { "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
          "546573742057697468205472756e636174696f6e",
          "1825eff4619fb8b20833b9432892c81b64e8fcc3caef9ca55422f02e238c5ac9" },
        // Case 6: 131-byte key, 54-byte message.
        { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579"
          "204669727374",
          "d23d79394f53d536a096e6514447eeaabb05ded01be32c1937da6a8f7103bc4e" },
        // Case 7: 131-byte key, 152-byte message.
        { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b65"
          "7920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
          "647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c"
          "676f726974686d2e",
          "cb60f6a791f140bf8aa2e51ff358cdb2cc5c0333045b7fb77aba7ab3b0cfb237" },
        // Case 8: 0-byte key, 0-byte message.
        { "",
          "",
          "eaf4bb25938f4d20e72656bbbc7a9bf63c0c18537333c35bdb67db1402661acd" },
        // Case 9: 64-byte key, 26-byte message.
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
          "303132333435363738393a3b3c3d3e3f",
          "61206b6579206f662065786163746c79206f6e6520626c6f636b",
          "98c85d28d8da064f6cac1f8288be88c280d06a1c7b993bde016efad7458a5494" },
        // Case 10: 65-byte key, 27-byte message.
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
          "303132333435363738393a3b3c3d3e3f40",
          "61206b6579206f66206f6e6520626c6f636b20706c7573206f6e65",
          "e15cfd42ba5006e67cc58b1224162027ad152ddf3a91da964fa1bf94cb9d8979" },
    };

    for (const Vector& v : VECTORS) {
        const std::vector<uint8_t> key = fromHex(v.key);
        const std::vector<uint8_t> message = fromHex(v.message);
        CAPTURE(key.size());
        CAPTURE(message.size());

        checkVector(EHASH_BLAKE2S, key, message, v.tag);
    }

    // The tag is BLAKE2s's own 32 bytes, and HKDF over it works -- which is the thing WireGuard
    // actually needs from this.
    CHmac mac;
    REQUIRE(mac.reset(EHASH_BLAKE2S, spanOf(ascii("key"))) == ERET_OK);
    CHECK(mac.byteWidth() == 32);
    CHECK(CHkdf::maxExpandBytes(EHASH_BLAKE2S) == 255 * 32);

    uint8_t pseudoKey[32];
    REQUIRE(CHkdf::extract(
        EHASH_BLAKE2S, spanOf(ascii("salt")), spanOf(ascii("ikm")),
        SByteSpan(pseudoKey, sizeof(pseudoKey))) == ERET_OK);

    // HKDF-Extract is HMAC with the salt as the key, so it must be exactly that.
    uint8_t viaHmac[32];
    REQUIRE(CHmac::compute(
        EHASH_BLAKE2S, spanOf(ascii("salt")), spanOf(ascii("ikm")),
        SByteSpan(viaHmac, sizeof(viaHmac))) == ERET_OK);
    CHECK(std::memcmp(pseudoKey, viaHmac, 32) == 0);

    uint8_t okm[80];
    REQUIRE(CHkdf::expand(
        EHASH_BLAKE2S, SReadOnlyByteSpan(pseudoKey, sizeof(pseudoKey)),
        spanOf(ascii("info")), SByteSpan(okm, sizeof(okm))) == ERET_OK);
}
