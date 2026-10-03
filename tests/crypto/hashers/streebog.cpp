#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/hashers/streebog256.hpp>
#include <certpp/crypto/hashers/streebog512.hpp>
#include <certpp/crypto/hmac.hpp>
#include <cstring>
#include <string>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    /* Converts a computed digest to lowercase hex, for comparing against the RFCs' vectors. */
    std::string toHex(const uint8_t* data, size_t size) {
        static const char* digits = "0123456789abcdef";
        std::string out;
        out.reserve(size * 2);
        for (size_t i = 0; i < size; ++i) {
            out.push_back(digits[data[i] >> 4]);
            out.push_back(digits[data[i] & 0xF]);
        }
        return out;
    }

    std::vector<uint8_t> fromHex(const std::string& hex) {
        std::vector<uint8_t> out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            auto nibble = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return uint8_t(c - '0');
                if (c >= 'a' && c <= 'f') return uint8_t(c - 'a' + 10);
                return uint8_t(c - 'A' + 10);
            };
            out.push_back(uint8_t((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
        }
        return out;
    }

    template <typename THasher>
    std::string digestOf(const std::vector<uint8_t>& message, size_t chunk = 0) {
        THasher hasher;

        if (chunk == 0) {
            hasher.push(SReadOnlyByteSpan(message.data(), message.size()));
        }

        else {
            for (size_t off = 0; off < message.size(); off += chunk) {
                const size_t take = (message.size() - off < chunk) ? (message.size() - off) : chunk;
                hasher.push(SReadOnlyByteSpan(message.data() + off, take));
            }
        }

        std::vector<uint8_t> out(hasher.byteWidth());
        REQUIRE(hasher.finish(SByteSpan(out.data(), out.size())));
        return toHex(out.data(), out.size());
    }

    /* RFC 6986 section 10.1's M1. The RFC prints a V_512 vector most-significant-byte-first,
     * which is the reverse of stream order, so M1 as a byte stream is this ASCII string -- a
     * fact worth stating in the test, since it's the clearest available evidence that the
     * byte order here is the right way round. */
    const char* M1_TEXT = "012345678901234567890123456789012345678901234567890123456789012";

    std::vector<uint8_t> m1() {
        return std::vector<uint8_t>(M1_TEXT, M1_TEXT + std::strlen(M1_TEXT));
    }

    /* RFC 6986 section 10.2's M2, likewise as a byte stream: the CP1251 encoding of a line from
     * "The Tale of Igor's Campaign". 72 bytes, so it exercises one full block plus a tail. */
    std::vector<uint8_t> m2() {
        return fromHex(
            "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20"
            "f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb"
            "20c8e3eef0e5e2fb");
    }
}

/* RFC 6986's own two example messages, both digest lengths. The published hex is the reverse of
 * these values, byte for byte: the RFC writes a V_512 vector most-significant-byte-first while
 * every implementation emits the digest the other way round. Both messages are hashed here in
 * stream order, which is what makes these the values an interoperating implementation produces.
 *
 * The 512-bit M1 digest below is also independently published for the ASCII string M1 spells
 * out, which is the cross-check that the orientation is right rather than merely self-consistent.
 */
TEST_CASE("Streebog-512 matches RFC 6986's example messages") {
    CHECK(digestOf<Streebog512>(m1()) ==
        "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa"
        "00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48");
}

TEST_CASE("Streebog-256 matches RFC 6986's example messages") {
    CHECK(digestOf<Streebog256>(m1()) ==
        "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");
}

/* Locks in that the 256-bit digest is a differently-seeded computation, not a cut of the
 * 512-bit one: RFC 6986 section 6.1 gives it IV = (00000001)^64 instead of 0^512. If reset()
 * used the 512-bit IV, this digest would equal the upper half of the 512-bit digest above --
 * which the two values plainly don't. */
TEST_CASE("Streebog-256 is not a truncation of Streebog-512") {
    const std::string h512 = digestOf<Streebog512>(m1());
    const std::string h256 = digestOf<Streebog256>(m1());

    CHECK(h256 != h512.substr(64));
    CHECK(h256 != h512.substr(0, 64));
}

TEST_CASE("Streebog matches RFC 6986's second example message (one full block plus a tail)") {
    CHECK(digestOf<Streebog512>(m2()) ==
        "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376"
        "035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28");

    CHECK(digestOf<Streebog256>(m2()) ==
        "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50");
}

/* The empty message, whose digests are the most widely published Streebog vectors there are.
 * It also exercises the padded-empty-block path on its own. */
TEST_CASE("Streebog matches the published empty-message digests") {
    CHECK(digestOf<Streebog512>(std::vector<uint8_t>()) ==
        "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7"
        "362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a");

    CHECK(digestOf<Streebog256>(std::vector<uint8_t>()) ==
        "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb");
}

TEST_CASE("Streebog byteWidth matches the digest length") {
    CHECK(Streebog256().byteWidth() == 32);
    CHECK(Streebog512().byteWidth() == 64);
}

TEST_CASE("Streebog is insensitive to how input is chunked across push() calls") {
    const std::vector<uint8_t> msg = m2();
    const std::string want512 = digestOf<Streebog512>(msg);
    const std::string want256 = digestOf<Streebog256>(msg);

    for (size_t chunk : { size_t(1), size_t(7), size_t(31), size_t(63), size_t(64), size_t(65) }) {
        CAPTURE(chunk);
        CHECK(digestOf<Streebog512>(msg, chunk) == want512);
        CHECK(digestOf<Streebog256>(msg, chunk) == want256);
    }
}

/* RFC 9385 appendix A.1.1 steps (2)/(9)/(15)/(16): SKEYSEED = HMAC_GOSTR3411_2012_512 over a
 * 64-byte key and 64-byte data, so both the inner and the outer hash see exactly 128 bytes.
 * That is the one message length where Streebog could silently differ -- an exact multiple of
 * the block size still gets a padded, entirely empty final block, because RFC 6986 step 2.1's
 * loop exits on |M| < 512 and |M| == 0 satisfies that. No vector in RFC 6986 reaches this case.
 *
 * It doubles as the check that CHmac::blockBytesOf() reports B = 64 for Streebog (RFC 7836
 * sections 4.1.1/4.1.2) rather than the 128 SHA-512 uses. */
TEST_CASE("Streebog-512 handles an exact multiple of the block size (RFC 9385 SKEYSEED)") {
    const std::vector<uint8_t> ni = fromHex(
        "48b6d3b3ab56f2c8f042d516e721d931f9ac10f97f808c512bd6f45993a74d13");
    const std::vector<uint8_t> nr = fromHex(
        "fb81c880e5f0356099ef46b27244950f0385f4739267b768438f906916fe63f0");
    const std::vector<uint8_t> shared = fromHex(
        "a2436cbd2dc10f810df76f24ae7870f2275d1bdcc5520ed853e5c54398f735ce"
        "3270892b8e890b7db39877cdbd315d18105d8bac16f0aafdbcdc7c69751448a8");

    std::vector<uint8_t> key(ni);
    key.insert(key.end(), nr.begin(), nr.end());
    REQUIRE(key.size() == 64);

    CHECK(CHmac::blockBytesOf(EHASH_STREEBOG512) == 64);
    CHECK(CHmac::blockBytesOf(EHASH_STREEBOG256) == 64);

    CHmac hmac;
    REQUIRE(hmac.reset(EHASH_STREEBOG512, SReadOnlyByteSpan(key.data(), key.size())) == ERET_OK);
    REQUIRE(hmac.push(SReadOnlyByteSpan(shared.data(), shared.size())) == shared.size());

    std::vector<uint8_t> mac(hmac.byteWidth());
    REQUIRE(mac.size() == 64);
    REQUIRE(hmac.finish(SByteSpan(mac.data(), mac.size())));

    CHECK(toHex(mac.data(), mac.size()) ==
        "fc7bd9804b150060d208173a084ba92a0f01cbc3efe9b5aa155b0e8024683c4c"
        "6cfbe9c8167d542d48ee61710168ca684f7cb01b6129209a68885b3fd7190bd0");
}

TEST_CASE("Streebog is reachable through IHasher::create()") {
    IHasherPtr hasher;

    REQUIRE(IHasher::create(EHASH_STREEBOG256, hasher) == ERET_OK);
    REQUIRE(hasher);
    CHECK(hasher->byteWidth() == 32);

    REQUIRE(IHasher::create(EHASH_STREEBOG512, hasher) == ERET_OK);
    REQUIRE(hasher);
    CHECK(hasher->byteWidth() == 64);
}
