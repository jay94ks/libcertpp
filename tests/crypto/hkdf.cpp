// HKDF (RFC 5869), against the test vectors in its Appendix A.
//
// All three SHA-256 cases are here (A.1 basic, A.2 longer inputs, A.3 empty salt and info), plus
// the SHA-1 cases A.4 through A.6. A.3 and A.6 are the ones where the salt is absent rather than
// supplied, which is what distinguishes "no salt" from "a salt of zero bytes" -- RFC 5869 2.2
// says they are the same thing, and a separate check below pins that.
//
// These vectors are the only thing that catches the two errors worth worrying about: extract()
// taking the salt as the message rather than the HMAC key, and expand() failing to chain each
// output block into the next. Both produce output that is internally consistent and matches no
// other implementation.

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

    SReadOnlyByteSpan spanOf(const std::vector<uint8_t>& v) {
        return v.empty() ? SReadOnlyByteSpan(nullptr, 0)
                         : SReadOnlyByteSpan(v.data(), v.size());
    }

    struct Vector {
        const char* name;
        EHashers alg;
        const char* ikm;
        const char* salt;
        const char* info;
        size_t length;
        const char* prk;
        const char* okm;
    };

    void checkVector(const Vector& v) {
        const std::vector<uint8_t> ikm = fromHex(v.ikm);
        const std::vector<uint8_t> salt = fromHex(v.salt);
        const std::vector<uint8_t> info = fromHex(v.info);
        const std::vector<uint8_t> expectedPrk = fromHex(v.prk);
        const std::vector<uint8_t> expectedOkm = fromHex(v.okm);

        REQUIRE(expectedOkm.size() == v.length);

        // extract() alone must reproduce the RFC's PRK -- the step where the salt/IKM argument
        // order matters.
        std::vector<uint8_t> prk(expectedPrk.size());
        REQUIRE(CHkdf::extract(
            v.alg, spanOf(salt), spanOf(ikm),
            SByteSpan(prk.data(), prk.size())) == ERET_OK);
        CHECK(prk == expectedPrk);

        // expand() from the RFC's own PRK, so a failure here is expand's and not extract's.
        std::vector<uint8_t> okm(v.length);
        REQUIRE(CHkdf::expand(
            v.alg, spanOf(expectedPrk), spanOf(info),
            SByteSpan(okm.data(), okm.size())) == ERET_OK);
        CHECK(okm == expectedOkm);

        // And the two together.
        std::vector<uint8_t> derived(v.length);
        REQUIRE(CHkdf::derive(
            v.alg, spanOf(salt), spanOf(ikm), spanOf(info),
            SByteSpan(derived.data(), derived.size())) == ERET_OK);
        CHECK(derived == expectedOkm);
    }
}

// RFC 5869 A.1: basic SHA-256 case.
TEST_CASE("CHkdf: RFC 5869 A.1, SHA-256 basic") {
    checkVector({
        "A.1", EHASH_SHA256,
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        42,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    });
}

// RFC 5869 A.2: longer inputs and output -- 80 bytes of IKM, salt and info, and an 82-byte OKM,
// which takes three expand blocks and so actually exercises the chaining.
TEST_CASE("CHkdf: RFC 5869 A.2, SHA-256 with longer inputs") {
    checkVector({
        "A.2", EHASH_SHA256,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        82,
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87"
    });
}

// RFC 5869 A.3: zero-length salt and info. The salt being absent means HKDF substitutes HashLen
// zero bytes, which is specified behaviour rather than an edge case to guess at.
TEST_CASE("CHkdf: RFC 5869 A.3, SHA-256 with empty salt and info") {
    checkVector({
        "A.3", EHASH_SHA256,
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "",
        "",
        42,
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    });

    // An empty salt and a salt of HashLen zero bytes must derive the same PRK -- that is what
    // RFC 5869 2.2 means by "if not provided", and it is worth pinning rather than inferring.
    const std::vector<uint8_t> ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const std::vector<uint8_t> zeros(32, 0x00);

    uint8_t withEmpty[32];
    uint8_t withZeros[32];
    REQUIRE(CHkdf::extract(EHASH_SHA256, SReadOnlyByteSpan(nullptr, 0), spanOf(ikm),
                           SByteSpan(withEmpty, sizeof(withEmpty))) == ERET_OK);
    REQUIRE(CHkdf::extract(EHASH_SHA256, spanOf(zeros), spanOf(ikm),
                           SByteSpan(withZeros, sizeof(withZeros))) == ERET_OK);
    CHECK(std::memcmp(withEmpty, withZeros, 32) == 0);
}

// RFC 5869 A.4 through A.6: the SHA-1 cases, which exercise a different digest length and so a
// different number of expand blocks for the same output size.
TEST_CASE("CHkdf: RFC 5869 A.4 through A.6, SHA-1") {
    checkVector({
        "A.4", EHASH_SHA1,
        "0b0b0b0b0b0b0b0b0b0b0b",
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        42,
        "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
        "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2"
        "c22e422478d305f3f896"
    });

    checkVector({
        "A.5", EHASH_SHA1,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        82,
        "8adae09a2a307059478d309b26c4115a224cfaf6",
        "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe"
        "8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e"
        "927336d0441f4c4300e2cff0d0900b52d3b4"
    });

    checkVector({
        "A.6", EHASH_SHA1,
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "",
        "",
        42,
        "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
        "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0"
        "ea00033de03984d34918"
    });
}

TEST_CASE("CHkdf: the limits and refusals") {
    const std::vector<uint8_t> ikm(32, 0x42);
    const std::vector<uint8_t> prk(32, 0x43);

    // 255 blocks is the ceiling, because the counter is a single byte.
    CHECK(CHkdf::maxExpandBytes(EHASH_SHA256) == 255 * 32);
    CHECK(CHkdf::maxExpandBytes(EHASH_SHA512) == 255 * 64);
    CHECK(CHkdf::maxExpandBytes(EHASH_SHAKE256) == 0);

    std::vector<uint8_t> atLimit(255 * 32);
    CHECK(CHkdf::expand(EHASH_SHA256, spanOf(prk), SReadOnlyByteSpan(nullptr, 0),
                        SByteSpan(atLimit.data(), atLimit.size())) == ERET_OK);

    std::vector<uint8_t> pastLimit(255 * 32 + 1);
    CHECK(CHkdf::expand(EHASH_SHA256, spanOf(prk), SReadOnlyByteSpan(nullptr, 0),
                        SByteSpan(pastLimit.data(), pastLimit.size())) == ERET_BADREQ);

    // RFC 5869 2.3 requires a PRK of at least HashLen bytes.
    const std::vector<uint8_t> shortPrk(31, 0x43);
    std::vector<uint8_t> out(32);
    CHECK(CHkdf::expand(EHASH_SHA256, spanOf(shortPrk), SReadOnlyByteSpan(nullptr, 0),
                        SByteSpan(out.data(), out.size())) == ERET_BADREQ);

    // Zero-length output is a caller error rather than a no-op, since it almost certainly means
    // a length was computed wrongly.
    CHECK(CHkdf::expand(EHASH_SHA256, spanOf(prk), SReadOnlyByteSpan(nullptr, 0),
                        SByteSpan(out.data(), 0)) == ERET_BADREQ);

    // Hashes HMAC is not defined over propagate the refusal rather than guessing.
    CHECK(CHkdf::extract(EHASH_SHAKE256, SReadOnlyByteSpan(nullptr, 0), spanOf(ikm),
                         SByteSpan(out.data(), out.size())) == ERET_NOTSUP);
    CHECK(CHkdf::derive(EHASH_SHAKE128, SReadOnlyByteSpan(nullptr, 0), spanOf(ikm),
                        SReadOnlyByteSpan(nullptr, 0),
                        SByteSpan(out.data(), out.size())) == ERET_NOTSUP);

    // extract()'s output is exactly HashLen; anything else is refused rather than truncated.
    CHECK(CHkdf::extract(EHASH_SHA256, SReadOnlyByteSpan(nullptr, 0), spanOf(ikm),
                         SByteSpan(out.data(), 31)) == ERET_NOSPC);
}

// The property cskcwk depends on: distinct info labels from one shared secret give unrelated
// keys. If they did not, a protocol deriving a key per direction would get the same key twice,
// and a record could be reflected back at its sender.
TEST_CASE("CHkdf: distinct info labels derive unrelated output") {
    const std::vector<uint8_t> secret(32, 0x5A);
    const std::vector<uint8_t> salt(32, 0xA5);

    auto deriveWith = [&](const char* label) {
        std::vector<uint8_t> info;
        for (const char* p = label; *p; ++p) {
            info.push_back(uint8_t(*p));
        }

        std::vector<uint8_t> out(44);   // 32-byte key plus a 12-byte nonce prefix
        REQUIRE(CHkdf::derive(EHASH_SHA256, spanOf(salt), spanOf(secret), spanOf(info),
                              SByteSpan(out.data(), out.size())) == ERET_OK);
        return out;
    };

    const std::vector<uint8_t> clientToServer = deriveWith("cskcwk c2s");
    const std::vector<uint8_t> serverToClient = deriveWith("cskcwk s2c");

    CHECK(clientToServer != serverToClient);

    // And the same label is reproducible, which is what lets both ends derive independently.
    CHECK(deriveWith("cskcwk c2s") == clientToServer);

    // A one-character change in the label changes everything, not just a suffix.
    const std::vector<uint8_t> nearby = deriveWith("cskcwk c2S");
    CHECK(nearby != clientToServer);

    size_t sharedPrefix = 0;
    while (sharedPrefix < nearby.size() && nearby[sharedPrefix] == clientToServer[sharedPrefix]) {
        ++sharedPrefix;
    }
    CHECK(sharedPrefix < 4);

    // A shorter request must be a prefix of a longer one -- the blocks are a stream, so asking
    // for fewer bytes gives the same leading bytes. cskcwk relies on this when it derives a key
    // and nonce prefix from one call.
    std::vector<uint8_t> shorter(16);
    const std::vector<uint8_t> info = { 'c', 's', 'k', 'c', 'w', 'k', ' ', 'c', '2', 's' };
    REQUIRE(CHkdf::derive(EHASH_SHA256, spanOf(salt), spanOf(secret), spanOf(info),
                          SByteSpan(shorter.data(), shorter.size())) == ERET_OK);
    CHECK(std::memcmp(shorter.data(), clientToServer.data(), 16) == 0);
}
