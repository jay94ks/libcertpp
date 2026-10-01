#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/hashers/sha256.hpp>
#include <cstring>
#include <string>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    /* Converts a computed digest to lowercase hex, for comparing against textbook test vectors. */
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

    /* Pushes text (once per repeat) into a fresh hasher and returns the digest as lowercase hex. */
    std::string digestOf(const char* text, size_t repeat = 1) {
        SHA256 hasher;
        SReadOnlyByteSpan span(reinterpret_cast<const uint8_t*>(text), std::strlen(text));

        for (size_t i = 0; i < repeat; ++i) {
            hasher.push(span);
        }

        std::vector<uint8_t> out(hasher.byteWidth());
        SByteSpan outSpan(out.data(), out.size());
        REQUIRE(hasher.finish(outSpan));
        return toHex(out.data(), out.size());
    }
}

/* FIPS 180-4's own SHA-256 examples (one-block and two-block messages). */
TEST_CASE("SHA-256 matches FIPS 180-4's example messages") {
    CHECK(digestOf("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(digestOf("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(digestOf("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("SHA256::byteWidth is 32 bytes (256 bits)") {
    SHA256 hasher;
    CHECK(hasher.byteWidth() == 32);
}

TEST_CASE("SHA-256 million-'a' stress vector from FIPS 180-4") {
    CHECK(digestOf("a", 1000000) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST_CASE("SHA-256 is insensitive to how input is chunked across push() calls") {
    const char* text = "The quick brown fox jumps over the lazy dog";
    size_t len = std::strlen(text);

    SHA256 whole;
    whole.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), len));
    uint8_t wholeDigest[32];
    SByteSpan wholeOut(wholeDigest, sizeof(wholeDigest));
    REQUIRE(whole.finish(wholeOut));

    SHA256 chunked;
    for (size_t i = 0; i < len; i += 3) {
        size_t n = (len - i < 3) ? (len - i) : 3;
        chunked.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text) + i, n));
    }
    uint8_t chunkedDigest[32];
    SByteSpan chunkedOut(chunkedDigest, sizeof(chunkedDigest));
    REQUIRE(chunked.finish(chunkedOut));

    CHECK(std::memcmp(wholeDigest, chunkedDigest, sizeof(wholeDigest)) == 0);
    CHECK(toHex(wholeDigest, sizeof(wholeDigest)) == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
}

TEST_CASE("SHA256::reset allows reusing the same instance for a second, independent digest") {
    SHA256 hasher;
    const uint8_t a[] = { 'a' };
    hasher.push(SReadOnlyByteSpan(a, sizeof(a)));

    hasher.reset();

    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t digest[32];
    SByteSpan out(digest, sizeof(digest));
    REQUIRE(hasher.finish(out));
    CHECK(toHex(digest, sizeof(digest)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("SHA256::finish rejects a destination shorter than byteWidth() without writing garbage") {
    SHA256 hasher;
    const uint8_t data[] = { 'x' };
    hasher.push(SReadOnlyByteSpan(data, sizeof(data)));

    uint8_t tooSmall[31];
    SByteSpan out(tooSmall, sizeof(tooSmall));
    CHECK_FALSE(hasher.finish(out));
}

TEST_CASE("SHA256::finish can be called more than once, yielding the same digest") {
    SHA256 hasher;
    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t first[32], second[32];
    SByteSpan firstOut(first, sizeof(first));
    SByteSpan secondOut(second, sizeof(second));
    REQUIRE(hasher.finish(firstOut));
    REQUIRE(hasher.finish(secondOut));
    CHECK(std::memcmp(first, second, sizeof(first)) == 0);
}
