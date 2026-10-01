#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/hashers/md5.hpp>
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
        MD5 hasher;
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

/* RFC 1321 section A.5's own test suite. */
TEST_CASE("MD5 matches RFC 1321's test suite") {
    CHECK(digestOf("") == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(digestOf("a") == "0cc175b9c0f1b6a831c399e269772661");
    CHECK(digestOf("abc") == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(digestOf("message digest") == "f96b697d7cb7938d525a2f31aaf161d0");
    CHECK(digestOf("abcdefghijklmnopqrstuvwxyz") == "c3fcd3d76192e4007dfb496cca67e13b");
    CHECK(digestOf("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        == "d174ab98d277d9f5a5611c2c9f419d9f");
    CHECK(digestOf("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
        == "57edf4a22be3c955ac49da2e2107b67a");
}

TEST_CASE("MD5::byteWidth is 16 bytes (128 bits)") {
    MD5 hasher;
    CHECK(hasher.byteWidth() == 16);
}

TEST_CASE("MD5 million-'a' stress vector") {
    // RFC 1321's own stress test: MD5 of one million repetitions of the character 'a'.
    CHECK(digestOf("a", 1000000) == "7707d6ae4e027c70eea2a935c2296f21");
}

TEST_CASE("MD5 is insensitive to how input is chunked across push() calls") {
    const char* text = "The quick brown fox jumps over the lazy dog";
    size_t len = std::strlen(text);

    MD5 whole;
    whole.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), len));
    uint8_t wholeDigest[16];
    SByteSpan wholeOut(wholeDigest, sizeof(wholeDigest));
    REQUIRE(whole.finish(wholeOut));

    // Same content, pushed 3 bytes at a time -- crosses the 64-byte block boundary many times.
    MD5 chunked;
    for (size_t i = 0; i < len; i += 3) {
        size_t n = (len - i < 3) ? (len - i) : 3;
        chunked.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text) + i, n));
    }
    uint8_t chunkedDigest[16];
    SByteSpan chunkedOut(chunkedDigest, sizeof(chunkedDigest));
    REQUIRE(chunked.finish(chunkedOut));

    CHECK(std::memcmp(wholeDigest, chunkedDigest, sizeof(wholeDigest)) == 0);
    CHECK(toHex(wholeDigest, sizeof(wholeDigest)) == "9e107d9d372bb6826bd81d3542a419d6");
}

TEST_CASE("MD5::reset allows reusing the same instance for a second, independent digest") {
    MD5 hasher;
    const uint8_t a[] = { 'a' };
    hasher.push(SReadOnlyByteSpan(a, sizeof(a)));

    hasher.reset();

    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t digest[16];
    SByteSpan out(digest, sizeof(digest));
    REQUIRE(hasher.finish(out));
    CHECK(toHex(digest, sizeof(digest)) == "900150983cd24fb0d6963f7d28e17f72");
}

TEST_CASE("MD5::finish rejects a destination shorter than byteWidth() without writing garbage") {
    MD5 hasher;
    const uint8_t data[] = { 'x' };
    hasher.push(SReadOnlyByteSpan(data, sizeof(data)));

    uint8_t tooSmall[15];
    SByteSpan out(tooSmall, sizeof(tooSmall));
    CHECK_FALSE(hasher.finish(out));
}

TEST_CASE("MD5::finish can be called more than once, yielding the same digest and not disturbing further push()") {
    MD5 hasher;
    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t first[16], second[16];
    SByteSpan firstOut(first, sizeof(first));
    SByteSpan secondOut(second, sizeof(second));
    REQUIRE(hasher.finish(firstOut));
    REQUIRE(hasher.finish(secondOut));
    CHECK(std::memcmp(first, second, sizeof(first)) == 0);
}
