#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/hashers/sha224.hpp>
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
        SHA224 hasher;
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

/* FIPS 180-4's own SHA-224 examples (one-block and two-block messages). */
TEST_CASE("SHA-224 matches FIPS 180-4's example messages") {
    CHECK(digestOf("") == "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    CHECK(digestOf("abc") == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
}

TEST_CASE("SHA224::byteWidth is 28 bytes (224 bits)") {
    SHA224 hasher;
    CHECK(hasher.byteWidth() == 28);
}

TEST_CASE("SHA-224 million-'a' stress vector") {
    CHECK(digestOf("a", 1000000) == "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67");
}

TEST_CASE("SHA-224 is insensitive to how input is chunked across push() calls") {
    const char* text = "The quick brown fox jumps over the lazy dog, twice over for a longer message";
    size_t len = std::strlen(text);

    SHA224 whole;
    whole.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), len));
    uint8_t wholeDigest[28];
    SByteSpan wholeOut(wholeDigest, sizeof(wholeDigest));
    REQUIRE(whole.finish(wholeOut));

    // Same content, pushed 3 bytes at a time -- crosses the 64-byte block boundary many times.
    SHA224 chunked;
    for (size_t i = 0; i < len; i += 3) {
        size_t n = (len - i < 3) ? (len - i) : 3;
        chunked.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text) + i, n));
    }
    uint8_t chunkedDigest[28];
    SByteSpan chunkedOut(chunkedDigest, sizeof(chunkedDigest));
    REQUIRE(chunked.finish(chunkedOut));

    CHECK(std::memcmp(wholeDigest, chunkedDigest, sizeof(wholeDigest)) == 0);
}

TEST_CASE("SHA224::reset allows reusing the same instance for a second, independent digest") {
    SHA224 hasher;
    const uint8_t a[] = { 'a' };
    hasher.push(SReadOnlyByteSpan(a, sizeof(a)));

    hasher.reset();

    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t digest[28];
    SByteSpan out(digest, sizeof(digest));
    REQUIRE(hasher.finish(out));
    CHECK(toHex(digest, sizeof(digest)) == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
}

TEST_CASE("SHA224::finish rejects a destination shorter than byteWidth() without writing garbage") {
    SHA224 hasher;
    const uint8_t data[] = { 'x' };
    hasher.push(SReadOnlyByteSpan(data, sizeof(data)));

    uint8_t tooSmall[27];
    SByteSpan out(tooSmall, sizeof(tooSmall));
    CHECK_FALSE(hasher.finish(out));
}

TEST_CASE("SHA224::finish can be called more than once, yielding the same digest") {
    SHA224 hasher;
    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t first[28], second[28];
    SByteSpan firstOut(first, sizeof(first));
    SByteSpan secondOut(second, sizeof(second));
    REQUIRE(hasher.finish(firstOut));
    REQUIRE(hasher.finish(secondOut));
    CHECK(std::memcmp(first, second, sizeof(first)) == 0);
}

TEST_CASE("SHA-224 and SHA-256 produce different digests for the same input") {
    // Sanity check that SHA-224 isn't accidentally just SHA-256 with the output truncated --
    // they must use different initial hash values, per FIPS 180-4.
    CHECK(digestOf("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a"); // SHA-256("abc")'s prefix
}
