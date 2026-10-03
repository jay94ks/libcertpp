#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/hashers/md4.hpp>
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
        MD4 hasher;
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

/* RFC 1320 section A.5's own test suite. */
TEST_CASE("MD4 matches RFC 1320's test suite") {
    CHECK(digestOf("") == "31d6cfe0d16ae931b73c59d7e0c089c0");
    CHECK(digestOf("a") == "bde52cb31de33e46245e05fbdbd6fb24");
    CHECK(digestOf("abc") == "a448017aaf21d8525fc10ae87aa6729d");
    CHECK(digestOf("message digest") == "d9130a8164549fe818874806e1c7014b");
    CHECK(digestOf("abcdefghijklmnopqrstuvwxyz") == "d79e1c308aa5bbcdeea8ed63df412da9");
    CHECK(digestOf("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        == "043f8582f241db351ce627e153e7f0e4");
    CHECK(digestOf("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
        == "e33b4ddc9c38f2199c3e7b164fcc0536");
}

TEST_CASE("MD4::byteWidth is 16 bytes (128 bits)") {
    MD4 hasher;
    CHECK(hasher.byteWidth() == 16);
}

TEST_CASE("MD4 million-'a' stress vector") {
    // RFC 1320's own stress test: MD4 of one million repetitions of the character 'a'.
    CHECK(digestOf("a", 1000000) == "bbce80cc6bb65e5c6745e30d4eeca9a4");
}

/* The reason MD4 is in this library at all: NTLM and EAP-MSCHAPv2 define the NT hash as MD4 of
 * the UTF-16LE encoding of the password. This vector is the one every MSCHAPv2 implementation
 * cites, so it doubles as a check that MD4 here is the MD4 those protocols mean. */
TEST_CASE("MD4 produces the documented NT hash of \"password\"") {
    const uint8_t utf16le[] = {
        'p', 0, 'a', 0, 's', 0, 's', 0, 'w', 0, 'o', 0, 'r', 0, 'd', 0
    };

    MD4 hasher;
    hasher.push(SReadOnlyByteSpan(utf16le, sizeof(utf16le)));

    uint8_t digest[16];
    SByteSpan out(digest, sizeof(digest));
    REQUIRE(hasher.finish(out));
    CHECK(toHex(digest, sizeof(digest)) == "8846f7eaee8fb117ad06bdd830b7586c");
}

TEST_CASE("MD4 is insensitive to how input is chunked across push() calls") {
    const char* text = "The quick brown fox jumps over the lazy dog";
    size_t len = std::strlen(text);

    MD4 whole;
    whole.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), len));
    uint8_t wholeDigest[16];
    SByteSpan wholeOut(wholeDigest, sizeof(wholeDigest));
    REQUIRE(whole.finish(wholeOut));

    // Same content, pushed 3 bytes at a time -- crosses the 64-byte block boundary many times.
    MD4 chunked;
    for (size_t i = 0; i < len; i += 3) {
        size_t n = (len - i < 3) ? (len - i) : 3;
        chunked.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text) + i, n));
    }
    uint8_t chunkedDigest[16];
    SByteSpan chunkedOut(chunkedDigest, sizeof(chunkedDigest));
    REQUIRE(chunked.finish(chunkedOut));

    CHECK(std::memcmp(wholeDigest, chunkedDigest, sizeof(wholeDigest)) == 0);
    CHECK(toHex(wholeDigest, sizeof(wholeDigest)) == "1bee69a46ba811185c194762abaeae90");
}

/* Lengths either side of a block boundary and of the 56-byte padding threshold, where a message
 * needs a whole extra block for its length field. One-byte chunking has to agree with one shot at
 * every one of them. */
TEST_CASE("MD4 agrees with itself across the block and padding boundaries") {
    std::vector<uint8_t> data(200);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = uint8_t(i * 37 + 11);
    }

    for (size_t len : { size_t(0), size_t(1), size_t(55), size_t(56), size_t(57),
                        size_t(63), size_t(64), size_t(65), size_t(119), size_t(120),
                        size_t(128), size_t(200) }) {
        MD4 whole;
        whole.push(SReadOnlyByteSpan(data.data(), len));
        uint8_t a[16];
        SByteSpan aOut(a, sizeof(a));
        REQUIRE(whole.finish(aOut));

        MD4 byByte;
        for (size_t i = 0; i < len; ++i) {
            byByte.push(SReadOnlyByteSpan(data.data() + i, 1));
        }
        uint8_t b[16];
        SByteSpan bOut(b, sizeof(b));
        REQUIRE(byByte.finish(bOut));

        CHECK(std::memcmp(a, b, sizeof(a)) == 0);
    }
}

TEST_CASE("MD4::reset allows reusing the same instance for a second, independent digest") {
    MD4 hasher;
    const uint8_t a[] = { 'a' };
    hasher.push(SReadOnlyByteSpan(a, sizeof(a)));

    hasher.reset();

    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t digest[16];
    SByteSpan out(digest, sizeof(digest));
    REQUIRE(hasher.finish(out));
    CHECK(toHex(digest, sizeof(digest)) == "a448017aaf21d8525fc10ae87aa6729d");
}

TEST_CASE("MD4::finish rejects a destination shorter than byteWidth() without writing garbage") {
    MD4 hasher;
    const uint8_t data[] = { 'x' };
    hasher.push(SReadOnlyByteSpan(data, sizeof(data)));

    uint8_t tooSmall[15];
    SByteSpan out(tooSmall, sizeof(tooSmall));
    CHECK_FALSE(hasher.finish(out));
}

TEST_CASE("MD4::finish can be called more than once, yielding the same digest") {
    MD4 hasher;
    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t first[16], second[16];
    SByteSpan firstOut(first, sizeof(first));
    SByteSpan secondOut(second, sizeof(second));
    REQUIRE(hasher.finish(firstOut));
    REQUIRE(hasher.finish(secondOut));
    CHECK(std::memcmp(first, second, sizeof(first)) == 0);
}

/* MD4 differs from MD5 in its round functions, shift table and word order, so a transposition in
 * any of those would still produce a 16-byte digest -- it would just be the wrong one, and quite
 * possibly MD5's. This pins the two apart. */
TEST_CASE("MD4 is reachable through IHasher::create and is not MD5") {
    IHasherPtr md4;
    IHasherPtr md5;
    REQUIRE(IHasher::create(EHASH_MD4, md4) == ERET_OK);
    REQUIRE(IHasher::create(EHASH_MD5, md5) == ERET_OK);
    REQUIRE(md4);
    REQUIRE(md5);
    CHECK(md4->byteWidth() == 16);

    const char* text = "abc";
    SReadOnlyByteSpan span(reinterpret_cast<const uint8_t*>(text), std::strlen(text));
    md4->push(span);
    md5->push(span);

    uint8_t a[16], b[16];
    SByteSpan aOut(a, sizeof(a));
    SByteSpan bOut(b, sizeof(b));
    REQUIRE(md4->finish(aOut));
    REQUIRE(md5->finish(bOut));

    CHECK(toHex(a, sizeof(a)) == "a448017aaf21d8525fc10ae87aa6729d");
    CHECK(std::memcmp(a, b, sizeof(a)) != 0);
}
