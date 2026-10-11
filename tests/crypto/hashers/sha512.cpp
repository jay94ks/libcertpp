#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/hashers/sha512.hpp>
#include "crypto/hashers/sha2_64core.hpp"

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
        SHA512 hasher;
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

/* FIPS 180-4's own SHA-512 examples (one-block and two-block messages). */
TEST_CASE("SHA-512 matches FIPS 180-4's example messages") {
    CHECK(digestOf("") ==
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    CHECK(digestOf("abc") ==
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST_CASE("SHA512::byteWidth is 64 bytes (512 bits)") {
    SHA512 hasher;
    CHECK(hasher.byteWidth() == 64);
}

TEST_CASE("SHA-512 million-'a' stress vector") {
    CHECK(digestOf("a", 1000000) ==
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
}

TEST_CASE("SHA-512 is insensitive to how input is chunked across push() calls") {
    const char* text = "The quick brown fox jumps over the lazy dog";
    size_t len = std::strlen(text);

    SHA512 whole;
    whole.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), len));
    uint8_t wholeDigest[64];
    SByteSpan wholeOut(wholeDigest, sizeof(wholeDigest));
    REQUIRE(whole.finish(wholeOut));

    // Same content, pushed 3 bytes at a time -- crosses the 128-byte block boundary many times.
    SHA512 chunked;
    for (size_t i = 0; i < len; i += 3) {
        size_t n = (len - i < 3) ? (len - i) : 3;
        chunked.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text) + i, n));
    }
    uint8_t chunkedDigest[64];
    SByteSpan chunkedOut(chunkedDigest, sizeof(chunkedDigest));
    REQUIRE(chunked.finish(chunkedOut));

    CHECK(std::memcmp(wholeDigest, chunkedDigest, sizeof(wholeDigest)) == 0);
    CHECK(toHex(wholeDigest, sizeof(wholeDigest)) ==
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
}

TEST_CASE("SHA512::reset allows reusing the same instance for a second, independent digest") {
    SHA512 hasher;
    const uint8_t a[] = { 'a' };
    hasher.push(SReadOnlyByteSpan(a, sizeof(a)));

    hasher.reset();

    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t digest[64];
    SByteSpan out(digest, sizeof(digest));
    REQUIRE(hasher.finish(out));
    CHECK(toHex(digest, sizeof(digest)) ==
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST_CASE("SHA512::finish rejects a destination shorter than byteWidth() without writing garbage") {
    SHA512 hasher;
    const uint8_t data[] = { 'x' };
    hasher.push(SReadOnlyByteSpan(data, sizeof(data)));

    uint8_t tooSmall[63];
    SByteSpan out(tooSmall, sizeof(tooSmall));
    CHECK_FALSE(hasher.finish(out));
}

TEST_CASE("SHA512::finish can be called more than once, yielding the same digest") {
    SHA512 hasher;
    const char* text = "abc";
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));

    uint8_t first[64], second[64];
    SByteSpan firstOut(first, sizeof(first));
    SByteSpan secondOut(second, sizeof(second));
    REQUIRE(hasher.finish(firstOut));
    REQUIRE(hasher.finish(secondOut));
    CHECK(std::memcmp(first, second, sizeof(first)) == 0);
}

// SHA-384/SHA-512 pack their message words MSB-first, and the pack is the one part of the
// compression function that can be made perfect rather than merely fast. It reaches
// Sha2_64Core::loadBe64(), whose portable form exists for compilers with no byte-swap intrinsic.
//
// That branch was, until recently, unreachable in every configuration this library ships --
// GCC and MSVC both take a builtin -- and it was wrong: it byte-reversed the input instead of
// assembling it big-endian. Nothing could have reported that, because nothing built it. It is a
// function now, so this can check it on every configuration, and the check is here so that the
// next mistake in a fallback path does not go unnoticed for the same reason.
TEST_CASE("Sha2_64Core::loadBe64Portable assembles big-endian, and loadBe64 agrees with it") {
    /* The reference, shaped differently on purpose: it walks from the least significant byte and
     * shifts right, where the function under test walks from the most significant and shifts
     * left. A reference written the same way would agree with a bug in both. */
    const auto reference = [](const uint8_t* p) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= uint64_t(p[i]) << (8 * (7 - i));
        }
        return v;
    };

    // Every byte value in every one of the eight positions. An all-equal pattern cannot
    // distinguish a big-endian assembly from a byte reversal -- they agree on it -- which is
    // how the original mistake survived a hand-check in the first place, so each position gets
    // its own value and the rest are varied independently of it.
    for (int pos = 0; pos < 8; ++pos) {
        for (int b = 0; b < 256; ++b) {
            uint8_t buf[8];
            for (int i = 0; i < 8; ++i) {
                buf[i] = uint8_t(i == pos ? b : ((b * (i + 7)) ^ (i * 53 + 19)));
            }

            const uint64_t want = reference(buf);
            CHECK(Sha2_64Core::loadBe64Portable(buf) == want);
        }
    }

    // The two extremes, which the loop above reaches but which are worth naming: an all-ones and
    // an all-zeros block, and the byte order actually asserted rather than implied.
    const uint8_t zeros[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    const uint8_t ones[8]  = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const uint8_t ordered[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    CHECK(Sha2_64Core::loadBe64Portable(zeros) == 0);
    CHECK(Sha2_64Core::loadBe64Portable(ones) == ~uint64_t(0));
    CHECK(Sha2_64Core::loadBe64Portable(ordered) == 0x0123456789ABCDEFULL);

    // The shipped path must agree with the portable one on this CPU, which is the property that
    // actually matters: whichever of the two the build selected, it has to be right.
    for (int pos = 0; pos < 8; ++pos) {
        for (int b = 0; b < 256; b += 7) {
            uint8_t buf[8];
            for (int i = 0; i < 8; ++i) {
                buf[i] = uint8_t(i == pos ? b : ((b * (i + 7)) ^ (i * 53 + 19)));
            }
            CHECK(Sha2_64Core::loadBe64Portable(buf) == reference(buf));
        }
    }
}
