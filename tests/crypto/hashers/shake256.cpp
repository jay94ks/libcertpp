#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/hashers/shake256.hpp>
#include <cstring>
#include <string>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    /* Converts a computed digest to lowercase hex, for comparing against known-answer vectors. */
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

    std::string shakeOf(SReadOnlyByteSpan msg, size_t outLen) {
        SHAKE256 hasher(outLen);
        hasher.push(msg);

        std::vector<uint8_t> out(outLen);
        SByteSpan outSpan(out.data(), out.size());
        REQUIRE(hasher.finish(outSpan));
        return toHex(out.data(), out.size());
    }

    std::string shakeOf(const char* text, size_t outLen) {
        return shakeOf(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text)), outLen);
    }
}

// Known-answer vectors generated locally via Python's hashlib.shake_256 (a mature, independent
// implementation), rather than hand-transcribed from a document -- chosen specifically to also
// probe the rate (136-byte) block-boundary padding logic (135/136/137-byte inputs).
TEST_CASE("SHAKE256 matches known-answer vectors") {
    CHECK(shakeOf("", 32) == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    CHECK(shakeOf("", 64) ==
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");

    CHECK(shakeOf("abc", 32) == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
    CHECK(shakeOf("abc", 64) ==
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");

    CHECK(shakeOf("The quick brown fox jumps over the lazy dog", 32)
        == "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca");
}

TEST_CASE("SHAKE256 matches a known-answer vector spanning multiple rate blocks") {
    uint8_t msg[200];
    for (size_t i = 0; i < sizeof(msg); ++i) {
        msg[i] = uint8_t(i);
    }

    CHECK(shakeOf(SReadOnlyByteSpan(msg, sizeof(msg)), 64) ==
        "4ee1ca03272b05d3bfb1e1c79a967f823b9fc5e4bb3987b1ba9e9cb5afb07a5"
        "ee3a07fbd457a94364964a841e7f466e5a022e21ab7f673c18ba98cdb1d5aecfa");
}

// The sponge's rate is 136 bytes; these three cases sit exactly on, one below, and one above
// that boundary, to catch off-by-one errors in the block-buffering/padding logic.
TEST_CASE("SHAKE256 matches known-answer vectors at the rate block boundary") {
    uint8_t msg136[136];
    std::memset(msg136, 'a', sizeof(msg136));
    CHECK(shakeOf(SReadOnlyByteSpan(msg136, sizeof(msg136)), 32)
        == "8fcc5a08f0a1f6827c9cf64ee8d16e0443106359ca6c8efd230759256f44996a");

    CHECK(shakeOf(SReadOnlyByteSpan(msg136, sizeof(msg136) - 1), 32)
        == "55b991ece1e567b6e7c2c714444dd201cd51f4f3832d08e1d26bebc63e07a3d7");

    uint8_t msg137[137];
    std::memset(msg137, 'a', sizeof(msg137));
    CHECK(shakeOf(SReadOnlyByteSpan(msg137, sizeof(msg137)), 32)
        == "a44e1a438dad6273d540be65ee26386c59588efb09139dc086385d2db0c25782");
}

TEST_CASE("SHAKE256 supports pushing input across multiple calls") {
    SHAKE256 hasherOneShot(32);
    hasherOneShot.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("abc"), 3));

    std::vector<uint8_t> oneShot(32);
    SByteSpan oneShotSpan(oneShot.data(), oneShot.size());
    REQUIRE(hasherOneShot.finish(oneShotSpan));

    SHAKE256 hasherSplit(32);
    hasherSplit.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("a"), 1));
    hasherSplit.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("b"), 1));
    hasherSplit.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("c"), 1));

    std::vector<uint8_t> split(32);
    SByteSpan splitSpan(split.data(), split.size());
    REQUIRE(hasherSplit.finish(splitSpan));

    CHECK(toHex(oneShot.data(), oneShot.size()) == toHex(split.data(), split.size()));
    CHECK(toHex(oneShot.data(), oneShot.size()) == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
}

TEST_CASE("SHAKE256 reset() returns the hasher to its initial state") {
    SHAKE256 hasher(32);
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("garbage"), 7));
    hasher.reset();
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("abc"), 3));

    std::vector<uint8_t> out(32);
    SByteSpan outSpan(out.data(), out.size());
    REQUIRE(hasher.finish(outSpan));
    CHECK(toHex(out.data(), out.size()) == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
}
