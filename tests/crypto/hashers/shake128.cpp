#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/hashers/shake128.hpp>
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
        SHAKE128 hasher(outLen);
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

// The empty-message case is NIST's own published SHAKE128 example value (CSRC "Example Values",
// SHAKE128_Msg0.pdf) -- transcribed byte-for-byte from that document, not generated locally.
TEST_CASE("SHAKE128 matches NIST's published empty-message example value") {
    CHECK(shakeOf("", 32) == "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
}

// The remaining vectors were generated locally via Python's hashlib.shake_128 (a mature,
// independent implementation), rather than hand-transcribed from a document -- chosen
// specifically to also probe the rate (168-byte) block-boundary padding logic (167/168/169-byte
// inputs), and cross-checked against the NIST empty-message vector above (both agree).
TEST_CASE("SHAKE128 matches known-answer vectors") {
    CHECK(shakeOf("", 64) ==
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2");

    CHECK(shakeOf("abc", 32) == "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
    CHECK(shakeOf("abc", 64) ==
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378");

    CHECK(shakeOf("The quick brown fox jumps over the lazy dog", 32)
        == "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e");
}

TEST_CASE("SHAKE128 matches a known-answer vector spanning multiple rate blocks") {
    uint8_t msg[200];
    for (size_t i = 0; i < sizeof(msg); ++i) {
        msg[i] = uint8_t(i);
    }

    CHECK(shakeOf(SReadOnlyByteSpan(msg, sizeof(msg)), 64) ==
        "0c4234ca1e31801ae606f8b8d8e0665c66f42a21d601c2681858a92c79ad5d6"
        "9e143c3b1393dd894e7abd5621b0d877f3573a34245e6b911f671081664a5fa53");
}

// The sponge's rate is 168 bytes; these three cases sit exactly on, one below, and one above
// that boundary, to catch off-by-one errors in the block-buffering/padding logic.
TEST_CASE("SHAKE128 matches known-answer vectors at the rate block boundary") {
    uint8_t msg168[168];
    std::memset(msg168, 'a', sizeof(msg168));
    CHECK(shakeOf(SReadOnlyByteSpan(msg168, sizeof(msg168)), 32)
        == "c22e11586c22b713bde373fce93314d76829de2c21d940a28eb659b8dec953a2");

    CHECK(shakeOf(SReadOnlyByteSpan(msg168, sizeof(msg168) - 1), 32)
        == "4f5c6c53ae8190a8ff8a55b2125d28703052d10278570960c2066a905d916c34");

    uint8_t msg169[169];
    std::memset(msg169, 'a', sizeof(msg169));
    CHECK(shakeOf(SReadOnlyByteSpan(msg169, sizeof(msg169)), 32)
        == "09fc23f3acfd944380db0c7f5b1bde62d3a43c6e4c61ca9cb3dfee54904b36a8");
}

TEST_CASE("SHAKE128 supports pushing input across multiple calls") {
    SHAKE128 hasherOneShot(32);
    hasherOneShot.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("abc"), 3));

    std::vector<uint8_t> oneShot(32);
    SByteSpan oneShotSpan(oneShot.data(), oneShot.size());
    REQUIRE(hasherOneShot.finish(oneShotSpan));

    SHAKE128 hasherSplit(32);
    hasherSplit.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("a"), 1));
    hasherSplit.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("b"), 1));
    hasherSplit.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("c"), 1));

    std::vector<uint8_t> split(32);
    SByteSpan splitSpan(split.data(), split.size());
    REQUIRE(hasherSplit.finish(splitSpan));

    CHECK(toHex(oneShot.data(), oneShot.size()) == toHex(split.data(), split.size()));
    CHECK(toHex(oneShot.data(), oneShot.size()) == "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
}

TEST_CASE("SHAKE128 reset() returns the hasher to its initial state") {
    SHAKE128 hasher(32);
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("garbage"), 7));
    hasher.reset();
    hasher.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("abc"), 3));

    std::vector<uint8_t> out(32);
    SByteSpan outSpan(out.data(), out.size());
    REQUIRE(hasher.finish(outSpan));
    CHECK(toHex(out.data(), out.size()) == "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
}
