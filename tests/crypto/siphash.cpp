// SipHash-2-4, against the reference implementation's published `vectors_sip64` table: the output
// for key 00 01 02 ... 0f over the message 00 01 ... (i-1), for every i from 0 to 63.
//
// Sixty-four consecutive lengths is not belt-and-braces here, it is the point. The table walks
// every residue of the message length mod 8, so it exercises each possible length of final partial
// block; it crosses the 8-byte block boundary eight times; and because the length byte goes into
// the top of the final block, every entry depends on a different padding word. An implementation
// with a wrong rotation constant, a byte-swapped load, a missing length byte or the wrong number of
// finalization rounds cannot match even one row by accident, let alone all sixty-four.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/siphash.hpp>
#include <cstring>
#include <string>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    /* Converts an output tag to lowercase hex, for comparing against the published vectors. */
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

    /* The reference key: bytes 0x00 through 0x0f. */
    std::vector<uint8_t> referenceKey() {
        std::vector<uint8_t> key(CSipHash::KEY_BYTES);
        for (size_t i = 0; i < key.size(); ++i) {
            key[i] = uint8_t(i);
        }
        return key;
    }

    /* One-shot SipHash-2-4 as lowercase hex. */
    std::string prfOf(const std::vector<uint8_t>& key, const uint8_t* msg, size_t len) {
        uint8_t tag[CSipHash::TAG_BYTES];
        SByteSpan out(tag, sizeof(tag));
        REQUIRE(CSipHash::compute(
            SReadOnlyByteSpan(key.data(), key.size()), SReadOnlyByteSpan(msg, len), out));
        return toHex(tag, sizeof(tag));
    }

    /* vectors_sip64[i] -- the output over the i-byte message 00 01 ... (i-1). */
    const char* VECTORS_SIP64[64] = {
        "310e0edd47db6f72", "fd67dc93c539f874",
        "5a4fa9d909806c0d", "2d7efbd796666785",
        "b7877127e09427cf", "8da699cd64557618",
        "cee3fe586e46c9cb", "37d1018bf50002ab",
        "6224939a79f5f593", "b0e4a90bdf82009e",
        "f3b9dd94c5bb5d7a", "a7ad6b22462fb3f4",
        "fbe50e86bc8f1e75", "903d84c02756ea14",
        "eef27a8e90ca23f7", "e545be4961ca29a1",
        "db9bc2577fcc2a3f", "9447be2cf5e99a69",
        "9cd38d96f0b3c14b", "bd6179a71dc96dbb",
        "98eea21af25cd6be", "c7673b2eb0cbf2d0",
        "883ea3e395675393", "c8ce5ccd8c030ca8",
        "94af49f6c650adb8", "eab8858ade92e1bc",
        "f315bb5bb835d817", "adcf6b0763612e2f",
        "a5c91da7acaa4dde", "716595876650a2a6",
        "28ef495c53a387ad", "42c341d8fa92d832",
        "ce7cf2722f512771", "e37859f94623f3a7",
        "381205bb1ab0e012", "ae97a10fd434e015",
        "b4a31508beff4d31", "81396229f0907902",
        "4d0cf49ee5d4dcca", "5c73336a76d8bf9a",
        "d0a704536ba93e0e", "925958fcd6420cad",
        "a915c29bc8067318", "952b79f3bc0aa6d4",
        "f21df2e41d4535f9", "87577519048f53a9",
        "10a56cf5dfcd9adb", "eb75095ccd986cd0",
        "51a9cb9ecba312e6", "96afadfc2ce666c7",
        "72fe52975a4364ee", "5a1645b276d592a1",
        "b274cb8ebf87870a", "6f9bb4203de7b381",
        "eaecb2a30b22a87f", "9924a43cc1315724",
        "bd838d3aafbf8db7", "0b1a2a3265d51aea",
        "135079a3231ce660", "932b2846e4d70666",
        "e1915f5cb1eca46c", "f325965ca16d629f",
        "575ff28e60381be5", "724506eb4c328a95",
    };
}

TEST_CASE("SipHash-2-4 matches all 64 of the reference implementation's vectors") {
    const std::vector<uint8_t> key = referenceKey();

    std::vector<uint8_t> message(64);
    for (size_t i = 0; i < message.size(); ++i) {
        message[i] = uint8_t(i);
    }

    for (size_t i = 0; i < 64; ++i) {
        CHECK(prfOf(key, message.data(), i) == VECTORS_SIP64[i]);
    }
}

TEST_CASE("CSipHash exposes a 128-bit key and a 64-bit output") {
    CHECK(CSipHash::KEY_BYTES == 16);
    CHECK(CSipHash::TAG_BYTES == 8);
    CHECK(CSipHash::BLOCK_BYTES == 8);
}

/* The message length enters only through the top byte of the final block, and that byte is the whole
 * of SipHash's padding. An implementation that merely zero-padded the last partial block would give
 * these two identical output -- they are the smallest message/zero-extension pair -- and would still
 * pass a round-trip test. The empty message also exercises the final-block path with no bytes at
 * all: there is always exactly one last block to absorb. */
TEST_CASE("SipHash-2-4 distinguishes the empty message from a zero byte") {
    const std::vector<uint8_t> key = referenceKey();
    const uint8_t zero[1] = { 0x00 };

    CHECK(prfOf(key, nullptr, 0) == "310e0edd47db6f72");
    CHECK(prfOf(key, zero, 1) == "fd67dc93c539f874");
}

/* The published table stops at 63 bytes, so it never distinguishes the message length from the
 * length byte: below 256 they are the same number. These lengths straddle the wrap, which is where
 * an implementation that counted only the residual bytes of the final partial block -- rather than
 * the whole message -- would first diverge. They come from a Python implementation cross-checked
 * against CPython's own C SipHash (which is SipHash-1-3, identical but for the round counts) over
 * lengths either side of 256. */
TEST_CASE("SipHash-2-4 takes its length byte from the whole message, across the 256-byte wrap") {
    const std::vector<uint8_t> key = referenceKey();

    std::vector<uint8_t> data(512);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = uint8_t(i);
    }

    CHECK(prfOf(key, data.data(), 255) == "1ab24dc7fe69c1a9");
    CHECK(prfOf(key, data.data(), 256) == "d7bfa7d226059d99");
    CHECK(prfOf(key, data.data(), 257) == "4897b2558d7b818a");
    CHECK(prfOf(key, data.data(), 512) == "0eda5ae5c3573b88");
}

TEST_CASE("SipHash-2-4 is insensitive to how input is chunked across push() calls") {
    const std::vector<uint8_t> key = referenceKey();

    std::vector<uint8_t> data(200);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = uint8_t(i * 37 + 11);
    }

    // Lengths either side of the 8-byte block boundary, plus a long one.
    for (size_t len : { size_t(0), size_t(1), size_t(7), size_t(8), size_t(9),
                        size_t(15), size_t(16), size_t(17), size_t(63), size_t(64),
                        size_t(200) }) {
        uint8_t oneShot[CSipHash::TAG_BYTES];
        SByteSpan oneShotOut(oneShot, sizeof(oneShot));
        REQUIRE(CSipHash::compute(
            SReadOnlyByteSpan(key.data(), key.size()),
            SReadOnlyByteSpan(data.data(), len), oneShotOut));

        // Byte at a time: every push() leaves a partial block behind.
        CSipHash byByte;
        REQUIRE(byByte.reset(SReadOnlyByteSpan(key.data(), key.size())));
        for (size_t i = 0; i < len; ++i) {
            CHECK(byByte.push(SReadOnlyByteSpan(data.data() + i, 1)) == 1);
        }
        uint8_t incremental[CSipHash::TAG_BYTES];
        SByteSpan incrementalOut(incremental, sizeof(incremental));
        REQUIRE(byByte.finish(incrementalOut));
        CHECK(std::memcmp(oneShot, incremental, sizeof(oneShot)) == 0);

        // Three at a time: the chunk size is coprime to the block size, so partial blocks get
        // topped up from the middle of a caller's buffer rather than at a tidy offset.
        CSipHash byThree;
        REQUIRE(byThree.reset(SReadOnlyByteSpan(key.data(), key.size())));
        for (size_t i = 0; i < len; i += 3) {
            const size_t n = (len - i < 3) ? (len - i) : 3;
            CHECK(byThree.push(SReadOnlyByteSpan(data.data() + i, n)) == n);
        }
        uint8_t threes[CSipHash::TAG_BYTES];
        SByteSpan threesOut(threes, sizeof(threes));
        REQUIRE(byThree.finish(threesOut));
        CHECK(std::memcmp(oneShot, threes, sizeof(oneShot)) == 0);
    }
}

/* SipHash is a reusable PRF, not a one-time MAC: unlike CPoly1305, finish() leaves the key alone
 * and reset() may be called as often as wanted. */
TEST_CASE("CSipHash keeps its key across finish() and can be restarted") {
    const std::vector<uint8_t> key = referenceKey();
    std::vector<uint8_t> message(16);
    for (size_t i = 0; i < message.size(); ++i) {
        message[i] = uint8_t(i);
    }

    CSipHash prf;
    REQUIRE(prf.reset(SReadOnlyByteSpan(key.data(), key.size())));
    REQUIRE(prf.push(SReadOnlyByteSpan(message.data(), 16)) == 16);

    uint8_t first[CSipHash::TAG_BYTES];
    SByteSpan firstOut(first, sizeof(first));
    REQUIRE(prf.finish(firstOut));
    CHECK(toHex(first, sizeof(first)) == VECTORS_SIP64[16]);

    // finish() again: same answer, state not spent.
    uint8_t again[CSipHash::TAG_BYTES];
    SByteSpan againOut(again, sizeof(again));
    REQUIRE(prf.finish(againOut));
    CHECK(std::memcmp(first, again, sizeof(first)) == 0);

    // reset() with no argument reuses the key already in place for a second message.
    REQUIRE(prf.reset());
    REQUIRE(prf.push(SReadOnlyByteSpan(message.data(), 7)) == 7);
    uint8_t second[CSipHash::TAG_BYTES];
    SByteSpan secondOut(second, sizeof(second));
    REQUIRE(prf.finish(secondOut));
    CHECK(toHex(second, sizeof(second)) == VECTORS_SIP64[7]);

    // And re-keying with the same key starts over identically.
    REQUIRE(prf.reset(SReadOnlyByteSpan(key.data(), key.size())));
    REQUIRE(prf.push(SReadOnlyByteSpan(message.data(), 16)) == 16);
    uint8_t third[CSipHash::TAG_BYTES];
    SByteSpan thirdOut(third, sizeof(third));
    REQUIRE(prf.finish(thirdOut));
    CHECK(std::memcmp(first, third, sizeof(first)) == 0);
}

/* k0 keys v0 and v2, k1 keys v1 and v3, so a swapped or truncated key load would still produce
 * output -- just not output that depends on the whole key. */
TEST_CASE("SipHash-2-4 output depends on every key byte") {
    std::vector<uint8_t> message(24);
    for (size_t i = 0; i < message.size(); ++i) {
        message[i] = uint8_t(i);
    }

    const std::vector<uint8_t> base = referenceKey();
    const std::string reference = prfOf(base, message.data(), message.size());

    for (size_t i = 0; i < CSipHash::KEY_BYTES; ++i) {
        std::vector<uint8_t> flipped = base;
        flipped[i] ^= 0x01;
        CHECK(prfOf(flipped, message.data(), message.size()) != reference);
    }
}

TEST_CASE("CSipHash rejects a wrong-sized key, an unkeyed push and a wrong-sized output") {
    const std::vector<uint8_t> key = referenceKey();
    const uint8_t data[4] = { 1, 2, 3, 4 };
    uint8_t tag[CSipHash::TAG_BYTES];

    CSipHash prf;

    // Nothing works before a key is installed.
    CHECK_FALSE(prf.reset());
    CHECK(prf.push(SReadOnlyByteSpan(data, sizeof(data))) == 0);
    CHECK_FALSE(prf.finish(SByteSpan(tag, sizeof(tag))));

    CHECK_FALSE(prf.reset(SReadOnlyByteSpan(key.data(), 15)));
    CHECK_FALSE(prf.reset(SReadOnlyByteSpan(key.data(), 0)));
    REQUIRE(prf.reset(SReadOnlyByteSpan(key.data(), key.size())));

    // The output is exactly 8 bytes: neither short nor long is accepted, since a caller passing a
    // 16-byte buffer is probably expecting SipHash-2-4-128, which this is not.
    CHECK_FALSE(prf.finish(SByteSpan(tag, 7)));
    uint8_t wide[16];
    CHECK_FALSE(prf.finish(SByteSpan(wide, sizeof(wide))));
    CHECK(prf.finish(SByteSpan(tag, sizeof(tag))));

    // compute() refuses the same bad arguments.
    CHECK_FALSE(CSipHash::compute(
        SReadOnlyByteSpan(key.data(), 15), SReadOnlyByteSpan(data, sizeof(data)),
        SByteSpan(tag, sizeof(tag))));
    CHECK_FALSE(CSipHash::compute(
        SReadOnlyByteSpan(key.data(), key.size()), SReadOnlyByteSpan(data, sizeof(data)),
        SByteSpan(tag, 4)));
}
