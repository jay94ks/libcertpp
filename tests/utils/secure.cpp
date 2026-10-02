// CSecure: zeroization that survives the optimizer, and constant-time compare/select.
//
// What a test can and cannot establish here is worth being explicit about. The functional
// contracts below -- which mask comes back, which bytes land where, that a buffer ends up zeroed
// -- are ordinary assertions. That the implementation is actually *constant-time*, or that the
// zeroization actually survived a particular compiler's optimizer, is not something a unit test
// can decide: timing measurements on a general-purpose OS are far too noisy to distinguish the
// cases, and a test that tried would fail at random. Those properties rest on the source
// containing no data-dependent branch and on the volatile indirection, both of which are
// reviewable but not assertable.
//
// So this file pins the behaviour, and in particular pins the parts an "optimization" of the
// implementation would be most likely to break: that equalsMask() returns a full mask rather than
// a bool-like 1, and that select() is driven by that mask rather than by a comparison.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;

TEST_CASE("CSecure::zero clears a buffer, and tolerates empty and null spans") {
    std::vector<uint8_t> buffer(64, 0xA5);
    CSecure::zero(SByteSpan(buffer.data(), buffer.size()));

    for (size_t i = 0; i < buffer.size(); ++i) {
        REQUIRE(buffer[i] == 0x00);
    }

    // A partial clear leaves the rest alone -- the span's size is the whole contract.
    std::vector<uint8_t> partial(8, 0xFF);
    CSecure::zero(SByteSpan(partial.data(), 3));
    CHECK(partial[0] == 0x00);
    CHECK(partial[1] == 0x00);
    CHECK(partial[2] == 0x00);
    CHECK(partial[3] == 0xFF);
    CHECK(partial[7] == 0xFF);

    // Neither of these may dereference anything.
    CSecure::zero(SByteSpan(partial.data(), 0));
    CSecure::zero(SByteSpan(nullptr, 0));
    CSecure::zero(SByteSpan(nullptr, 32));
    CHECK(partial[3] == 0xFF);
}

TEST_CASE("CSecure::equalsMask returns a full mask, not a boolean") {
    const uint8_t a[4] = { 0x01, 0x02, 0x03, 0x04 };
    const uint8_t b[4] = { 0x01, 0x02, 0x03, 0x04 };
    const uint8_t c[4] = { 0x01, 0x02, 0x03, 0x05 };

    // 0xFF rather than 1: select() ANDs with this, so a value of 1 would silently keep only the
    // low bit of each selected byte. This is the assertion that catches "simplifying" the fold.
    CHECK(CSecure::equalsMask(SReadOnlyByteSpan(a, 4), SReadOnlyByteSpan(b, 4)) == 0xFF);
    CHECK(CSecure::equalsMask(SReadOnlyByteSpan(a, 4), SReadOnlyByteSpan(c, 4)) == 0x00);

    CHECK(CSecure::equals(SReadOnlyByteSpan(a, 4), SReadOnlyByteSpan(b, 4)));
    CHECK_FALSE(CSecure::equals(SReadOnlyByteSpan(a, 4), SReadOnlyByteSpan(c, 4)));

    // Length mismatch is not equality, in either direction, and a prefix doesn't count.
    CHECK(CSecure::equalsMask(SReadOnlyByteSpan(a, 4), SReadOnlyByteSpan(b, 3)) == 0x00);
    CHECK(CSecure::equalsMask(SReadOnlyByteSpan(a, 3), SReadOnlyByteSpan(b, 4)) == 0x00);

    // Two empty spans are equal; a null pointer with a nonzero size is not, and must not be read.
    CHECK(CSecure::equalsMask(SReadOnlyByteSpan(a, 0), SReadOnlyByteSpan(b, 0)) == 0xFF);
    CHECK(CSecure::equalsMask(SReadOnlyByteSpan(nullptr, 0), SReadOnlyByteSpan(nullptr, 0)) == 0xFF);
    CHECK(CSecure::equalsMask(SReadOnlyByteSpan(nullptr, 4), SReadOnlyByteSpan(b, 4)) == 0x00);
    CHECK(CSecure::equalsMask(SReadOnlyByteSpan(a, 4), SReadOnlyByteSpan(nullptr, 4)) == 0x00);
}

// Every single-byte difference has to be detected, at every position. The arithmetic fold is the
// part most likely to be wrong in a way that only shows for particular values -- a byte whose XOR
// lands exactly on 0x80, say -- so this sweeps all 255 differences across several positions
// rather than trying one.
TEST_CASE("CSecure::equalsMask detects a difference in any byte, of any value") {
    std::vector<uint8_t> base(17);
    for (size_t i = 0; i < base.size(); ++i) {
        base[i] = uint8_t(i * 7 + 3);
    }

    for (size_t position = 0; position < base.size(); ++position) {
        for (int delta = 1; delta < 256; ++delta) {
            std::vector<uint8_t> altered = base;
            altered[position] = uint8_t(altered[position] ^ uint8_t(delta));

            REQUIRE(CSecure::equalsMask(
                SReadOnlyByteSpan(base.data(), base.size()),
                SReadOnlyByteSpan(altered.data(), altered.size())) == 0x00);
        }
    }

    // And an identical copy still compares equal after all that.
    std::vector<uint8_t> same = base;
    CHECK(CSecure::equalsMask(
        SReadOnlyByteSpan(base.data(), base.size()),
        SReadOnlyByteSpan(same.data(), same.size())) == 0xFF);
}

TEST_CASE("CSecure::select picks either input according to the mask") {
    const uint8_t ifSet[5] = { 0x11, 0x22, 0x33, 0x44, 0x55 };
    const uint8_t ifClear[5] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    uint8_t out[5] = { 0 };

    REQUIRE(CSecure::select(
        0xFF, SReadOnlyByteSpan(ifSet, 5), SReadOnlyByteSpan(ifClear, 5), SByteSpan(out, 5)));
    CHECK(std::memcmp(out, ifSet, 5) == 0);

    REQUIRE(CSecure::select(
        0x00, SReadOnlyByteSpan(ifSet, 5), SReadOnlyByteSpan(ifClear, 5), SByteSpan(out, 5)));
    CHECK(std::memcmp(out, ifClear, 5) == 0);

    // Mismatched sizes and null spans are refused rather than guessed at.
    CHECK_FALSE(CSecure::select(
        0xFF, SReadOnlyByteSpan(ifSet, 4), SReadOnlyByteSpan(ifClear, 5), SByteSpan(out, 5)));
    CHECK_FALSE(CSecure::select(
        0xFF, SReadOnlyByteSpan(ifSet, 5), SReadOnlyByteSpan(ifClear, 4), SByteSpan(out, 5)));
    CHECK_FALSE(CSecure::select(
        0xFF, SReadOnlyByteSpan(ifSet, 5), SReadOnlyByteSpan(ifClear, 5), SByteSpan(out, 4)));
    CHECK_FALSE(CSecure::select(
        0xFF, SReadOnlyByteSpan(nullptr, 5), SReadOnlyByteSpan(ifClear, 5), SByteSpan(out, 5)));
    CHECK_FALSE(CSecure::select(
        0xFF, SReadOnlyByteSpan(ifSet, 5), SReadOnlyByteSpan(ifClear, 5), SByteSpan(nullptr, 5)));
}

// The pairing the two are built for, which is how ML-KEM's decapsulation resolves its
// re-encryption check without branching on the outcome.
TEST_CASE("CSecure: equalsMask feeding select is a branch-free conditional copy") {
    const uint8_t expected[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    const uint8_t onMatch[8] = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7 };
    const uint8_t onMismatch[8] = { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 };

    for (int tamper = 0; tamper < 2; ++tamper) {
        std::vector<uint8_t> candidate(expected, expected + 8);
        if (tamper) {
            candidate[5] ^= 0x40;
        }

        uint8_t out[8] = { 0 };
        const uint8_t mask = CSecure::equalsMask(
            SReadOnlyByteSpan(expected, 8),
            SReadOnlyByteSpan(candidate.data(), candidate.size()));

        REQUIRE(CSecure::select(
            mask, SReadOnlyByteSpan(onMatch, 8), SReadOnlyByteSpan(onMismatch, 8),
            SByteSpan(out, 8)));

        CHECK(std::memcmp(out, tamper ? onMismatch : onMatch, 8) == 0);
    }
}
