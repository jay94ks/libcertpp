#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::asn1;

TEST_CASE("CDer::appendBigInteger/readBigInteger round-trip") {
    TArray<uint8_t> der;
    REQUIRE(CDer::appendBigInteger(der, CBigNum(uint64_t(0x1234))));

    TReadOnlySpan<uint8_t> cursor(der.begin(), der.size());
    CBigNum value;
    REQUIRE(CDer::readBigInteger(cursor, value));
    CHECK(value == CBigNum(uint64_t(0x1234)));
    CHECK(cursor.empty());
}

TEST_CASE("CDer::appendBigInteger pads a value whose top bit is set") {
    TArray<uint8_t> der;
    REQUIRE(CDer::appendBigInteger(der, CBigNum(uint64_t(0xFF))));

    // tag(1) + length(1) + content(2: 0x00 0xFF)
    REQUIRE(der.size() == 4);
    CHECK(der[0] == uint8_t(EAUTAG_INTEGER));
    CHECK(der[1] == 2);
    CHECK(der[2] == 0x00);
    CHECK(der[3] == 0xFF);
}

TEST_CASE("CDer::appendBigInteger of zero encodes as a single 0x00 content byte") {
    TArray<uint8_t> der;
    REQUIRE(CDer::appendBigInteger(der, CBigNum()));

    REQUIRE(der.size() == 3);
    CHECK(der[0] == uint8_t(EAUTAG_INTEGER));
    CHECK(der[1] == 1);
    CHECK(der[2] == 0x00);
}

TEST_CASE("CDer::appendSequence/readOuterSequence round-trip multiple integers") {
    TArray<uint8_t> inner;
    REQUIRE(CDer::appendBigInteger(inner, CBigNum(uint64_t(1))));
    REQUIRE(CDer::appendBigInteger(inner, CBigNum(uint64_t(65537))));

    TArray<uint8_t> der;
    REQUIRE(CDer::appendSequence(der, SReadOnlyByteSpan(inner.begin(), inner.size())));

    TReadOnlySpan<uint8_t> content;
    REQUIRE(CDer::readOuterSequence(SReadOnlyByteSpan(der.begin(), der.size()), content));

    CBigNum a, b;
    REQUIRE(CDer::readBigInteger(content, a));
    REQUIRE(CDer::readBigInteger(content, b));
    CHECK(content.empty());

    CHECK(a == CBigNum(uint64_t(1)));
    CHECK(b == CBigNum(uint64_t(65537)));
}

TEST_CASE("CDer::readBigInteger rejects a negative INTEGER") {
    const uint8_t negativeOne[] = { uint8_t(EAUTAG_INTEGER), 1, 0xFF }; // INTEGER -1
    TReadOnlySpan<uint8_t> cursor(negativeOne, sizeof(negativeOne));

    CBigNum value;
    CHECK_FALSE(CDer::readBigInteger(cursor, value));
}

TEST_CASE("CDer::readOuterSequence rejects a non-SEQUENCE tag") {
    const uint8_t notASequence[] = { uint8_t(EAUTAG_INTEGER), 1, 0x2A };
    TReadOnlySpan<uint8_t> content;
    CHECK_FALSE(CDer::readOuterSequence(SReadOnlyByteSpan(notASequence, sizeof(notASequence)), content));
}

TEST_CASE("CDer arbitrary-precision round-trip survives a value wider than 64 bits") {
    const uint8_t bytes[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    CBigNum big = CBigNum::fromBigEndian(SReadOnlyByteSpan(bytes, sizeof(bytes)));

    TArray<uint8_t> der;
    REQUIRE(CDer::appendBigInteger(der, big));

    TReadOnlySpan<uint8_t> cursor(der.begin(), der.size());
    CBigNum roundTripped;
    REQUIRE(CDer::readBigInteger(cursor, roundTripped));
    CHECK(roundTripped == big);
}
