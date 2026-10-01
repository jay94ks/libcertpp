#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/asn1/encoder.hpp>
#include <cstring>
#include <vector>
#include <clocale>
#include <string>

using namespace certpp;
using namespace certpp::asn1;

namespace {
    /* Temporarily switches the CRT locale, restoring the previous one on scope exit. */
    struct LocaleGuard {
        std::string previous;
        bool active;

        explicit LocaleGuard(const char* name) : active(false) {
            const char* cur = std::setlocale(LC_ALL, nullptr);
            previous = cur ? cur : "C";
            active = std::setlocale(LC_ALL, name) != nullptr;
        }

        ~LocaleGuard() {
            std::setlocale(LC_ALL, previous.c_str());
        }
    };
}

TEST_CASE("writeEncodedValue emits the exact short-form byte sequence") {
    const uint8_t content[] = { 0x2A };
    uint8_t buf[8] = {};
    size_t written = 0;

    CTag tag(EAUTAG_INTEGER, false);
    bool ok = CEncoder::writeEncodedValue(TSpan<uint8_t>(buf, sizeof(buf)), EAENC_DER, tag, SReadOnlyByteSpan(content, sizeof(content)), written);

    const uint8_t expected[] = { 0x02, 0x01, 0x2A };
    REQUIRE(ok);
    CHECK(written == sizeof(expected));
    CHECK(std::memcmp(buf, expected, sizeof(expected)) == 0);
    CHECK(CEncoder::encodedValueSize(tag, SReadOnlyByteSpan(content, sizeof(content))) == written);
}

TEST_CASE("writeEncodedValue emits a minimal long-form length header") {
    std::vector<uint8_t> content(300, 0xAB);
    std::vector<uint8_t> buf(400, 0);
    size_t written = 0;

    CTag tag(EAUTAG_STRING_OCTET, false);
    bool ok = CEncoder::writeEncodedValue(
        TSpan<uint8_t>(buf.data(), buf.size()), EAENC_BER, tag,
        SReadOnlyByteSpan(content.data(), content.size()), written
    );

    REQUIRE(ok);
    CHECK(written == 1 + 3 + 300); // tag(1) + length(0x82,0x01,0x2C) + content(300)
    CHECK(buf[0] == 0x04);
    CHECK(buf[1] == 0x82);
    CHECK(buf[2] == 0x01);
    CHECK(buf[3] == 0x2C);
    CHECK(std::memcmp(buf.data() + 4, content.data(), content.size()) == 0);
}

TEST_CASE("writeEncodedValue rejects a destination too small for tag+length+content") {
    const uint8_t content[] = { 0x01, 0x02, 0x03 };
    uint8_t buf[3]; // needs 5 (tag 1 + length 1 + content 3)
    size_t written = 0;

    CTag tag(EAUTAG_STRING_OCTET, false);
    bool ok = CEncoder::writeEncodedValue(TSpan<uint8_t>(buf, sizeof(buf)), EAENC_DER, tag, SReadOnlyByteSpan(content, sizeof(content)), written);

    CHECK_FALSE(ok);
    CHECK(written == 0);
}

TEST_CASE("writeEncodedValue rejects an invalid tag") {
    uint8_t buf[16];
    size_t written = 0;

    CTag invalid;
    bool ok = CEncoder::writeEncodedValue(TSpan<uint8_t>(buf, sizeof(buf)), EAENC_DER, invalid, SReadOnlyByteSpan(nullptr, 0), written);

    CHECK_FALSE(ok);
    CHECK(CEncoder::encodedValueSize(invalid, SReadOnlyByteSpan(nullptr, 0)) == 0);
}

TEST_CASE("writeEncodedValue enforces the CER primitive-string segment limit") {
    std::vector<uint8_t> content(CER_MAX_SEGMENT + 1, 0);
    std::vector<uint8_t> buf(content.size() + 16, 0);
    size_t written = 0;

    CTag tag(EAUTAG_STRING_OCTET, false);
    bool ok = CEncoder::writeEncodedValue(
        TSpan<uint8_t>(buf.data(), buf.size()), EAENC_CER, tag,
        SReadOnlyByteSpan(content.data(), content.size()), written
    );

    CHECK_FALSE(ok);
}

TEST_CASE("encodeBoolean always emits the canonical octet") {
    uint8_t buf[1];
    size_t written = 0;

    REQUIRE(CEncoder::encodeBoolean(TSpan<uint8_t>(buf, 1), true, written));
    CHECK(written == 1);
    CHECK(buf[0] == 0xFF);

    REQUIRE(CEncoder::encodeBoolean(TSpan<uint8_t>(buf, 1), false, written));
    CHECK(buf[0] == 0x00);

    CHECK_FALSE(CEncoder::encodeBoolean(TSpan<uint8_t>(buf, 0), true, written));
}

TEST_CASE("encodeInteger / decodeInteger round-trip and exact bytes") {
    const int64_t values[] = { 0, 1, -1, 127, 128, -128, 255, -129, 65535, INT64_MIN, INT64_MAX };

    for (int64_t v : values) {
        CAPTURE(v);

        uint8_t buf[9];
        size_t written = 0;
        REQUIRE(CEncoder::encodeInteger(TSpan<uint8_t>(buf, sizeof(buf)), v, written));

        int64_t decoded = 0;
        REQUIRE(CDecoder::decodeInteger(SReadOnlyByteSpan(buf, written), decoded));
        CHECK(decoded == v);
    }

    // Exact byte check for the classic "needs a leading 0x00" case.
    uint8_t buf[9];
    size_t written = 0;
    REQUIRE(CEncoder::encodeInteger(TSpan<uint8_t>(buf, sizeof(buf)), int64_t(128), written));
    REQUIRE(written == 2);
    CHECK(buf[0] == 0x00);
    CHECK(buf[1] == 0x80);
}

TEST_CASE("encodeEnumerated / decodeEnumerated round-trip") {
    const uint32_t values[] = { 0, 1, 127, 128, 255, 65535, 0xFFFFFFFFu };

    for (uint32_t v : values) {
        CAPTURE(v);

        uint8_t buf[8];
        size_t written = 0;
        REQUIRE(CEncoder::encodeEnumerated(TSpan<uint8_t>(buf, sizeof(buf)), v, written));

        uint32_t decoded = 0;
        REQUIRE(CDecoder::decodeEnumerated(SReadOnlyByteSpan(buf, written), decoded));
        CHECK(decoded == v);
    }
}

TEST_CASE("encodeNull writes no content octets") {
    size_t written = 123;
    REQUIRE(CEncoder::encodeNull(TSpan<uint8_t>(nullptr, 0), written));
    CHECK(written == 0);
}

TEST_CASE("encodeOctetString copies the value") {
    const uint8_t value[] = { 1, 2, 3, 4 };
    uint8_t buf[4];
    size_t written = 0;

    REQUIRE(CEncoder::encodeOctetString(TSpan<uint8_t>(buf, sizeof(buf)), SReadOnlyByteSpan(value, sizeof(value)), written));
    CHECK(written == 4);
    CHECK(std::memcmp(buf, value, 4) == 0);

    uint8_t tooSmall[3];
    CHECK_FALSE(CEncoder::encodeOctetString(TSpan<uint8_t>(tooSmall, 3), SReadOnlyByteSpan(value, sizeof(value)), written));
}

TEST_CASE("encodeOctetString from a COctet matches the SReadOnlyByteSpan overload") {
    const uint8_t value[] = { 1, 2, 3, 4 };
    COctet octet(value, sizeof(value));

    uint8_t buf[4];
    size_t written = 0;
    REQUIRE(CEncoder::encodeOctetString(TSpan<uint8_t>(buf, sizeof(buf)), octet, written));
    CHECK(written == 4);
    CHECK(std::memcmp(buf, value, 4) == 0);

    uint8_t tooSmall[3];
    CHECK_FALSE(CEncoder::encodeOctetString(TSpan<uint8_t>(tooSmall, 3), octet, written));

    // An empty COctet encodes to an empty OCTET STRING.
    COctet empty;
    REQUIRE(CEncoder::encodeOctetString(TSpan<uint8_t>(buf, sizeof(buf)), empty, written));
    CHECK(written == 0);
}

TEST_CASE("encodeBitString / decodeBitString round-trip") {
    const uint8_t bits[] = { 0xF0 };
    uint8_t buf[2];
    size_t written = 0;

    REQUIRE(CEncoder::encodeBitString(TSpan<uint8_t>(buf, sizeof(buf)), SReadOnlyByteSpan(bits, 1), 4, written));
    CHECK(written == 2);
    CHECK(buf[0] == 4);
    CHECK(buf[1] == 0xF0);

    SReadOnlyByteSpan outBits;
    uint8_t outUnused = 0;
    REQUIRE(CDecoder::decodeBitString(SReadOnlyByteSpan(buf, written), outBits, outUnused));
    CHECK(outUnused == 4);
    REQUIRE(outBits.size == 1);
    CHECK(outBits[0] == 0xF0);

    // Non-zero padding bits in the caller's data must be rejected, not silently written.
    const uint8_t dirty[] = { 0xF1 };
    CHECK_FALSE(CEncoder::encodeBitString(TSpan<uint8_t>(buf, sizeof(buf)), SReadOnlyByteSpan(dirty, 1), 4, written));
}

TEST_CASE("encodeBitString from a COctet / decodeBitString into a COctet round-trip") {
    const uint8_t bits[] = { 0xF0 };
    COctet octet(bits, sizeof(bits));

    uint8_t buf[2];
    size_t written = 0;
    REQUIRE(CEncoder::encodeBitString(TSpan<uint8_t>(buf, sizeof(buf)), octet, 4, written));
    CHECK(written == 2);
    CHECK(buf[0] == 4);
    CHECK(buf[1] == 0xF0);

    COctet outBits;
    uint8_t outUnused = 0;
    REQUIRE(CDecoder::decodeBitString(SReadOnlyByteSpan(buf, written), outBits, outUnused));
    CHECK(outUnused == 4);
    REQUIRE(outBits.size() == 1);
    CHECK(outBits.toPtr()[0] == 0xF0);

    // Non-zero padding bits in the caller's data must be rejected, not silently written.
    const uint8_t dirty[] = { 0xF1 };
    COctet dirtyOctet(dirty, sizeof(dirty));
    CHECK_FALSE(CEncoder::encodeBitString(TSpan<uint8_t>(buf, sizeof(buf)), dirtyOctet, 4, written));
}

TEST_CASE("encodeNamedBitList trims trailing zero bits") {
    // KeyUsage-style: 9 named bits, only bit 0 (digitalSignature) and bit 5 (keyCertSign) set.
    const uint8_t bits[] = { 0x84, 0x00 }; // bits: 10000100 00000000
    uint8_t buf[4];
    size_t written = 0;

    REQUIRE(CEncoder::encodeNamedBitList(TSpan<uint8_t>(buf, sizeof(buf)), SReadOnlyByteSpan(bits, sizeof(bits)), 9, written));

    // Highest set bit is 5 -> 6 significant bits -> 1 data byte, 2 unused bits.
    REQUIRE(written == 2);
    CHECK(buf[0] == 2);
    CHECK(buf[1] == 0x84);

    CHECK(CDecoder::testNamedBit(SReadOnlyByteSpan(buf, written), 0));
    CHECK(CDecoder::testNamedBit(SReadOnlyByteSpan(buf, written), 5));
    CHECK_FALSE(CDecoder::testNamedBit(SReadOnlyByteSpan(buf, written), 1));
}

TEST_CASE("encodeNamedBitList with no set bits encodes as the empty BIT STRING") {
    const uint8_t bits[] = { 0x00 };
    uint8_t buf[4];
    size_t written = 0;

    REQUIRE(CEncoder::encodeNamedBitList(TSpan<uint8_t>(buf, sizeof(buf)), SReadOnlyByteSpan(bits, sizeof(bits)), 8, written));
    REQUIRE(written == 1);
    CHECK(buf[0] == 0);
}

TEST_CASE("encodeOid / decodeOid round-trip and exact bytes") {
    // 1.2.840.113549.1.1.1 (rsaEncryption)
    const uint32_t arcs[] = { 1, 2, 840, 113549, 1, 1, 1 };
    const uint8_t expected[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

    uint8_t buf[16];
    size_t written = 0;
    REQUIRE(CEncoder::encodeOid(TSpan<uint8_t>(buf, sizeof(buf)), TReadOnlySpan<uint32_t>(arcs, 7), written));
    REQUIRE(written == sizeof(expected));
    CHECK(std::memcmp(buf, expected, sizeof(expected)) == 0);
    CHECK(CEncoder::encodedOidSize(TReadOnlySpan<uint32_t>(arcs, 7)) == written);

    uint32_t decodedArcs[7];
    size_t arcCount = 0;
    REQUIRE(CDecoder::decodeOid(SReadOnlyByteSpan(buf, written), TSpan<uint32_t>(decodedArcs, 7), arcCount));
    REQUIRE(arcCount == 7);
    for (size_t i = 0; i < 7; ++i) {
        CHECK(decodedArcs[i] == arcs[i]);
    }
}

TEST_CASE("encodeOid rejects an invalid first arc") {
    const uint32_t badFirst[] = { 3, 0 };   // arcs[0] must be 0-2
    const uint32_t badSecond[] = { 1, 40 }; // arcs[0] < 2 requires arcs[1] < 40
    uint8_t buf[16];
    size_t written = 0;

    CHECK(CEncoder::encodedOidSize(TReadOnlySpan<uint32_t>(badFirst, 2)) == 0);
    CHECK_FALSE(CEncoder::encodeOid(TSpan<uint8_t>(buf, sizeof(buf)), TReadOnlySpan<uint32_t>(badFirst, 2), written));
    CHECK(CEncoder::encodedOidSize(TReadOnlySpan<uint32_t>(badSecond, 2)) == 0);
    CHECK_FALSE(CEncoder::encodeOid(TSpan<uint8_t>(buf, sizeof(buf)), TReadOnlySpan<uint32_t>(badSecond, 2), written));
}

TEST_CASE("encodeOidString<char> / decodeOidString<char> round-trip, exact bytes") {
    // 1.2.840.113549.1.1.1 (rsaEncryption)
    TString<char> text("1.2.840.113549.1.1.1");
    const uint8_t expected[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

    uint8_t buf[16];
    size_t written = 0;
    REQUIRE(CEncoder::encodedOidStringSize(text) == sizeof(expected));
    REQUIRE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    REQUIRE(written == sizeof(expected));
    CHECK(std::memcmp(buf, expected, sizeof(expected)) == 0);

    TString<char> decoded;
    REQUIRE(CDecoder::decodeOidString(SReadOnlyByteSpan(buf, written), decoded));
    CHECK(decoded == text);
}

TEST_CASE("encodeOidString<wchar_t> / decodeOidString<wchar_t> round-trip") {
    TString<wchar_t> text(L"2.5.4.3"); // commonName
    const uint8_t expected[] = { 0x55, 0x04, 0x03 };

    uint8_t buf[16];
    size_t written = 0;
    REQUIRE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    REQUIRE(written == sizeof(expected));
    CHECK(std::memcmp(buf, expected, sizeof(expected)) == 0);

    TString<wchar_t> decoded;
    REQUIRE(CDecoder::decodeOidString(SReadOnlyByteSpan(buf, written), decoded));
    CHECK(decoded == text);
}

TEST_CASE("encodeOidString rejects malformed dotted-decimal text") {
    uint8_t buf[16];
    size_t written = 0;

    SUBCASE("empty text") {
        TString<char> text;
        CHECK(CEncoder::encodedOidStringSize(text) == 0);
        CHECK_FALSE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    }

    SUBCASE("non-minimal leading zero") {
        TString<char> text("1.02.3");
        CHECK_FALSE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    }

    SUBCASE("empty component (double dot)") {
        TString<char> text("1..3");
        CHECK_FALSE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    }

    SUBCASE("trailing dot") {
        TString<char> text("1.2.");
        CHECK_FALSE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    }

    SUBCASE("non-digit component") {
        TString<char> text("1.2.x");
        CHECK_FALSE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    }

    SUBCASE("arc value overflowing uint32_t") {
        TString<char> text("1.2.99999999999");
        CHECK_FALSE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    }

    SUBCASE("invalid arc structure (arcs[0] > 2), rejected by the underlying encodeOid") {
        TString<char> text("3.5.4.3");
        CHECK(CEncoder::encodedOidStringSize(text) == 0);
        CHECK_FALSE(CEncoder::encodeOidString(TSpan<uint8_t>(buf, sizeof(buf)), text, written));
    }

    CHECK(written == 0);
}

TEST_CASE("encodeOidString rejects a destination too small") {
    TString<char> text("1.2.840.113549.1.1.1");
    uint8_t tooSmall[3];
    size_t written = 0;
    CHECK_FALSE(CEncoder::encodeOidString(TSpan<uint8_t>(tooSmall, sizeof(tooSmall)), text, written));
}

TEST_CASE("encodeText validates before writing") {
    const uint8_t valid[] = "Hello";
    const uint8_t invalid[] = "Hello@";
    uint8_t buf[16];
    size_t written = 0;

    REQUIRE(CEncoder::encodeText(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_P, SReadOnlyByteSpan(valid, 5), written));
    CHECK(written == 5);
    CHECK_FALSE(CEncoder::encodeText(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_P, SReadOnlyByteSpan(invalid, 6), written));
}

TEST_CASE("encodeString<wchar_t> / decodeString<wchar_t> round-trip, locale-independent") {
    uint8_t buf[64];
    size_t written = 0;

    SUBCASE("ASCII content") {
        TString<wchar_t> text(L"Hello, World.");
        REQUIRE(CEncoder::encodedStringSize(text) == text.size());
        REQUIRE(CEncoder::encodeString(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_UTF8, text, written));
        CHECK(written == text.size());
        CHECK(std::memcmp(buf, "Hello, World.", written) == 0);

        TString<wchar_t> decoded;
        REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(buf, written), EAUTAG_STRING_UTF8, decoded));
        CHECK(decoded == text);
    }

    SUBCASE("empty text encodes to zero content octets") {
        TString<wchar_t> text;
        CHECK(CEncoder::encodedStringSize(text) == 0);
        REQUIRE(CEncoder::encodeString(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_UTF8, text, written));
        CHECK(written == 0);
    }

    SUBCASE("destination too small is rejected") {
        TString<wchar_t> text(L"Hello");
        CHECK_FALSE(CEncoder::encodeString(TSpan<uint8_t>(buf, 2), EAUTAG_STRING_UTF8, text, written));
        CHECK(written == 0);
    }

    SUBCASE("content invalid for kind is rejected") {
        // Encodes to a multi-byte (8-bit) UTF-8 sequence, which IA5String's 7-bit charset rejects.
        const wchar_t korean[] = { 0xC548, 0xB155 };
        TString<wchar_t> text(korean, 2);
        CHECK_FALSE(CEncoder::encodeString(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_IA5, text, written));
        CHECK(written == 0);
    }

    SUBCASE("multilingual content round-trips through genuine UTF-8") {
        const wchar_t korean[] = { 0xC548, 0xB155 };
        const wchar_t japanese[] = { 0x3053, 0x3093, 0x306B, 0x3061, 0x306F };
        const wchar_t latin[] = { 0x00E0, 0x00E9, 0x00EE, 0x00F5, 0x00FC };

        struct Case { const char* name; const wchar_t* text; size_t length; size_t utf8Bytes; };
        const Case cases[] = {
            { "Korean", korean, 2, 6 },
            { "Japanese", japanese, 5, 15 },
            { "Latin", latin, 5, 10 },
        };

        for (const auto& c : cases) {
            CAPTURE(c.name);

            TString<wchar_t> text(c.text, c.length);
            REQUIRE(CEncoder::encodedStringSize(text) == c.utf8Bytes);
            REQUIRE(CEncoder::encodeString(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_UTF8, text, written));
            CHECK(written == c.utf8Bytes);

            TString<wchar_t> decoded;
            REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(buf, written), EAUTAG_STRING_UTF8, decoded));
            CHECK(decoded == text);
        }
    }
}

TEST_CASE("encodeString<char> / decodeString<char> round-trip") {
    uint8_t buf[64];
    size_t written = 0;

    SUBCASE("ASCII content, no locale requirement") {
        TString<char> text("Hello, World.");
        REQUIRE(CEncoder::encodeString(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_UTF8, text, written));
        CHECK(written == text.size());

        TString<char> decoded;
        REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(buf, written), EAUTAG_STRING_UTF8, decoded));
        CHECK(decoded == text);
    }

    SUBCASE("empty text encodes to zero content octets") {
        TString<char> text;
        REQUIRE(CEncoder::encodeString(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_UTF8, text, written));
        CHECK(written == 0);
    }

    SUBCASE("multilingual content round-trips under a UTF-8 process locale") {
        // TChar=char goes through Utf8EncodingForChar, which treats char as native-locale text --
        // so this specifically needs a UTF-8-compatible locale (see encodeString()'s doc comment).
        LocaleGuard locale(".UTF8");
        if (!locale.active) {
            MESSAGE("UTF-8 locale (\".UTF8\") not available on this platform/CRT; skipping");
            return;
        }

        const wchar_t korean[] = { 0xC548, 0xB155 };
        const wchar_t japanese[] = { 0x3053, 0x3093, 0x306B, 0x3061, 0x306F };
        const wchar_t latin[] = { 0x00E0, 0x00E9, 0x00EE, 0x00F5, 0x00FC };

        struct Case { const char* name; const wchar_t* text; size_t length; };
        const Case cases[] = {
            { "Korean", korean, 2 },
            { "Japanese", japanese, 5 },
            { "Latin", latin, 5 },
        };

        for (const auto& c : cases) {
            CAPTURE(c.name);

            TString<wchar_t> wide(c.text, c.length);
            TString<char> native = wide.convertTo<char>();
            REQUIRE_FALSE(native.empty());

            REQUIRE(CEncoder::encodeString(TSpan<uint8_t>(buf, sizeof(buf)), EAUTAG_STRING_UTF8, native, written));

            TString<char> decoded;
            REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(buf, written), EAUTAG_STRING_UTF8, decoded));
            CHECK(decoded == native);
        }
    }
}

TEST_CASE("encodeUtcTime / decodeUtcTime round-trip") {
    SDateTime time;
    time.year = 2025;
    time.month = 1;
    time.day = 31;
    time.hour = 12;
    time.minute = 0;
    time.second = 0;
    time.isUtc = true;

    uint8_t buf[13];
    size_t written = 0;
    REQUIRE(CEncoder::encodeUtcTime(TSpan<uint8_t>(buf, sizeof(buf)), time, written));
    REQUIRE(written == 13);

    const uint8_t expected[] = "250131120000Z";
    CHECK(std::memcmp(buf, expected, 13) == 0);

    SDateTime decoded;
    REQUIRE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(buf, written), decoded));
    CHECK(decoded.year == time.year);
    CHECK(decoded.month == time.month);
    CHECK(decoded.day == time.day);

    SDateTime notUtc;
    notUtc.isUtc = false;
    CHECK_FALSE(CEncoder::encodeUtcTime(TSpan<uint8_t>(buf, sizeof(buf)), notUtc, written));

    SDateTime outOfRange = time;
    outOfRange.year = 2050; // UTCTime can only represent 1950-2049
    CHECK_FALSE(CEncoder::encodeUtcTime(TSpan<uint8_t>(buf, sizeof(buf)), outOfRange, written));
}

TEST_CASE("encodeGeneralizedTime / decodeGeneralizedTime round-trip, fraction trimming") {
    SDateTime time;
    time.year = 2025;
    time.month = 1;
    time.day = 31;
    time.hour = 12;
    time.minute = 0;
    time.second = 0;
    time.millisecond = 120;
    time.isUtc = true;

    uint8_t buf[24];
    size_t written = 0;
    REQUIRE(CEncoder::encodeGeneralizedTime(TSpan<uint8_t>(buf, sizeof(buf)), time, written));
    CHECK(written == CEncoder::encodedGeneralizedTimeSize(time));

    const uint8_t expected[] = "20250131120000.12Z";
    REQUIRE(written == sizeof(expected) - 1);
    CHECK(std::memcmp(buf, expected, written) == 0);

    SDateTime decoded;
    REQUIRE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(buf, written), decoded));
    CHECK(decoded.millisecond == 120);

    time.millisecond = 0;
    REQUIRE(CEncoder::encodeGeneralizedTime(TSpan<uint8_t>(buf, sizeof(buf)), time, written));
    CHECK(written == 15); // no fractional part at all
}

TEST_CASE("writeSequenceOf concatenates children in order") {
    CTag intTag(EAUTAG_INTEGER, false);

    size_t w1 = 0, w2 = 0;
    uint8_t buf1[8], buf2[8];
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(buf1, sizeof(buf1)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x01", 1), w1));
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(buf2, sizeof(buf2)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x02", 1), w2));

    SReadOnlyByteSpan children[2] = {
        SReadOnlyByteSpan(buf1, w1),
        SReadOnlyByteSpan(buf2, w2)
    };

    uint8_t out[16];
    size_t written = 0;
    REQUIRE(CEncoder::writeSequenceOf(TSpan<uint8_t>(out, sizeof(out)), TReadOnlySpan<SReadOnlyByteSpan>(children, 2), written));
    REQUIRE(written == w1 + w2);
    CHECK(std::memcmp(out, buf1, w1) == 0);
    CHECK(std::memcmp(out + w1, buf2, w2) == 0);
}

TEST_CASE("writeSetOf reorders children into canonical ascending order") {
    CTag intTag(EAUTAG_INTEGER, false);
    uint8_t bufHigh[8], bufLow[8];
    size_t wHigh = 0, wLow = 0;

    // 0x02 (higher first byte) vs 0x01 (lower first byte) as encoded TLVs.
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(bufHigh, sizeof(bufHigh)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x02", 1), wHigh));
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(bufLow, sizeof(bufLow)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x01", 1), wLow));

    // Deliberately given in descending order; writeSetOf must reorder them ascending.
    SReadOnlyByteSpan children[2] = {
        SReadOnlyByteSpan(bufHigh, wHigh),
        SReadOnlyByteSpan(bufLow, wLow)
    };

    uint8_t out[16];
    size_t written = 0;
    REQUIRE(CEncoder::writeSetOf(TSpan<uint8_t>(out, sizeof(out)), TSpan<SReadOnlyByteSpan>(children, 2), written));
    REQUIRE(written == wLow + wHigh);
    CHECK(std::memcmp(out, bufLow, wLow) == 0);
    CHECK(std::memcmp(out + wLow, bufHigh, wHigh) == 0);

    // The caller's array itself is left reordered too.
    CHECK(children[0].data == bufLow);
    CHECK(children[1].data == bufHigh);
}
