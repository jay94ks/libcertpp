#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/asn1/decoder.hpp>
#include <vector>
#include <clocale>
#include <string>
#include <cstring>

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

TEST_CASE("readEncodedValue decodes a definite-length TLV") {
    const uint8_t data[] = { 0x02, 0x01, 0x2A };

    CTag outTag;
    SReadOnlyByteSpan outArea;
    size_t bytesRead = 0;

    bool ok = CDecoder::readEncodedValue(SReadOnlyByteSpan(data, sizeof(data)), EAENC_DER, outTag, outArea, bytesRead);

    REQUIRE(ok);
    CHECK(bytesRead == sizeof(data));
    CHECK(outTag.hasSameClassAndValue(CTag(EAUTAG_INTEGER, false)));
    REQUIRE(outArea.size == 1);
    CHECK(outArea[0] == 0x2A);
}

TEST_CASE("readEncodedValue decodes a long-form length header") {
    // Regression test: decodeLength() used to compare the decoded length VALUE, not its
    // octet count, against sizeof(uint32_t), rejecting every length above 4.
    std::vector<uint8_t> data = { 0x04, 0x82, 0x01, 0x2C }; // OCTET STRING, length 300
    data.resize(data.size() + 300, 0xAB);

    CTag outTag;
    SReadOnlyByteSpan outArea;
    size_t bytesRead = 0;

    bool ok = CDecoder::readEncodedValue(SReadOnlyByteSpan(data.data(), data.size()), EAENC_BER, outTag, outArea, bytesRead);

    REQUIRE(ok);
    CHECK(bytesRead == data.size());
    CHECK(outArea.size == 300);
}

TEST_CASE("readEncodedValue skips a BER indefinite-length value to its EOC marker") {
    const uint8_t data[] = {
        0x30, 0x80,          // SEQUENCE, constructed, indefinite length
        0x02, 0x01, 0x01,    // INTEGER 1
        0x02, 0x01, 0x02,    // INTEGER 2
        0x00, 0x00           // end-of-contents
    };

    CTag outTag;
    SReadOnlyByteSpan outArea;
    size_t bytesRead = 0;

    bool ok = CDecoder::readEncodedValue(SReadOnlyByteSpan(data, sizeof(data)), EAENC_BER, outTag, outArea, bytesRead);

    REQUIRE(ok);
    CHECK(bytesRead == sizeof(data));
    CHECK(outTag.isConstructed());
    CHECK(outArea.size == 6); // the two INTEGER TLVs, EOC excluded
}

TEST_CASE("readEncodedValue rejects indefinite length under DER") {
    const uint8_t data[] = { 0x30, 0x80, 0x00, 0x00 };

    CTag outTag;
    SReadOnlyByteSpan outArea;
    size_t bytesRead = 0;

    bool ok = CDecoder::readEncodedValue(SReadOnlyByteSpan(data, sizeof(data)), EAENC_DER, outTag, outArea, bytesRead);
    CHECK_FALSE(ok);
}

TEST_CASE("readEncodedValue rejects indefinite-length nesting beyond the depth guard") {
    // depth > CDecoder::MAX_NESTING_DEPTH (64); attacker-reachable input for a certificate
    // parser must fail cleanly instead of exhausting the stack.
    std::vector<uint8_t> data;
    const int depth = 100;

    for (int i = 0; i < depth; ++i) {
        data.push_back(0x30);
        data.push_back(0x80);
    }

    for (int i = 0; i < depth; ++i) {
        data.push_back(0x00);
        data.push_back(0x00);
    }

    CTag outTag;
    SReadOnlyByteSpan outArea;
    size_t bytesRead = 0;

    bool ok = CDecoder::readEncodedValue(SReadOnlyByteSpan(data.data(), data.size()), EAENC_BER, outTag, outArea, bytesRead);
    CHECK_FALSE(ok);
}

TEST_CASE("readEncodedValue rejects a length that exceeds the remaining source") {
    const uint8_t data[] = { 0x04, 0x05, 0x01, 0x02 }; // OCTET STRING, length 5, only 2 octets present

    CTag outTag;
    SReadOnlyByteSpan outArea;
    size_t bytesRead = 0;

    bool ok = CDecoder::readEncodedValue(SReadOnlyByteSpan(data, sizeof(data)), EAENC_DER, outTag, outArea, bytesRead);
    CHECK_FALSE(ok);
}

TEST_CASE("readNextElement iterates a SEQUENCE's members") {
    const uint8_t data[] = {
        0x02, 0x01, 0x01,   // INTEGER 1
        0x01, 0x01, 0xFF,   // BOOLEAN true
        0x05, 0x00          // NULL
    };

    SReadOnlyByteSpan cursor(data, sizeof(data));
    int count = 0;

    while (!cursor.empty()) {
        CTag tag;
        SReadOnlyByteSpan area;
        REQUIRE(CDecoder::readNextElement(cursor, EAENC_DER, tag, area));
        count++;
    }

    CHECK(count == 3);
}

TEST_CASE("readNextElement fails without advancing the cursor on malformed input") {
    const uint8_t data[] = { 0x02, 0x05, 0x01 }; // INTEGER claims 5 octets, only 1 present
    SReadOnlyByteSpan cursor(data, sizeof(data));

    CTag tag;
    SReadOnlyByteSpan area;
    CHECK_FALSE(CDecoder::readNextElement(cursor, EAENC_DER, tag, area));
    CHECK(cursor.size == sizeof(data));
}

TEST_CASE("decodeBoolean") {
    bool value = false;

    SUBCASE("DER/CER accept only 0x00 and 0xFF") {
        const uint8_t trueBytes[] = { 0xFF };
        const uint8_t falseBytes[] = { 0x00 };
        const uint8_t nonCanonical[] = { 0x01 };

        REQUIRE(CDecoder::decodeBoolean(SReadOnlyByteSpan(trueBytes, 1), EAENC_DER, value));
        CHECK(value);
        REQUIRE(CDecoder::decodeBoolean(SReadOnlyByteSpan(falseBytes, 1), EAENC_DER, value));
        CHECK_FALSE(value);
        CHECK_FALSE(CDecoder::decodeBoolean(SReadOnlyByteSpan(nonCanonical, 1), EAENC_DER, value));
        CHECK_FALSE(CDecoder::decodeBoolean(SReadOnlyByteSpan(nonCanonical, 1), EAENC_CER, value));
    }

    SUBCASE("BER accepts any nonzero octet as true") {
        const uint8_t nonCanonical[] = { 0x01 };
        REQUIRE(CDecoder::decodeBoolean(SReadOnlyByteSpan(nonCanonical, 1), EAENC_BER, value));
        CHECK(value);
    }

    SUBCASE("wrong length is rejected") {
        const uint8_t empty[] = { 0 };
        CHECK_FALSE(CDecoder::decodeBoolean(SReadOnlyByteSpan(empty, 0), EAENC_DER, value));
    }
}

TEST_CASE("decodeInteger") {
    int64_t value = 0;

    SUBCASE("small positive/negative values") {
        const uint8_t zero[] = { 0x00 };
        const uint8_t one[] = { 0x01 };
        const uint8_t minusOne[] = { 0xFF };
        const uint8_t oneTwoSeven[] = { 0x7F };
        const uint8_t oneTwoEight[] = { 0x00, 0x80 };
        const uint8_t minusOneTwoEight[] = { 0x80 };

        REQUIRE(CDecoder::decodeInteger(SReadOnlyByteSpan(zero, sizeof(zero)), value));
        CHECK(value == 0);
        REQUIRE(CDecoder::decodeInteger(SReadOnlyByteSpan(one, sizeof(one)), value));
        CHECK(value == 1);
        REQUIRE(CDecoder::decodeInteger(SReadOnlyByteSpan(minusOne, sizeof(minusOne)), value));
        CHECK(value == -1);
        REQUIRE(CDecoder::decodeInteger(SReadOnlyByteSpan(oneTwoSeven, sizeof(oneTwoSeven)), value));
        CHECK(value == 127);
        REQUIRE(CDecoder::decodeInteger(SReadOnlyByteSpan(oneTwoEight, sizeof(oneTwoEight)), value));
        CHECK(value == 128);
        REQUIRE(CDecoder::decodeInteger(SReadOnlyByteSpan(minusOneTwoEight, sizeof(minusOneTwoEight)), value));
        CHECK(value == -128);
    }

    SUBCASE("non-minimal encoding is rejected") {
        const uint8_t redundantPositive[] = { 0x00, 0x01 }; // 1 could fit in one octet
        const uint8_t redundantNegative[] = { 0xFF, 0x80 }; // -128 could fit in one octet
        CHECK_FALSE(CDecoder::decodeInteger(SReadOnlyByteSpan(redundantPositive, sizeof(redundantPositive)), value));
        CHECK_FALSE(CDecoder::decodeInteger(SReadOnlyByteSpan(redundantNegative, sizeof(redundantNegative)), value));
    }

    SUBCASE("empty content is rejected") {
        CHECK_FALSE(CDecoder::decodeInteger(SReadOnlyByteSpan(nullptr, 0), value));
    }
}

TEST_CASE("decodeEnumerated") {
    uint32_t value = 0;
    const uint8_t encoded[] = { 0x00, 0x80 }; // 128, needs the leading 0x00 to stay non-negative

    REQUIRE(CDecoder::decodeEnumerated(SReadOnlyByteSpan(encoded, sizeof(encoded)), value));
    CHECK(value == 128);

    const uint8_t negative[] = { 0xFF }; // -1, not representable as uint32_t
    CHECK_FALSE(CDecoder::decodeEnumerated(SReadOnlyByteSpan(negative, sizeof(negative)), value));
}

TEST_CASE("decodeNull") {
    CHECK(CDecoder::decodeNull(SReadOnlyByteSpan(nullptr, 0)));

    const uint8_t nonEmpty[] = { 0x00 };
    CHECK_FALSE(CDecoder::decodeNull(SReadOnlyByteSpan(nonEmpty, sizeof(nonEmpty))));
}

TEST_CASE("decodeOctetString passes content through unchanged") {
    const uint8_t data[] = { 0x01, 0x02, 0x03 };
    SReadOnlyByteSpan outValue;

    REQUIRE(CDecoder::decodeOctetString(SReadOnlyByteSpan(data, sizeof(data)), outValue));
    CHECK(outValue.data == data);
    CHECK(outValue.size == sizeof(data));
}

TEST_CASE("decodeOctetString into a COctet copies content, doesn't alias it") {
    const uint8_t data[] = { 0x01, 0x02, 0x03 };
    COctet outValue;

    SUBCASE("non-empty content") {
        REQUIRE(CDecoder::decodeOctetString(SReadOnlyByteSpan(data, sizeof(data)), outValue));
        REQUIRE(outValue.size() == sizeof(data));
        CHECK(std::memcmp(outValue.toPtr(), data, sizeof(data)) == 0);
        CHECK(outValue.toPtr() != data);
    }

    SUBCASE("empty content decodes to an empty COctet, clearing any prior content") {
        outValue.store(data, sizeof(data));
        REQUIRE(CDecoder::decodeOctetString(SReadOnlyByteSpan(nullptr, 0), outValue));
        CHECK(outValue.empty());
    }
}

TEST_CASE("decodeBitString") {
    SReadOnlyByteSpan bits;
    uint8_t unusedBits = 0xFF;

    SUBCASE("valid content") {
        const uint8_t content[] = { 0x04, 0xF0 }; // 4 unused bits, data 0xF0 -> bits "1111"
        REQUIRE(CDecoder::decodeBitString(SReadOnlyByteSpan(content, sizeof(content)), bits, unusedBits));
        CHECK(unusedBits == 4);
        REQUIRE(bits.size == 1);
        CHECK(bits[0] == 0xF0);
    }

    SUBCASE("unused bit count out of range is rejected") {
        const uint8_t content[] = { 0x08, 0x00 };
        CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(content, sizeof(content)), bits, unusedBits));
    }

    SUBCASE("non-zero padding bits are rejected") {
        const uint8_t content[] = { 0x04, 0xF1 }; // low 4 bits should be 0 but aren't
        CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(content, sizeof(content)), bits, unusedBits));
    }

    SUBCASE("empty content is rejected") {
        CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(nullptr, 0), bits, unusedBits));
    }
}

TEST_CASE("decodeBitString into a COctet copies the packed bit data, doesn't alias it") {
    COctet outBits;
    uint8_t unusedBits = 0xFF;

    SUBCASE("valid content") {
        const uint8_t content[] = { 0x04, 0xF0 }; // 4 unused bits, data 0xF0 -> bits "1111"
        REQUIRE(CDecoder::decodeBitString(SReadOnlyByteSpan(content, sizeof(content)), outBits, unusedBits));
        CHECK(unusedBits == 4);
        REQUIRE(outBits.size() == 1);
        CHECK(outBits.toPtr()[0] == 0xF0);
        CHECK(outBits.toPtr() != content + 1);
    }

    SUBCASE("the empty (zero-bit) BIT STRING decodes to an empty COctet") {
        outBits.store(reinterpret_cast<const uint8_t*>("\xAA"), 1); // pre-existing content
        const uint8_t content[] = { 0x00 }; // 0 unused bits, no data octets
        REQUIRE(CDecoder::decodeBitString(SReadOnlyByteSpan(content, sizeof(content)), outBits, unusedBits));
        CHECK(unusedBits == 0);
        CHECK(outBits.empty());
    }

    SUBCASE("invalid content is rejected, leaving outBits unchanged") {
        const uint8_t original[] = { 0x11 };
        outBits.store(original, sizeof(original));

        const uint8_t content[] = { 0x04, 0xF1 }; // non-zero padding bits
        CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(content, sizeof(content)), outBits, unusedBits));

        REQUIRE(outBits.size() == sizeof(original));
        CHECK(std::memcmp(outBits.toPtr(), original, sizeof(original)) == 0);
    }
}

TEST_CASE("testNamedBit reads KeyUsage-style named bits") {
    // KeyUsage ::= BIT STRING { digitalSignature(0), ..., keyCertSign(5), ... }
    // Trimmed encoding for {digitalSignature, keyCertSign} = bits 0 and 5 set: 10000100 -> 0x84, 2 unused bits.
    const uint8_t content[] = { 0x02, 0x84 };
    SReadOnlyByteSpan span(content, sizeof(content));

    CHECK(CDecoder::testNamedBit(span, 0));  // digitalSignature
    CHECK_FALSE(CDecoder::testNamedBit(span, 1));
    CHECK(CDecoder::testNamedBit(span, 5));  // keyCertSign
    CHECK_FALSE(CDecoder::testNamedBit(span, 6)); // beyond the encoded (trimmed) bits -> implicitly unset
    CHECK_FALSE(CDecoder::testNamedBit(span, 100));
}

TEST_CASE("countOidArcs / decodeOid") {
    // 1.2.840.113549.1.1.1 (rsaEncryption)
    const uint8_t content[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    SReadOnlyByteSpan span(content, sizeof(content));

    REQUIRE(CDecoder::countOidArcs(span) == 7);

    uint32_t arcs[7];
    size_t arcCount = 0;
    REQUIRE(CDecoder::decodeOid(span, TSpan<uint32_t>(arcs, 7), arcCount));
    REQUIRE(arcCount == 7);

    const uint32_t expected[] = { 1, 2, 840, 113549, 1, 1, 1 };
    for (size_t i = 0; i < 7; ++i) {
        CHECK(arcs[i] == expected[i]);
    }
}

TEST_CASE("decodeOid rejects a buffer too small for the arc count") {
    const uint8_t content[] = { 0x2A, 0x03 }; // 1.2.3 -> 3 arcs
    uint32_t arcs[2];
    size_t arcCount = 0;
    CHECK_FALSE(CDecoder::decodeOid(SReadOnlyByteSpan(content, sizeof(content)), TSpan<uint32_t>(arcs, 2), arcCount));
}

TEST_CASE("decodeOidString<char> formats the arcs as dotted-decimal text") {
    // 1.2.840.113549.1.1.1 (rsaEncryption)
    const uint8_t content[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    TString<char> outValue;

    REQUIRE(CDecoder::decodeOidString(SReadOnlyByteSpan(content, sizeof(content)), outValue));
    CHECK(outValue == TString<char>("1.2.840.113549.1.1.1"));
}

TEST_CASE("decodeOidString<wchar_t> formats the arcs as dotted-decimal text") {
    const uint8_t content[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    TString<wchar_t> outValue;

    REQUIRE(CDecoder::decodeOidString(SReadOnlyByteSpan(content, sizeof(content)), outValue));
    CHECK(outValue == TString<wchar_t>(L"1.2.840.113549.1.1.1"));
}

TEST_CASE("decodeOidString handles single/zero-valued arcs without dropping digits") {
    // 2.5.4.3 (commonName): includes single-digit arcs and an arc value of exactly the
    // combined-arc formula's boundary, exercising the digit-formatting loop's edge cases.
    const uint8_t content[] = { 0x55, 0x04, 0x03 };
    TString<char> outValue;

    REQUIRE(CDecoder::decodeOidString(SReadOnlyByteSpan(content, sizeof(content)), outValue));
    CHECK(outValue == TString<char>("2.5.4.3"));
}

TEST_CASE("decodeOidString rejects invalid content and leaves outValue unchanged") {
    TString<char> outValue = "sentinel";

    SUBCASE("empty content") {
        CHECK_FALSE(CDecoder::decodeOidString(SReadOnlyByteSpan(nullptr, 0), outValue));
    }

    SUBCASE("truncated base-128 subidentifier") {
        const uint8_t content[] = { 0x2A, 0x86 }; // continuation bit set with nothing following
        CHECK_FALSE(CDecoder::decodeOidString(SReadOnlyByteSpan(content, sizeof(content)), outValue));
    }

    CHECK(outValue == TString<char>("sentinel"));
}

TEST_CASE("decodeText validates per character-set kind") {
    SReadOnlyByteSpan outText;

    SUBCASE("UTF8String") {
        const uint8_t valid[] = { 0xC3, 0xA9 }; // U+00E9, 'e' with acute accent
        const uint8_t invalid[] = { 0xC3 };     // truncated 2-byte sequence
        CHECK(CDecoder::decodeText(SReadOnlyByteSpan(valid, sizeof(valid)), EAUTAG_STRING_UTF8, outText));
        CHECK_FALSE(CDecoder::decodeText(SReadOnlyByteSpan(invalid, sizeof(invalid)), EAUTAG_STRING_UTF8, outText));
    }

    SUBCASE("PrintableString") {
        const uint8_t valid[] = "Hello, World.";
        const uint8_t invalid[] = "Hello@World";
        CHECK(CDecoder::decodeText(SReadOnlyByteSpan(valid, sizeof(valid) - 1), EAUTAG_STRING_P, outText));
        CHECK_FALSE(CDecoder::decodeText(SReadOnlyByteSpan(invalid, sizeof(invalid) - 1), EAUTAG_STRING_P, outText));
    }

    SUBCASE("IA5String rejects 8-bit octets") {
        const uint8_t invalid[] = { 0x80 };
        CHECK_FALSE(CDecoder::decodeText(SReadOnlyByteSpan(invalid, sizeof(invalid)), EAUTAG_STRING_IA5, outText));
    }

    SUBCASE("unvalidated kind passes anything through") {
        const uint8_t anything[] = { 0xFF, 0x00, 0x80 };
        CHECK(CDecoder::decodeText(SReadOnlyByteSpan(anything, sizeof(anything)), EAUTAG_STRING_BMP, outText));
    }
}

TEST_CASE("decodeUtcTime") {
    SDateTime time;

    SUBCASE("valid, RFC 5280 century rule") {
        const uint8_t y2025[] = "250131120000Z"; // 2025-01-31 12:00:00Z (YY=25 -> 20xx)
        REQUIRE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(y2025, 13), time));
        CHECK(time.year == 2025);
        CHECK(time.month == 1);
        CHECK(time.day == 31);
        CHECK(time.hour == 12);
        CHECK(time.isUtc);

        const uint8_t y1999[] = "991231235959Z"; // YY=99 -> 19xx
        REQUIRE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(y1999, 13), time));
        CHECK(time.year == 1999);
    }

    SUBCASE("missing Z suffix is rejected") {
        const uint8_t noZ[] = "250131120000 ";
        CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(noZ, 13), time));
    }

    SUBCASE("out-of-range month is rejected") {
        const uint8_t badMonth[] = "251331120000Z";
        CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(badMonth, 13), time));
    }
}

TEST_CASE("decodeGeneralizedTime") {
    SDateTime time;

    SUBCASE("without fractional seconds") {
        const uint8_t data[] = "20250131120000Z";
        REQUIRE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(data, 15), time));
        CHECK(time.year == 2025);
        CHECK(time.millisecond == 0);
    }

    SUBCASE("with fractional seconds") {
        const uint8_t data[] = "20250131120000.5Z";
        REQUIRE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(data, 17), time));
        CHECK(time.millisecond == 500);
    }

    SUBCASE("trailing-zero fraction is rejected (non-canonical)") {
        const uint8_t data[] = "20250131120000.50Z";
        CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(data, 18), time));
    }

    SUBCASE("leap-day validation") {
        const uint8_t nonLeap[] = "20230229120000Z"; // 2023 is not a leap year
        CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(nonLeap, 15), time));

        const uint8_t leap[] = "20240229120000Z"; // 2024 is a leap year
        CHECK(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(leap, 15), time));
    }
}

TEST_CASE("decodeString<wchar_t> decodes character-set content directly into a TString") {
    TString<wchar_t> outValue;

    SUBCASE("UTF8String, ASCII content") {
        const uint8_t data[] = "Hello, World.";
        REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(data, sizeof(data) - 1), EAUTAG_STRING_UTF8, outValue));
        CHECK(outValue == TString<wchar_t>(L"Hello, World."));
    }

    SUBCASE("PrintableString content") {
        const uint8_t data[] = "Hello, World.";
        REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(data, sizeof(data) - 1), EAUTAG_STRING_P, outValue));
        CHECK(outValue == TString<wchar_t>(L"Hello, World."));
    }

    SUBCASE("empty content decodes to an empty string") {
        REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(nullptr, 0), EAUTAG_STRING_UTF8, outValue));
        CHECK(outValue.empty());
    }

    SUBCASE("invalid charset is rejected and leaves outValue unchanged") {
        outValue = L"sentinel";
        const uint8_t invalid[] = { 0xC3 }; // truncated 2-byte UTF-8 sequence
        CHECK_FALSE(CDecoder::decodeString(SReadOnlyByteSpan(invalid, sizeof(invalid)), EAUTAG_STRING_UTF8, outValue));
        CHECK(outValue == TString<wchar_t>(L"sentinel"));
    }

    SUBCASE("IA5String rejecting an 8-bit octet leaves outValue unchanged") {
        outValue = L"sentinel";
        const uint8_t invalid[] = { 0x80 };
        CHECK_FALSE(CDecoder::decodeString(SReadOnlyByteSpan(invalid, sizeof(invalid)), EAUTAG_STRING_IA5, outValue));
        CHECK(outValue == TString<wchar_t>(L"sentinel"));
    }

    SUBCASE("multilingual UTF8String content round-trips through genuine UTF-8, locale-independent") {
        // wchar_t decode uses Utf8EncodingForWChar (std::codecvt_utf8<wchar_t> directly), so this
        // must hold regardless of the process locale -- no LocaleGuard needed.
        const wchar_t korean[] = { 0xC548, 0xB155 };
        const wchar_t japanese[] = { 0x3053, 0x3093, 0x306B, 0x3061, 0x306F };
        const wchar_t latin[] = { 0x00E0, 0x00E9, 0x00EE, 0x00F5, 0x00FC };

        struct Case { const char* name; const wchar_t* text; size_t length; };
        const Case cases[] = {
            { "Korean", korean, sizeof(korean) / sizeof(wchar_t) },
            { "Japanese", japanese, sizeof(japanese) / sizeof(wchar_t) },
            { "Latin", latin, sizeof(latin) / sizeof(wchar_t) },
        };

        for (const auto& c : cases) {
            CAPTURE(c.name);

            // --> Derive the ASN.1 UTF8String content bytes from the wchar_t source via the
            // library's own encoder, rather than hand-typing UTF-8 byte literals.
            uint8_t utf8Bytes[64];
            SByteSpan utf8Dst(utf8Bytes, sizeof(utf8Bytes));
            IStringEncoding<wchar_t>& wideEnc = TUtf8Encoding<wchar_t>::get();
            size_t utf8Len = wideEnc.encodeTo(utf8Dst, TReadOnlySpan<wchar_t>(c.text, c.length));
            REQUIRE(utf8Len > 0);

            REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(utf8Bytes, utf8Len), EAUTAG_STRING_UTF8, outValue));
            CHECK(outValue == TString<wchar_t>(c.text, c.length));
        }
    }
}

TEST_CASE("decodeString<char> decodes character-set content directly into a TString") {
    TString<char> outValue;

    SUBCASE("UTF8String, ASCII content") {
        const uint8_t data[] = "Hello, World.";
        REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(data, sizeof(data) - 1), EAUTAG_STRING_UTF8, outValue));
        CHECK(outValue == TString<char>("Hello, World."));
    }

    SUBCASE("NumericString content") {
        const uint8_t data[] = "0123456789";
        REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(data, sizeof(data) - 1), EAUTAG_STRING_N, outValue));
        CHECK(outValue == TString<char>("0123456789"));
    }

    SUBCASE("empty content decodes to an empty string") {
        REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(nullptr, 0), EAUTAG_STRING_UTF8, outValue));
        CHECK(outValue.empty());
    }

    SUBCASE("invalid charset is rejected and leaves outValue unchanged") {
        outValue = "sentinel";
        const uint8_t invalid[] = { 0xC3 }; // truncated 2-byte UTF-8 sequence
        CHECK_FALSE(CDecoder::decodeString(SReadOnlyByteSpan(invalid, sizeof(invalid)), EAUTAG_STRING_UTF8, outValue));
        CHECK(outValue == TString<char>("sentinel"));
    }

    SUBCASE("multilingual UTF8String content round-trips under a UTF-8 process locale") {
        // TChar=char goes through Utf8EncodingForChar, which treats char as native-locale text --
        // so this specifically needs a UTF-8-compatible locale to round-trip non-ASCII content
        // (see decodeString()'s doc comment).
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
            { "Korean", korean, sizeof(korean) / sizeof(wchar_t) },
            { "Japanese", japanese, sizeof(japanese) / sizeof(wchar_t) },
            { "Latin", latin, sizeof(latin) / sizeof(wchar_t) },
        };

        for (const auto& c : cases) {
            CAPTURE(c.name);

            uint8_t utf8Bytes[64];
            SByteSpan utf8Dst(utf8Bytes, sizeof(utf8Bytes));
            IStringEncoding<wchar_t>& wideEnc = TUtf8Encoding<wchar_t>::get();
            size_t utf8Len = wideEnc.encodeTo(utf8Dst, TReadOnlySpan<wchar_t>(c.text, c.length));
            REQUIRE(utf8Len > 0);

            REQUIRE(CDecoder::decodeString(SReadOnlyByteSpan(utf8Bytes, utf8Len), EAUTAG_STRING_UTF8, outValue));

            // --> Round-trip back to wide via convertTo<wchar_t>() (native -> wide, using the same
            // mbsrtowcs() primitive) and compare against the original wchar_t source.
            TString<wchar_t> roundTripped = outValue.convertTo<wchar_t>();
            CHECK(roundTripped == TString<wchar_t>(c.text, c.length));
        }
    }
}

TEST_CASE("tryReadEncodedValue: a truncated value is reported apart from a malformed one") {
    // The whole reason EDecoderStatus has more than two values: a caller feeding bytes in as
    // they arrive has to know whether to wait for more or give up, and until this entry point
    // existed no public API could tell it -- decodeLength(), the only producer, is private.

    // SEQUENCE { INTEGER 1, INTEGER 2 }: 30 06 02 01 01 02 01 02
    const uint8_t complete[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };

    CTag tag;
    SReadOnlyByteSpan area;
    size_t bytesRead = 0;

    SUBCASE("the complete value reads, and agrees with the bool overload") {
        REQUIRE(CDecoder::tryReadEncodedValue(
            SReadOnlyByteSpan(complete, sizeof(complete)), EAENC_DER, tag, area, bytesRead)
            == EDEC_OK);
        CHECK(tag == CTag(CTag::SEQ));
        CHECK(bytesRead == sizeof(complete));
        CHECK(area.size == 6);      // the content, not the whole TLV

        CHECK(CDecoder::readEncodedValue(
            SReadOnlyByteSpan(complete, sizeof(complete)), EAENC_DER, tag, area, bytesRead));
    }

    SUBCASE("every proper prefix is EDEC_NEED_MORE, never EDEC_BAD_ARGS") {
        // Cutting a valid encoding short can only ever mean "incomplete". A caller that got
        // EDEC_BAD_ARGS here would abandon a stream that was merely mid-value.
        for (size_t cut = 0; cut < sizeof(complete); ++cut) {
            CAPTURE(cut);
            CHECK(CDecoder::tryReadEncodedValue(
                SReadOnlyByteSpan(complete, cut), EAENC_DER, tag, area, bytesRead)
                == EDEC_NEED_MORE);
        }
    }

    SUBCASE("a long-form length whose content never arrives is EDEC_NEED_MORE") {
        // OCTET STRING, length 0x81 0x80 (128 bytes), with only three content octets present.
        const uint8_t shortContent[] = { 0x04, 0x81, 0x80, 0xAA, 0xBB, 0xCC };
        CHECK(CDecoder::tryReadEncodedValue(
            SReadOnlyByteSpan(shortContent, sizeof(shortContent)), EAENC_BER, tag, area, bytesRead)
            == EDEC_NEED_MORE);
    }

    SUBCASE("the reserved length form is malformed, not incomplete") {
        // 0xFF is reserved by X.690 8.1.3.5(c). No number of further bytes makes it legal, so
        // reporting EDEC_NEED_MORE would strand a caller waiting forever.
        const uint8_t reserved[] = { 0x04, 0xFF, 0x00, 0x00, 0x00, 0x00 };
        CHECK(CDecoder::tryReadEncodedValue(
            SReadOnlyByteSpan(reserved, sizeof(reserved)), EAENC_BER, tag, area, bytesRead)
            == EDEC_RESERVED);
    }

    SUBCASE("an indefinite length under DER is prohibited, not incomplete") {
        // 0x80 is the indefinite-length form. BER and CER allow it; DER does not, and that is a
        // property of the rule set rather than of how much input arrived.
        const uint8_t indefinite[] = { 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00 };
        CHECK(CDecoder::tryReadEncodedValue(
            SReadOnlyByteSpan(indefinite, sizeof(indefinite)), EAENC_DER, tag, area, bytesRead)
            == EDEC_PROHIBITED);

        // Under BER the same bytes read fine, which is what makes the distinction meaningful.
        CHECK(CDecoder::tryReadEncodedValue(
            SReadOnlyByteSpan(indefinite, sizeof(indefinite)), EAENC_BER, tag, area, bytesRead)
            == EDEC_OK);
    }

    SUBCASE("an indefinite-length value missing its end-of-contents marker is EDEC_NEED_MORE") {
        // The status has to survive the recursion through readIndefiniteContent(), which is
        // where it used to be discarded: a nested value that ran short reported the same false
        // as a nested value that was wrong.
        const uint8_t noEoc[] = { 0x30, 0x80, 0x02, 0x01, 0x01 };
        CHECK(CDecoder::tryReadEncodedValue(
            SReadOnlyByteSpan(noEoc, sizeof(noEoc)), EAENC_BER, tag, area, bytesRead)
            == EDEC_NEED_MORE);
    }

    SUBCASE("an unknown encoding rule is a caller error") {
        CHECK(CDecoder::tryReadEncodedValue(
            SReadOnlyByteSpan(complete, sizeof(complete)),
            static_cast<EEncodingRule>(0x7F), tag, area, bytesRead)
            == EDEC_BAD_ARGS);
    }
}
