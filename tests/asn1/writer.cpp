#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/asn1/writer.hpp>
#include <certpp/name.hpp>
#include <cstring>
#include <vector>

using namespace certpp;
using namespace certpp::asn1;

namespace {
    /* Reads everything written to stream so far (from the beginning) into a byte vector. */
    std::vector<uint8_t> snapshot(const IStreamPtr& stream) {
        std::vector<uint8_t> data(size_t(stream->length()));
        stream->seek(0, ESEEK_SET);
        if (!data.empty()) {
            stream->read(data.data(), data.size());
        }
        return data;
    }
}

TEST_CASE("writeElement writes the exact tag-length-value bytes") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    const uint8_t content[] = { 0x2A };
    REQUIRE(writer.writeElement(CTag(EAUTAG_INTEGER, false), SReadOnlyByteSpan(content, sizeof(content))));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x02, 0x01, 0x2A };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeElement rejects an invalid tag and a null stream") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    CTag invalid;
    CHECK_FALSE(writer.writeElement(invalid, SReadOnlyByteSpan(nullptr, 0)));

    CWriter nullWriter(nullptr);
    CHECK_FALSE(nullWriter.writeElement(CTag::BOOLEAN, SReadOnlyByteSpan(nullptr, 0)));
}

TEST_CASE("writeBoolean writes the canonical octet") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    REQUIRE(writer.writeBoolean(true));
    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x01, 0x01, 0xFF };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeInteger writes a minimal two's-complement encoding") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    REQUIRE(writer.writeInteger(128));
    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x02, 0x02, 0x00, 0x80 };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeEnumerated / writeNull") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    REQUIRE(writer.writeEnumerated(1));
    REQUIRE(writer.writeNull());

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x0A, 0x01, 0x01, 0x05, 0x00 };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeOctetString (span and COctet overloads) write identical bytes") {
    const uint8_t value[] = { 0xDE, 0xAD, 0xBE, 0xEF };

    IStreamPtr spanStream = IStream::createMemory();
    CWriter spanWriter(spanStream);
    REQUIRE(spanWriter.writeOctetString(SReadOnlyByteSpan(value, sizeof(value))));

    IStreamPtr octetStream = IStream::createMemory();
    CWriter octetWriter(octetStream);
    COctet octet(value, sizeof(value));
    REQUIRE(octetWriter.writeOctetString(octet));

    auto spanBytes = snapshot(spanStream);
    auto octetBytes = snapshot(octetStream);
    const uint8_t expected[] = { 0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF };

    REQUIRE(spanBytes.size() == sizeof(expected));
    CHECK(std::memcmp(spanBytes.data(), expected, sizeof(expected)) == 0);
    CHECK(spanBytes == octetBytes);
}

TEST_CASE("writeBitString / writeNamedBitList") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    const uint8_t bits[] = { 0xF0 };
    REQUIRE(writer.writeBitString(SReadOnlyByteSpan(bits, 1), 4));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x03, 0x02, 0x04, 0xF0 };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);

    // Non-zero padding bits in the caller's data must be rejected.
    CWriter rejecting(IStream::createMemory());
    const uint8_t dirty[] = { 0xF1 };
    CHECK_FALSE(rejecting.writeBitString(SReadOnlyByteSpan(dirty, 1), 4));

    // NamedBitList trims trailing zero bits.
    IStreamPtr namedStream = IStream::createMemory();
    CWriter namedWriter(namedStream);
    const uint8_t namedBits[] = { 0x84, 0x00 };
    REQUIRE(namedWriter.writeNamedBitList(SReadOnlyByteSpan(namedBits, sizeof(namedBits)), 9));

    auto namedBytes = snapshot(namedStream);
    const uint8_t expectedNamed[] = { 0x03, 0x02, 0x02, 0x84 };
    REQUIRE(namedBytes.size() == sizeof(expectedNamed));
    CHECK(std::memcmp(namedBytes.data(), expectedNamed, sizeof(expectedNamed)) == 0);
}

TEST_CASE("writeOid writes the exact arc encoding") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    const uint32_t arcs[] = { 1, 2, 840, 113549, 1, 1, 1 };
    REQUIRE(writer.writeOid(TReadOnlySpan<uint32_t>(arcs, 7)));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);

    CWriter rejecting(IStream::createMemory());
    const uint32_t badFirst[] = { 3, 0 };
    CHECK_FALSE(rejecting.writeOid(TReadOnlySpan<uint32_t>(badFirst, 2)));
}

TEST_CASE("writeOidString<char> / writeOidString<wchar_t> write the same OID bytes") {
    IStreamPtr charStream = IStream::createMemory();
    CWriter charWriter(charStream);
    REQUIRE(charWriter.writeOidString(TString<char>("1.2.840.113549.1.1.1")));

    IStreamPtr wideStream = IStream::createMemory();
    CWriter wideWriter(wideStream);
    REQUIRE(wideWriter.writeOidString(TString<wchar_t>(L"1.2.840.113549.1.1.1")));

    auto charBytes = snapshot(charStream);
    auto wideBytes = snapshot(wideStream);
    const uint8_t expected[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

    REQUIRE(charBytes.size() == sizeof(expected));
    CHECK(std::memcmp(charBytes.data(), expected, sizeof(expected)) == 0);
    CHECK(charBytes == wideBytes);

    CWriter rejecting(IStream::createMemory());
    CHECK_FALSE(rejecting.writeOidString(TString<char>("1.02.3")));
}

TEST_CASE("writeText validates before writing") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    const uint8_t valid[] = "Hello";
    REQUIRE(writer.writeText(EAUTAG_STRING_P, SReadOnlyByteSpan(valid, 5)));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x13, 0x05, 'H', 'e', 'l', 'l', 'o' };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);

    CWriter rejecting(IStream::createMemory());
    const uint8_t invalid[] = "Hello@";
    CHECK_FALSE(rejecting.writeText(EAUTAG_STRING_P, SReadOnlyByteSpan(invalid, 6)));
}

TEST_CASE("writeString<TChar> writes a UTF8String from a TString") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);

    REQUIRE(writer.writeString(EAUTAG_STRING_UTF8, TString<wchar_t>(L"Hi")));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x0C, 0x02, 'H', 'i' };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeUtcTime / writeGeneralizedTime write the DER-canonical forms") {
    SDateTime time;
    time.year = 2025;
    time.month = 1;
    time.day = 31;
    time.hour = 12;
    time.minute = 0;
    time.second = 0;
    time.isUtc = true;

    IStreamPtr utcStream = IStream::createMemory();
    CWriter utcWriter(utcStream);
    REQUIRE(utcWriter.writeUtcTime(time));

    auto utcBytes = snapshot(utcStream);
    const uint8_t expectedUtc[] = { 0x17, 0x0D, '2', '5', '0', '1', '3', '1', '1', '2', '0', '0', '0', '0', 'Z' };
    REQUIRE(utcBytes.size() == sizeof(expectedUtc));
    CHECK(std::memcmp(utcBytes.data(), expectedUtc, sizeof(expectedUtc)) == 0);

    IStreamPtr genStream = IStream::createMemory();
    CWriter genWriter(genStream);
    REQUIRE(genWriter.writeGeneralizedTime(time));

    auto genBytes = snapshot(genStream);
    const uint8_t expectedGen[] = { 0x18, 0x0F, '2', '0', '2', '5', '0', '1', '3', '1', '1', '2', '0', '0', '0', '0', 'Z' };
    REQUIRE(genBytes.size() == sizeof(expectedGen));
    CHECK(std::memcmp(genBytes.data(), expectedGen, sizeof(expectedGen)) == 0);
}

TEST_CASE("writeSequence concatenates already-encoded children under a SEQUENCE tag") {
    CTag intTag(EAUTAG_INTEGER, false);
    uint8_t buf1[8], buf2[8];
    size_t w1 = 0, w2 = 0;
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(buf1, sizeof(buf1)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x01", 1), w1));
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(buf2, sizeof(buf2)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x02", 1), w2));

    SReadOnlyByteSpan children[2] = { SReadOnlyByteSpan(buf1, w1), SReadOnlyByteSpan(buf2, w2) };

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeSequence(TReadOnlySpan<SReadOnlyByteSpan>(children, 2)));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeSet reorders children into canonical ascending order") {
    CTag intTag(EAUTAG_INTEGER, false);
    uint8_t bufHigh[8], bufLow[8];
    size_t wHigh = 0, wLow = 0;
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(bufHigh, sizeof(bufHigh)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x02", 1), wHigh));
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(bufLow, sizeof(bufLow)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x01", 1), wLow));

    SReadOnlyByteSpan children[2] = { SReadOnlyByteSpan(bufHigh, wHigh), SReadOnlyByteSpan(bufLow, wLow) };

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeSet(TSpan<SReadOnlyByteSpan>(children, 2)));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeDistinguishedName writes the exact expected bytes for a single component") {
    // Same C=US encoding verified byte-for-byte at the CEncoder level (see
    // tests/asn1/roundtrip.cpp), just wrapped in the outer SEQUENCE tag-length-value writeElement()
    // adds on top of CEncoder::encodeDistinguishedName()'s content.
    CDistinguishedName dn;
    REQUIRE(dn.trySet(CName(ENAME_C, "US")));

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeDistinguishedName(dn));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = {
        0x30, 0x0D,                             // SEQUENCE, length 13 (the RDNSequence)
            0x31, 0x0B,                         // SET, length 11 (the RDN)
                0x30, 0x09,                     // SEQUENCE, length 9 (the AttributeTypeAndValue)
                    0x06, 0x03, 0x55, 0x04, 0x06,    // OBJECT IDENTIFIER 2.5.4.6
                    0x13, 0x02, 0x55, 0x53,          // PrintableString "US"
    };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeDistinguishedName writes an empty distinguished name as an empty SEQUENCE") {
    CDistinguishedName empty;

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeDistinguishedName(empty));

    auto bytes = snapshot(stream);
    const uint8_t expected[] = { 0x30, 0x00 };
    REQUIRE(bytes.size() == sizeof(expected));
    CHECK(std::memcmp(bytes.data(), expected, sizeof(expected)) == 0);
}

TEST_CASE("writeDistinguishedName writes multiple components in ascending ENameType order") {
    CDistinguishedName dn;
    REQUIRE(dn.trySet(CName(ENAME_C, "US")));
    REQUIRE(dn.trySet(CName(ENAME_CN, "example.com")));

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeDistinguishedName(dn));

    auto bytes = snapshot(stream);

    // CN (1) must come before C (6), regardless of trySet() call order.
    CTag outerTag;
    SReadOnlyByteSpan outerContent;
    size_t bytesRead = 0;
    REQUIRE(CDecoder::readEncodedValue(SReadOnlyByteSpan(bytes.data(), bytes.size()), EAENC_DER, outerTag, outerContent, bytesRead));
    REQUIRE(outerTag == CTag::SEQ);

    TReadOnlySpan<uint8_t> cursor = outerContent;
    CTag firstRdnTag;
    SReadOnlyByteSpan firstRdnContent;
    REQUIRE(CDecoder::readNextElement(cursor, EAENC_DER, firstRdnTag, firstRdnContent));
    REQUIRE(firstRdnTag == CTag::SET_OF);

    // The first RDN's AttributeTypeAndValue must be CN's OID (2.5.4.3 -> content {0x55, 0x04, 0x03}).
    TReadOnlySpan<uint8_t> rdnCursor = firstRdnContent;
    CTag avTag;
    SReadOnlyByteSpan avContent;
    REQUIRE(CDecoder::readNextElement(rdnCursor, EAENC_DER, avTag, avContent));

    CTag oidTag;
    SReadOnlyByteSpan oidContent;
    REQUIRE(CDecoder::readNextElement(avContent, EAENC_DER, oidTag, oidContent));
    REQUIRE(oidContent.size == 3);
    CHECK((oidContent[0] == 0x55 && oidContent[1] == 0x04 && oidContent[2] == 0x03));
}
