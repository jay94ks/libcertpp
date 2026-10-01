#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/asn1/reader.hpp>
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

TEST_CASE("CReader constructed from a span reads without an IStream") {
    const uint8_t data[] = { 0x01, 0x01, 0xFF }; // BOOLEAN true
    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));

    CHECK_FALSE(reader.atEnd());
    bool value = false;
    REQUIRE(reader.readBoolean(value));
    CHECK(value);
    CHECK(reader.atEnd());
}

TEST_CASE("CReader constructed from an IStream reads its content") {
    const uint8_t data[] = { 0x01, 0x01, 0xFF };
    IStreamPtr stream = IStream::createMemory(SReadOnlyByteSpan(data, sizeof(data)));

    CReader reader(stream);
    bool value = false;
    REQUIRE(reader.readBoolean(value));
    CHECK(value);
    CHECK(reader.atEnd());
}

TEST_CASE("CReader reads from the stream lazily, not just at construction") {
    // Regression test: a CReader must not assume it has already seen everything the stream will
    // ever produce. The stream is empty when the CReader is constructed; if construction ate the
    // stream's content eagerly (as an earlier version of this class did), it would have captured
    // zero bytes here and no amount of writing afterward could make readBoolean() succeed.
    IStreamPtr stream = IStream::createMemory();
    CReader reader(stream);
    CHECK(reader.atEnd()); // nothing available yet

    const uint8_t data[] = { 0x01, 0x01, 0xFF };
    REQUIRE(stream->write(data, sizeof(data)) == sizeof(data));
    REQUIRE(stream->seek(0, ESEEK_SET) == ERET_OK);

    CHECK_FALSE(reader.atEnd());
    bool value = false;
    REQUIRE(reader.readBoolean(value));
    CHECK(value);
}

TEST_CASE("CReader grows its buffer across multiple elements read one at a time") {
    // Exercises growBuffer()'s retry loop being invoked repeatedly (once per element) against
    // the same stream, rather than only ever running once at construction.
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeInteger(1));
    REQUIRE(writer.writeInteger(2));
    REQUIRE(writer.writeInteger(3));
    REQUIRE(stream->seek(0, ESEEK_SET) == ERET_OK);

    CReader reader(stream);
    int64_t value = 0;

    REQUIRE(reader.readInteger(value));
    CHECK(value == 1);
    REQUIRE(reader.readInteger(value));
    CHECK(value == 2);
    REQUIRE(reader.readInteger(value));
    CHECK(value == 3);
    CHECK(reader.atEnd());
}

TEST_CASE("a mismatched typed read survives buffer growth spanning multiple stream reads") {
    // Content larger than one internal read chunk (4096 bytes), so even the first
    // readNextElement() attempt needs growBuffer() to run more than once to gather enough data --
    // exercising the rollback path that must reconstruct the cursor from the (by then
    // reallocated) buffer, not a dangling pointer into an earlier, already-freed allocation.
    std::vector<uint8_t> value(5000);
    for (size_t i = 0; i < value.size(); ++i) {
        value[i] = uint8_t(i);
    }

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeOctetString(SReadOnlyByteSpan(value.data(), value.size())));
    REQUIRE(stream->seek(0, ESEEK_SET) == ERET_OK);

    CReader reader(stream);

    // Wrong type first: must fail without corrupting the reader (this is the growth-then-
    // tag-mismatch case).
    int64_t asInt = 0;
    CHECK_FALSE(reader.readInteger(asInt));
    CHECK_FALSE(reader.atEnd());

    // Correct type: must still work, with the full content intact.
    COctet outValue;
    REQUIRE(reader.readOctetString(outValue));
    REQUIRE(outValue.size() == value.size());
    CHECK(std::memcmp(outValue.toPtr(), value.data(), value.size()) == 0);
    CHECK(reader.atEnd());
}

TEST_CASE("CReader constructed from an IStream honors the stream's current position") {
    const uint8_t data[] = { 0xAA, 0x01, 0x01, 0xFF }; // one junk byte, then a BOOLEAN
    IStreamPtr stream = IStream::createMemory(SReadOnlyByteSpan(data, sizeof(data)));
    REQUIRE(stream->seek(1, ESEEK_SET) == ERET_OK);

    CReader reader(stream);
    bool value = false;
    REQUIRE(reader.readBoolean(value));
    CHECK(value);
}

TEST_CASE("an empty/null-backed CReader is immediately at end") {
    CReader fromEmptySpan(SReadOnlyByteSpan(nullptr, 0));
    CHECK(fromEmptySpan.atEnd());

    IStreamPtr nullStream;
    CReader fromNullStream(nullStream);
    CHECK(fromNullStream.atEnd());

    CReader defaultConstructed;
    CHECK(defaultConstructed.atEnd());
}

TEST_CASE("readNextElement reads tag+content and advances, failing without advancing on malformed input") {
    const uint8_t data[] = { 0x02, 0x01, 0x2A, 0x01, 0x01, 0xFF };
    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));

    CTag tag;
    SReadOnlyByteSpan content;
    REQUIRE(reader.readNextElement(tag, content));
    CHECK(tag.hasSameClassAndValue(CTag(EAUTAG_INTEGER, false)));
    REQUIRE(content.size == 1);
    CHECK(content[0] == 0x2A);

    REQUIRE(reader.readNextElement(tag, content));
    CHECK(tag.hasSameClassAndValue(CTag(EAUTAG_BOOLEAN, false)));
    CHECK(reader.atEnd());

    // No more elements: fails, cursor (already empty) stays empty.
    CHECK_FALSE(reader.readNextElement(tag, content));
    CHECK(reader.atEnd());
}

TEST_CASE("a typed read that doesn't match the next tag fails without consuming the cursor") {
    const uint8_t data[] = { 0x01, 0x01, 0xFF }; // a BOOLEAN, not an INTEGER
    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));

    int64_t asInt = 0;
    CHECK_FALSE(reader.readInteger(asInt));
    CHECK_FALSE(reader.atEnd()); // cursor untouched -- can retry as the correct type

    bool asBool = false;
    REQUIRE(reader.readBoolean(asBool));
    CHECK(asBool);
    CHECK(reader.atEnd());
}

TEST_CASE("readInteger / readEnumerated / readNull round-trip") {
    const uint8_t data[] = {
        0x02, 0x02, 0x00, 0x80, // INTEGER 128
        0x0A, 0x01, 0x01,       // ENUMERATED 1
        0x05, 0x00              // NULL
    };
    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));

    int64_t intValue = 0;
    REQUIRE(reader.readInteger(intValue));
    CHECK(intValue == 128);

    uint32_t enumValue = 0;
    REQUIRE(reader.readEnumerated(enumValue));
    CHECK(enumValue == 1);

    REQUIRE(reader.readNull());
    CHECK(reader.atEnd());
}

TEST_CASE("readOctetString (span and COctet overloads) round-trip and reject constructed encodings") {
    const uint8_t data[] = { 0x04, 0x03, 0xDE, 0xAD, 0xBE };
    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));

    SReadOnlyByteSpan outSpan;
    REQUIRE(reader.readOctetString(outSpan));
    REQUIRE(outSpan.size == 3);
    CHECK(outSpan[0] == 0xDE);

    // A constructed (segmented) OCTET STRING isn't reassembled -- must be rejected, not
    // misinterpreted as if its raw nested-TLV bytes were the value.
    const uint8_t constructedData[] = { 0x24, 0x03, 0x04, 0x01, 0xAB };
    CReader constructedReader(SReadOnlyByteSpan(constructedData, sizeof(constructedData)));
    SReadOnlyByteSpan rejected;
    CHECK_FALSE(constructedReader.readOctetString(rejected));

    COctet outOctet;
    CReader octetReader(SReadOnlyByteSpan(data, sizeof(data)));
    REQUIRE(octetReader.readOctetString(outOctet));
    REQUIRE(outOctet.size() == 3);
    CHECK(std::memcmp(outOctet.toPtr(), data + 2, 3) == 0);
}

TEST_CASE("readBitString (span and COctet overloads) round-trip") {
    const uint8_t data[] = { 0x03, 0x02, 0x04, 0xF0 };

    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));
    SReadOnlyByteSpan bits;
    uint8_t unused = 0;
    REQUIRE(reader.readBitString(bits, unused));
    CHECK(unused == 4);
    REQUIRE(bits.size == 1);
    CHECK(bits[0] == 0xF0);

    CReader octetReader(SReadOnlyByteSpan(data, sizeof(data)));
    COctet outBits;
    unused = 0;
    REQUIRE(octetReader.readBitString(outBits, unused));
    CHECK(unused == 4);
    REQUIRE(outBits.size() == 1);
    CHECK(outBits.toPtr()[0] == 0xF0);
}

TEST_CASE("readOid round-trips arc values") {
    const uint8_t data[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));

    uint32_t arcs[7];
    size_t arcCount = 0;
    REQUIRE(reader.readOid(TSpan<uint32_t>(arcs, 7), arcCount));
    REQUIRE(arcCount == 7);
    const uint32_t expected[] = { 1, 2, 840, 113549, 1, 1, 1 };
    for (size_t i = 0; i < 7; ++i) {
        CHECK(arcs[i] == expected[i]);
    }
}

TEST_CASE("readOidString<char> / readOidString<wchar_t> format dotted-decimal text") {
    const uint8_t data[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

    CReader charReader(SReadOnlyByteSpan(data, sizeof(data)));
    TString<char> charValue;
    REQUIRE(charReader.readOidString(charValue));
    CHECK(charValue == TString<char>("1.2.840.113549.1.1.1"));

    CReader wideReader(SReadOnlyByteSpan(data, sizeof(data)));
    TString<wchar_t> wideValue;
    REQUIRE(wideReader.readOidString(wideValue));
    CHECK(wideValue == TString<wchar_t>(L"1.2.840.113549.1.1.1"));
}

TEST_CASE("readText / readString<TChar> validate the requested kind") {
    const uint8_t data[] = { 0x13, 0x05, 'H', 'e', 'l', 'l', 'o' }; // PrintableString "Hello"
    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));

    SReadOnlyByteSpan outText;
    REQUIRE(reader.readText(EAUTAG_STRING_P, outText));
    REQUIRE(outText.size == 5);

    CReader wrongKindReader(SReadOnlyByteSpan(data, sizeof(data)));
    SReadOnlyByteSpan rejected;
    CHECK_FALSE(wrongKindReader.readText(EAUTAG_STRING_IA5, rejected)); // wrong tag value

    CReader stringReader(SReadOnlyByteSpan(data, sizeof(data)));
    TString<wchar_t> outValue;
    REQUIRE(stringReader.readString(EAUTAG_STRING_P, outValue));
    CHECK(outValue == TString<wchar_t>(L"Hello"));
}

TEST_CASE("readUtcTime / readGeneralizedTime round-trip") {
    const uint8_t utc[] = { 0x17, 0x0D, '2','5','0','1','3','1','1','2','0','0','0','0','Z' };
    CReader utcReader(SReadOnlyByteSpan(utc, sizeof(utc)));
    SDateTime time;
    REQUIRE(utcReader.readUtcTime(time));
    CHECK(time.year == 2025);
    CHECK(time.month == 1);
    CHECK(time.day == 31);

    const uint8_t gen[] = { 0x18, 0x0F, '2','0','2','5','0','1','3','1','1','2','0','0','0','0','Z' };
    CReader genReader(SReadOnlyByteSpan(gen, sizeof(gen)));
    SDateTime genTime;
    REQUIRE(genReader.readGeneralizedTime(genTime));
    CHECK(genTime.year == 2025);
}

TEST_CASE("readSequence / readSet / readConstructed descend into nested content") {
    // SEQUENCE { INTEGER 1, INTEGER 2 }
    const uint8_t seqData[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    CReader outer(SReadOnlyByteSpan(seqData, sizeof(seqData)));

    CReader nested;
    REQUIRE(outer.readSequence(nested));
    CHECK(outer.atEnd()); // the outer cursor consumed the whole SEQUENCE TLV

    int64_t first = 0, second = 0;
    REQUIRE(nested.readInteger(first));
    REQUIRE(nested.readInteger(second));
    CHECK(first == 1);
    CHECK(second == 2);
    CHECK(nested.atEnd());

    // Same content re-read via readSet fails (wrong tag: SEQUENCE, not SET).
    CReader outerAgain(SReadOnlyByteSpan(seqData, sizeof(seqData)));
    CReader rejected;
    CHECK_FALSE(outerAgain.readSet(rejected));
    CHECK_FALSE(outerAgain.atEnd());

    // readConstructed accepts any constructed tag and reports it back.
    CReader outerGeneric(SReadOnlyByteSpan(seqData, sizeof(seqData)));
    CTag outTag;
    CReader generic;
    REQUIRE(outerGeneric.readConstructed(outTag, generic));
    CHECK(outTag.hasSameClassAndValue(CTag(EAUTAG_SEQ, true)));
}

TEST_CASE("CReader and CWriter round-trip a nested structure through a real IStream") {
    // Build: SEQUENCE { INTEGER 7, BOOLEAN true, UTF8String "hi", OBJECT IDENTIFIER 2.5.4.3 }
    CTag intTag(EAUTAG_INTEGER, false);
    CTag boolTag(EAUTAG_BOOLEAN, false);

    uint8_t intBuf[8], boolBuf[8], strBuf[16], oidBuf[16];
    size_t wInt = 0, wBool = 0, wStr = 0, wOid = 0;

    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(intBuf, sizeof(intBuf)), EAENC_DER, intTag, SReadOnlyByteSpan((const uint8_t*)"\x07", 1), wInt));
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(boolBuf, sizeof(boolBuf)), EAENC_DER, boolTag, SReadOnlyByteSpan((const uint8_t*)"\xFF", 1), wBool));

    CTag strTag(EAUTAG_STRING_UTF8, false);
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(strBuf, sizeof(strBuf)), EAENC_DER, strTag, SReadOnlyByteSpan((const uint8_t*)"hi", 2), wStr));

    const uint32_t arcs[] = { 2, 5, 4, 3 };
    uint8_t oidContent[8];
    size_t oidContentLen = 0;
    REQUIRE(CEncoder::encodeOid(TSpan<uint8_t>(oidContent, sizeof(oidContent)), TReadOnlySpan<uint32_t>(arcs, 4), oidContentLen));
    CTag oidTag(EAUTAG_OBJ_ID, false);
    REQUIRE(CEncoder::writeEncodedValue(TSpan<uint8_t>(oidBuf, sizeof(oidBuf)), EAENC_DER, oidTag, SReadOnlyByteSpan(oidContent, oidContentLen), wOid));

    SReadOnlyByteSpan children[] = {
        SReadOnlyByteSpan(intBuf, wInt),
        SReadOnlyByteSpan(boolBuf, wBool),
        SReadOnlyByteSpan(strBuf, wStr),
        SReadOnlyByteSpan(oidBuf, wOid),
    };

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeSequence(TReadOnlySpan<SReadOnlyByteSpan>(children, 4)));

    // Read it back from the same stream via CReader.
    REQUIRE(stream->seek(0, ESEEK_SET) == ERET_OK);
    CReader outer(stream);

    CReader seq;
    REQUIRE(outer.readSequence(seq));
    CHECK(outer.atEnd());

    int64_t intValue = 0;
    REQUIRE(seq.readInteger(intValue));
    CHECK(intValue == 7);

    bool boolValue = false;
    REQUIRE(seq.readBoolean(boolValue));
    CHECK(boolValue);

    TString<char> strValue;
    REQUIRE(seq.readString(EAUTAG_STRING_UTF8, strValue));
    CHECK(strValue == TString<char>("hi"));

    TString<char> oidValue;
    REQUIRE(seq.readOidString(oidValue));
    CHECK(oidValue == TString<char>("2.5.4.3"));

    CHECK(seq.atEnd());
}

TEST_CASE("readDistinguishedName reads back a CDistinguishedName written by writeDistinguishedName") {
    CDistinguishedName original;
    REQUIRE(original.trySet(CName(ENAME_CN, "example.com")));
    REQUIRE(original.trySet(CName(ENAME_OU, "Engineering")));
    REQUIRE(original.trySet(CName(ENAME_C, "US")));

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeDistinguishedName(original));
    REQUIRE(stream->seek(0, ESEEK_SET) == ERET_OK);

    CReader reader(stream);
    CDistinguishedName decoded;
    REQUIRE(reader.readDistinguishedName(decoded));
    CHECK(reader.atEnd());
    CHECK(decoded == original);
}

TEST_CASE("readDistinguishedName round-trips an empty distinguished name") {
    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeDistinguishedName(CDistinguishedName()));
    REQUIRE(stream->seek(0, ESEEK_SET) == ERET_OK);

    CReader reader(stream);
    CDistinguishedName decoded;
    REQUIRE(decoded.trySet(CName(ENAME_OU, "leftover")));
    REQUIRE(reader.readDistinguishedName(decoded));
    CHECK(decoded.empty());
}

TEST_CASE("readDistinguishedName leaves the cursor unchanged on a tag mismatch") {
    const uint8_t data[] = { 0x01, 0x01, 0xFF }; // BOOLEAN true, not a SEQUENCE
    CReader reader(SReadOnlyByteSpan(data, sizeof(data)));

    CDistinguishedName decoded;
    CHECK_FALSE(reader.readDistinguishedName(decoded));

    // Cursor must be untouched, so a different typed read still succeeds on the same data.
    bool value = false;
    REQUIRE(reader.readBoolean(value));
    CHECK(value);
}

TEST_CASE("readDistinguishedName rejects a malformed structure and leaves the cursor unchanged") {
    CDistinguishedName dn;
    REQUIRE(dn.trySet(CName(ENAME_C, "US")));

    IStreamPtr stream = IStream::createMemory();
    CWriter writer(stream);
    REQUIRE(writer.writeDistinguishedName(dn));
    auto bytes = snapshot(stream);

    // Corrupt the AttributeTypeAndValue's SEQUENCE tag (offset 4: outer SEQ tag+len(2) + RDN SET
    // tag+len(2)) into a SET, making the structure invalid.
    REQUIRE(bytes[4] == 0x30);
    bytes[4] = 0x31;

    CReader reader(SReadOnlyByteSpan(bytes.data(), bytes.size()));
    CDistinguishedName decoded;
    CHECK_FALSE(reader.readDistinguishedName(decoded));

    // Cursor must be untouched despite the nested parse failure -- the same (still-intact) outer
    // SEQUENCE tag can still be read as a generic constructed value.
    CTag outTag;
    CReader nested;
    REQUIRE(reader.readConstructed(outTag, nested));
}
