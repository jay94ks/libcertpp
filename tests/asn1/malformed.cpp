#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/der.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::asn1;

/* Adversarial / negative-input tests for the asn1 TLV header and per-type codecs.
 *
 * Every other test under tests/asn1/ feeds the decoder bytes CEncoder itself produced, so the
 * DER-strictness gates -- the rules that exist purely to reject an encoding a *different*
 * producer could have made -- were effectively untested. These are hand-built malformed TLVs,
 * each one violating exactly one named X.690 clause, asserting the decoder rejects it.
 *
 * A TEST_CASE whose name starts with "known gap" documents something this library currently
 * accepts but shouldn't; its failing assertions use WARN so the suite stays green while still
 * reporting the gap on every run. Do not downgrade those to match the current behavior.
 */

namespace {
    /* Runs readEncodedValue over a raw byte array and reports only whether it accepted. */
    bool readsOk(const uint8_t* data, size_t size, EEncodingRule ruleSet) {
        CTag tag;
        SReadOnlyByteSpan area;
        size_t bytesRead = 0;

        return CDecoder::readEncodedValue(SReadOnlyByteSpan(data, size), ruleSet, tag, area, bytesRead);
    }

    /* Builds `levels` nested indefinite-length SEQUENCEs, each closed with its own EOC marker. */
    std::vector<uint8_t> nestIndefinite(size_t levels) {
        std::vector<uint8_t> data;

        for (size_t i = 0; i < levels; ++i) {
            data.push_back(0x30);
            data.push_back(0x80);
        }

        for (size_t i = 0; i < levels; ++i) {
            data.push_back(0x00);
            data.push_back(0x00);
        }

        return data;
    }
}

// --------------------------------------------------------------------------------------------
// Length octets -- X.690 8.1.3 (form), 10.1 / 11 (DER/CER canonical restrictions).
// --------------------------------------------------------------------------------------------

/* X.690 8.1.3.5 (c): the length-octet count 1111111 (i.e. a leading octet of 0xFF) is reserved
 * for future additions and shall not be used. Rejected under every rule set, not just DER. */
TEST_CASE("readEncodedValue rejects the reserved 0xFF length form") {
    const uint8_t data[] = { 0x04, 0xFF, 0x01, 0x02, 0x03, 0x04 };

    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_CER));
    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_BER));
}

/* X.690 10.1: DER/CER require the minimum number of length octets, so a length of 5 may not be
 * written with two of them. BER permits it, which is exactly why the gate has to be rule-aware
 * -- the one pre-existing long-form test in tests/asn1/decoder.cpp runs under BER and so never
 * reached this branch. */
TEST_CASE("readEncodedValue rejects a non-minimal long-form length under DER/CER") {
    const uint8_t data[] = { 0x04, 0x82, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };

    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_CER));

    // --> The same bytes are a legal (if wasteful) BER encoding, so BER must still accept them.
    CHECK(readsOk(data, sizeof(data), EAENC_BER));
}

/* X.690 10.1: a definite length below 128 shall use the short form. 0x81 0x05 encodes 5 in the
 * long form, which DER/CER forbid even though no padding octet is involved. */
TEST_CASE("readEncodedValue rejects the long form for a length below 128 under DER/CER") {
    const uint8_t data[] = { 0x04, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };

    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_CER));
    CHECK(readsOk(data, sizeof(data), EAENC_BER));
}

/* A length octet count wider than a size_t can hold -- the value is unrepresentable, so it must
 * be refused up front (EDEC_TOO_BIG) rather than silently truncated into a small length that
 * then "fits" the buffer. 9 octets exceeds sizeof(size_t) on both 32- and 64-bit builds. */
TEST_CASE("readEncodedValue rejects a length whose octet count exceeds sizeof(size_t)") {
    const uint8_t data[] = {
        0x04, 0x89,                                                 // OCTET STRING, 9 length octets
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00        // 2^64 -- unrepresentable
    };

    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_BER));
}

TEST_CASE("readEncodedValue rejects a truncated header") {
    SUBCASE("tag octet with no length octet") {
        const uint8_t data[] = { 0x30 };
        CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    }

    SUBCASE("long form with fewer length octets than its count declares") {
        const uint8_t data[] = { 0x04, 0x82, 0x01 }; // declares 2 length octets, supplies 1
        CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    }

    SUBCASE("high-tag-number form with no subsequent octet") {
        const uint8_t data[] = { 0x1F };
        CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    }

    SUBCASE("high-tag-number form whose continuation never terminates") {
        const uint8_t data[] = { 0x1F, 0x81, 0x81 }; // every octet sets the continuation bit
        CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    }
}

TEST_CASE("readEncodedValue rejects a TLV whose declared length runs past the buffer") {
    SUBCASE("short form") {
        const uint8_t data[] = { 0x04, 0x05, 0x01, 0x02 }; // declares 5 content octets, supplies 2
        CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    }

    SUBCASE("long form") {
        // Declares 256 content octets; only 8 are present. A length this far past the end is the
        // classic over-read primitive, so it must fail at the header check, not at the copy.
        const uint8_t data[] = {
            0x04, 0x82, 0x01, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };
        CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    }

    SUBCASE("length exactly one octet past the end") {
        const uint8_t data[] = { 0x04, 0x03, 0x01, 0x02 };
        CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    }
}

/* X.690 10.1: DER has no indefinite-length form at all. tests/asn1/decoder.cpp covers the
 * outermost value; this covers a child of an otherwise well-formed definite-length SEQUENCE,
 * i.e. that the gate is applied at every depth rather than only at the entry point. */
TEST_CASE("readNextElement rejects an indefinite-length child inside a definite DER SEQUENCE") {
    const uint8_t data[] = {
        0x30, 0x04,             // SEQUENCE, definite length 4
        0x30, 0x80, 0x00, 0x00  // child SEQUENCE, indefinite length, empty
    };

    CTag tag;
    SReadOnlyByteSpan content;
    size_t bytesRead = 0;

    REQUIRE(CDecoder::readEncodedValue(SReadOnlyByteSpan(data, sizeof(data)), EAENC_DER, tag, content, bytesRead));
    REQUIRE(bytesRead == sizeof(data));

    CTag childTag;
    SReadOnlyByteSpan childContent;
    CHECK_FALSE(CDecoder::readNextElement(content, EAENC_DER, childTag, childContent));

    // --> The same child is legal BER, so the rejection above is the rule set talking, not a
    // malformed-bytes accident.
    SReadOnlyByteSpan berContent = content;
    CHECK(CDecoder::readNextElement(berContent, EAENC_BER, childTag, childContent));
}

/* The indefinite-length nesting guard is what keeps a deeply-nested BER document from
 * exhausting the stack, so the boundary itself is worth pinning: CDecoder::MAX_NESTING_DEPTH is
 * 64, and an off-by-one either way is a bug (too low rejects valid input, too high is the
 * crash). tests/asn1/decoder.cpp only checks a depth of 100. */
TEST_CASE("readEncodedValue's indefinite-length nesting guard sits exactly at 64 levels") {
    const std::vector<uint8_t> atLimit = nestIndefinite(64);
    CHECK(readsOk(atLimit.data(), atLimit.size(), EAENC_BER));

    const std::vector<uint8_t> overLimit = nestIndefinite(65);
    CHECK_FALSE(readsOk(overLimit.data(), overLimit.size(), EAENC_BER));

    const std::vector<uint8_t> farOverLimit = nestIndefinite(4096);
    CHECK_FALSE(readsOk(farOverLimit.data(), farOverLimit.size(), EAENC_BER));
}

// --------------------------------------------------------------------------------------------
// Identifier octets -- X.690 8.1.2.
// --------------------------------------------------------------------------------------------

/* X.690 8.1.2.4.2 (c): in the high-tag-number form, bits 7 to 1 of the first subsequent octet
 * shall not all be zero -- a leading 0x80 is padding, and admitting it would give every
 * high-numbered tag unboundedly many encodings. */
TEST_CASE("readEncodedValue rejects a non-minimal high-tag-number form") {
    const uint8_t padded[] = { 0x1F, 0x80, 0x1F, 0x00 }; // tag 31, written with a padding octet
    CHECK_FALSE(readsOk(padded, sizeof(padded), EAENC_DER));
    CHECK_FALSE(readsOk(padded, sizeof(padded), EAENC_BER));

    const uint8_t minimal[] = { 0x1F, 0x1F, 0x00 }; // the only legal encoding of tag 31
    CHECK(readsOk(minimal, sizeof(minimal), EAENC_DER));
}

/* X.690 8.1.2.4.1: the high-tag-number form is for tag numbers 31 and above; a tag number that
 * fits in the low form must use it. */
TEST_CASE("readEncodedValue rejects the high-tag-number form for a tag below 31") {
    const uint8_t data[] = { 0x1F, 0x1E, 0x00 }; // tag 30 in the high form
    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_DER));
    CHECK_FALSE(readsOk(data, sizeof(data), EAENC_BER));
}

// --------------------------------------------------------------------------------------------
// BIT STRING -- X.690 8.6, 11.2.
// --------------------------------------------------------------------------------------------

TEST_CASE("decodeBitString rejects an out-of-range unused-bit count") {
    SReadOnlyByteSpan bits;
    uint8_t unusedBits = 0;

    // X.690 8.6.2.2: the initial octet is the number of unused bits, 0 to 7. 8 is the
    // off-by-one an implementation gets wrong by writing "> 8" or ">= 8" on the wrong side.
    const uint8_t eight[] = { 0x08, 0x00 };
    CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(eight, sizeof(eight)), bits, unusedBits));

    const uint8_t max[] = { 0xFF, 0x00 };
    CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(max, sizeof(max)), bits, unusedBits));

    const uint8_t seven[] = { 0x07, 0x80 }; // 7 is in range, and its padding bits are zero
    CHECK(CDecoder::decodeBitString(SReadOnlyByteSpan(seven, sizeof(seven)), bits, unusedBits));
}

/* X.690 11.2.1: under DER the unused bits of the final octet shall each be zero. Accepting a
 * non-zero pad would give every BIT STRING 2^unusedBits distinct encodings -- for an X.509
 * signature or a KeyUsage, that is direct malleability. */
TEST_CASE("decodeBitString rejects non-zero padding bits") {
    SReadOnlyByteSpan bits;
    uint8_t unusedBits = 0;

    const uint8_t lowBitSet[] = { 0x07, 0x81 }; // 7 unused bits, but bit 0 of the pad is 1
    CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(lowBitSet, sizeof(lowBitSet)), bits, unusedBits));

    const uint8_t allPadSet[] = { 0x07, 0xFF };
    CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(allPadSet, sizeof(allPadSet)), bits, unusedBits));

    const uint8_t oneUnused[] = { 0x01, 0x03 }; // 1 unused bit, set
    CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(oneUnused, sizeof(oneUnused)), bits, unusedBits));
}

/* X.690 8.6.2.3: if the bit string is empty there shall be no subsequent octets and the initial
 * octet shall be zero -- "4 unused bits of nothing" is not a thing. */
TEST_CASE("decodeBitString rejects a non-zero unused-bit count with no data octets") {
    SReadOnlyByteSpan bits;
    uint8_t unusedBits = 0;

    const uint8_t data[] = { 0x04 };
    CHECK_FALSE(CDecoder::decodeBitString(SReadOnlyByteSpan(data, sizeof(data)), bits, unusedBits));

    const uint8_t empty[] = { 0x00 }; // the one legal encoding of the empty BIT STRING
    CHECK(CDecoder::decodeBitString(SReadOnlyByteSpan(empty, sizeof(empty)), bits, unusedBits));
    CHECK(bits.empty());
}

// --------------------------------------------------------------------------------------------
// INTEGER -- X.690 8.3.2.
// --------------------------------------------------------------------------------------------

/* X.690 8.3.2: the first 9 bits of an INTEGER's content shall not be all zero or all one, i.e.
 * a leading 0x00/0xFF that merely sign-extends the next octet is prohibited. CDer::readBigInteger
 * is the arbitrary-precision sibling of CDecoder::decodeInteger and reaches every DER-encoded
 * signature and public key this library parses; it missed this rule until recently, and a
 * redundant pad byte there is signature malleability. This locks the fix in. */
TEST_CASE("CDer::readBigInteger rejects a non-minimal INTEGER") {
    CBigNum value;

    SUBCASE("one redundant 0x00") {
        const uint8_t data[] = { 0x02, 0x02, 0x00, 0x05 }; // 5, paddable to one octet
        SReadOnlyByteSpan cursor(data, sizeof(data));
        CHECK_FALSE(CDer::readBigInteger(cursor, value));
    }

    SUBCASE("two redundant 0x00s") {
        const uint8_t data[] = { 0x02, 0x03, 0x00, 0x00, 0x05 };
        SReadOnlyByteSpan cursor(data, sizeof(data));
        CHECK_FALSE(CDer::readBigInteger(cursor, value));
    }

    SUBCASE("a 0x00 that only pads a zero") {
        const uint8_t data[] = { 0x02, 0x02, 0x00, 0x00 };
        SReadOnlyByteSpan cursor(data, sizeof(data));
        CHECK_FALSE(CDer::readBigInteger(cursor, value));
    }

    SUBCASE("a leading 0x00 that genuinely carries the sign is still accepted") {
        const uint8_t data[] = { 0x02, 0x02, 0x00, 0x80 }; // 128; the pad is required here
        SReadOnlyByteSpan cursor(data, sizeof(data));
        REQUIRE(CDer::readBigInteger(cursor, value));
        CHECK(value == CBigNum(uint64_t(128)));
    }

    SUBCASE("an empty INTEGER has no valid value") {
        const uint8_t data[] = { 0x02, 0x00 };
        SReadOnlyByteSpan cursor(data, sizeof(data));
        CHECK_FALSE(CDer::readBigInteger(cursor, value));
    }
}

TEST_CASE("CDecoder::decodeInteger rejects every redundant sign-extension octet") {
    int64_t value = 0;

    const uint8_t zeroPaddedZero[] = { 0x00, 0x00 };
    CHECK_FALSE(CDecoder::decodeInteger(SReadOnlyByteSpan(zeroPaddedZero, sizeof(zeroPaddedZero)), value));

    const uint8_t onePaddedNegative[] = { 0xFF, 0xFF }; // -1, paddable to one octet
    CHECK_FALSE(CDecoder::decodeInteger(SReadOnlyByteSpan(onePaddedNegative, sizeof(onePaddedNegative)), value));

    const uint8_t zeroPadded127[] = { 0x00, 0x7F };
    CHECK_FALSE(CDecoder::decodeInteger(SReadOnlyByteSpan(zeroPadded127, sizeof(zeroPadded127)), value));

    // --> The counterpart that must still pass: a pad carrying the sign of a 0x80-topped value.
    const uint8_t signCarrying[] = { 0x00, 0xFF };
    REQUIRE(CDecoder::decodeInteger(SReadOnlyByteSpan(signCarrying, sizeof(signCarrying)), value));
    CHECK(value == 255);
}

/* Regression lock: trailing bytes past the outer SEQUENCE used to be ignored, which let an
 * attacker append arbitrary data to a DER signature and have it still verify -- enough to break
 * any scheme that identifies a signed object by its signature bytes. */
TEST_CASE("CDer::readOuterSequence rejects trailing bytes after the SEQUENCE") {
    SReadOnlyByteSpan content;

    const uint8_t oneTrailingByte[] = {
        0x30, 0x03, 0x02, 0x01, 0x01, // SEQUENCE { INTEGER 1 }
        0x00                          // garbage
    };
    CHECK_FALSE(CDer::readOuterSequence(SReadOnlyByteSpan(oneTrailingByte, sizeof(oneTrailingByte)), content));

    const uint8_t trailingTlv[] = {
        0x30, 0x03, 0x02, 0x01, 0x01,
        0x02, 0x01, 0x02              // a whole second, well-formed TLV
    };
    CHECK_FALSE(CDer::readOuterSequence(SReadOnlyByteSpan(trailingTlv, sizeof(trailingTlv)), content));

    const uint8_t exact[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    CHECK(CDer::readOuterSequence(SReadOnlyByteSpan(exact, sizeof(exact)), content));
}

// --------------------------------------------------------------------------------------------
// OBJECT IDENTIFIER -- X.690 8.19.
// --------------------------------------------------------------------------------------------

/* X.690 8.19.2: each subidentifier is base-128 with the minimum number of octets, so its
 * leading octet is never 0x80. Without this, every OID has infinitely many encodings, and an
 * OID is how this library dispatches on algorithms, extensions and name attributes -- two
 * encodings of the same OID means an extension that one parser honours and another skips. */
TEST_CASE("OBJECT IDENTIFIER decoding rejects a non-minimal subidentifier") {
    SUBCASE("padding in a trailing subidentifier") {
        const uint8_t data[] = { 0x2A, 0x80, 0x01 }; // 1.2.1, with arc 1 padded to two octets
        SReadOnlyByteSpan span(data, sizeof(data));

        CHECK(CDecoder::countOidArcs(span) == 0);

        uint32_t arcs[8];
        size_t arcCount = 0;
        CHECK_FALSE(CDecoder::decodeOid(span, TSpan<uint32_t>(arcs, 8), arcCount));

        CString text;
        CHECK_FALSE(CDecoder::decodeOidString(span, text));
    }

    SUBCASE("padding in the first (joint) subidentifier") {
        const uint8_t data[] = { 0x80, 0x2A }; // 1.2, with the joint arc padded
        SReadOnlyByteSpan span(data, sizeof(data));

        CHECK(CDecoder::countOidArcs(span) == 0);

        uint32_t arcs[8];
        size_t arcCount = 0;
        CHECK_FALSE(CDecoder::decodeOid(span, TSpan<uint32_t>(arcs, 8), arcCount));
    }

    SUBCASE("a legitimately multi-octet subidentifier is still accepted") {
        const uint8_t data[] = { 0x2A, 0x86, 0x48 }; // 1.2.840 -- 840 needs two octets
        SReadOnlyByteSpan span(data, sizeof(data));

        REQUIRE(CDecoder::countOidArcs(span) == 3);

        uint32_t arcs[3];
        size_t arcCount = 0;
        REQUIRE(CDecoder::decodeOid(span, TSpan<uint32_t>(arcs, 3), arcCount));
        CHECK(arcCount == 3);
        CHECK(arcs[2] == 840);
    }
}

TEST_CASE("OBJECT IDENTIFIER decoding rejects truncated and empty content") {
    uint32_t arcs[8];
    size_t arcCount = 0;

    // The final subidentifier sets the continuation bit but nothing follows it.
    const uint8_t truncated[] = { 0x2A, 0x86 };
    CHECK(CDecoder::countOidArcs(SReadOnlyByteSpan(truncated, sizeof(truncated))) == 0);
    CHECK_FALSE(CDecoder::decodeOid(SReadOnlyByteSpan(truncated, sizeof(truncated)), TSpan<uint32_t>(arcs, 8), arcCount));

    // X.690 8.19.1: an OID has at least one subidentifier, so empty content is never valid.
    CHECK(CDecoder::countOidArcs(SReadOnlyByteSpan(nullptr, 0)) == 0);
    CHECK_FALSE(CDecoder::decodeOid(SReadOnlyByteSpan(nullptr, 0), TSpan<uint32_t>(arcs, 8), arcCount));
}

TEST_CASE("OBJECT IDENTIFIER decoding rejects a subidentifier wider than a uint32_t") {
    uint32_t arcs[8];
    size_t arcCount = 0;

    SUBCASE("an arc of exactly 2^32-1 still fits and is accepted") {
        const uint8_t data[] = { 0x2A, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F }; // 1.2.4294967295
        SReadOnlyByteSpan span(data, sizeof(data));

        REQUIRE(CDecoder::countOidArcs(span) == 3);
        REQUIRE(CDecoder::decodeOid(span, TSpan<uint32_t>(arcs, 8), arcCount));
        CHECK(arcCount == 3);
        CHECK(arcs[2] == 0xFFFFFFFFu);
    }

    SUBCASE("one more than that overflows and must be refused, not wrapped") {
        const uint8_t data[] = { 0x2A, 0x90, 0xFF, 0xFF, 0xFF, 0x7F }; // 4563402751 > 2^32-1
        SReadOnlyByteSpan span(data, sizeof(data));

        CHECK(CDecoder::countOidArcs(span) == 0);
        CHECK_FALSE(CDecoder::decodeOid(span, TSpan<uint32_t>(arcs, 8), arcCount));
    }
}

// --------------------------------------------------------------------------------------------
// UTCTime / GeneralizedTime -- X.690 11.7-11.8, RFC 5280 4.1.2.5.
// --------------------------------------------------------------------------------------------

TEST_CASE("decodeUtcTime rejects an impossible calendar date") {
    SDateTime time;

    const uint8_t feb30[] = "240230000000Z"; // 2024 is a leap year, but February still ends at 29
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(feb30, 13), time));

    const uint8_t feb29NonLeap[] = "230229000000Z";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(feb29NonLeap, 13), time));

    const uint8_t apr31[] = "240431000000Z";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(apr31, 13), time));

    const uint8_t dayZero[] = "240100000000Z";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(dayZero, 13), time));

    const uint8_t monthZero[] = "240015000000Z";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(monthZero, 13), time));

    const uint8_t hour24[] = "240115240000Z";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(hour24, 13), time));

    const uint8_t minute60[] = "240115126000Z";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(minute60, 13), time));

    const uint8_t second60[] = "240115120060Z"; // X.690 has no leap second in this form
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(second60, 13), time));
}

/* RFC 5280 4.1.2.5.1: YY >= 50 means 19YY, YY <= 49 means 20YY. The pivot is the kind of
 * constant that gets "fixed" to 70 (the Unix epoch) or 49 by a passing glance, and either
 * mistake silently moves a certificate's validity window by a century. */
TEST_CASE("decodeUtcTime applies RFC 5280's century pivot at exactly YY=50") {
    SDateTime time;

    const uint8_t yy49[] = "490101000000Z";
    REQUIRE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(yy49, 13), time));
    CHECK(time.year == 2049);

    const uint8_t yy50[] = "500101000000Z";
    REQUIRE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(yy50, 13), time));
    CHECK(time.year == 1950);

    const uint8_t yy00[] = "000101000000Z";
    REQUIRE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(yy00, 13), time));
    CHECK(time.year == 2000);

    const uint8_t yy99[] = "990101000000Z";
    REQUIRE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(yy99, 13), time));
    CHECK(time.year == 1999);
}

/* X.690 11.8.1 plus RFC 5280 4.1.2.5.1: a UTCTime in a certificate is exactly YYMMDDHHMMSSZ --
 * seconds are mandatory and the only permitted zone is Z, so neither the seconds-omitted form
 * nor a numeric offset is acceptable, however legal they may be in unrestricted BER. */
TEST_CASE("decodeUtcTime requires the full seconds-plus-Z form") {
    SDateTime time;

    const uint8_t noSeconds[] = "2401151200Z"; // YYMMDDHHMMZ
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(noSeconds, 11), time));

    const uint8_t noZone[] = "240115120000";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(noZone, 12), time));

    const uint8_t numericOffset[] = "240115120000+0900";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(numericOffset, 17), time));

    const uint8_t lowercaseZone[] = "240115120000z";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(lowercaseZone, 13), time));

    const uint8_t nonDigit[] = "2401151X0000Z";
    CHECK_FALSE(CDecoder::decodeUtcTime(SReadOnlyByteSpan(nonDigit, 13), time));
}

TEST_CASE("decodeGeneralizedTime rejects an impossible date and a non-Z time zone") {
    SDateTime time;

    const uint8_t feb30[] = "20240230000000Z";
    CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(feb30, 15), time));

    const uint8_t month13[] = "20241301000000Z";
    CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(month13, 15), time));

    // X.690 11.7.1: the only permitted zone is Z; a local-time or offset form is not DER.
    const uint8_t numericOffset[] = "20240115120000+0900";
    CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(numericOffset, 19), time));

    const uint8_t localTime[] = "20240115120000";
    CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(localTime, 14), time));

    // X.690 11.7.2/11.7.3: seconds are mandatory and must not be omitted.
    const uint8_t noSeconds[] = "202401151200Z";
    CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(noSeconds, 13), time));

    // X.690 11.7.5: a fractional part with no digits after the point is not permitted.
    const uint8_t emptyFraction[] = "20240115120000.Z";
    CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(emptyFraction, 16), time));

    // X.690 11.7.4: the separator shall be a full stop, not a comma.
    const uint8_t commaSeparator[] = "20240115120000,5Z";
    CHECK_FALSE(CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan(commaSeparator, 17), time));
}
