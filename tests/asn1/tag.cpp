#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/asn1/tag.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::asn1;

TEST_CASE("default-constructed CTag is invalid") {
    CTag tag;

    CHECK_FALSE(tag.isValid());
    CHECK_FALSE(bool(tag));
    CHECK(!tag);
    CHECK(tag.tagClass() == EATAG_INVALID);
}

TEST_CASE("Shortcut constants produce the expected class/constructed/value") {
    CHECK(CTag(CTag::EOC).tagClass() == EATAG_UNIVERSAL);
    CHECK(CTag(CTag::EOC).value() == uint32_t(EAUTAG_EOC));
    CHECK_FALSE(CTag(CTag::EOC).isConstructed());

    CHECK(CTag(CTag::BOOLEAN).value() == uint32_t(EAUTAG_BOOLEAN));
    CHECK(CTag(CTag::INTEGER).value() == uint32_t(EAUTAG_INTEGER));

    CHECK(CTag(CTag::STRING_BIT).isConstructed() == false);
    CHECK(CTag(CTag::CONSTRUCTED_STRING_BIT).isConstructed());
    CHECK(CTag(CTag::STRING_BIT).value() == CTag(CTag::CONSTRUCTED_STRING_BIT).value());

    CHECK(CTag(CTag::SEQ).isConstructed());
    CHECK(CTag(CTag::SEQ).value() == uint32_t(EAUTAG_SEQ));
    CHECK(CTag(CTag::SET_OF).isConstructed());

    CHECK(CTag(CTag::NULL_).value() == uint32_t(EAUTAG_NULL));
    CHECK(CTag(CTag::TIME_UTC_).value() == uint32_t(EAUTAG_TIME_UTC));

    CHECK(CTag(CTag::EOC).isValid());
}

TEST_CASE("EUniversalTags constructor") {
    SUBCASE("valid tag, primitive and constructed") {
        CTag primitive(EAUTAG_SEQ, false);
        CTag constructed(EAUTAG_SEQ, true);

        REQUIRE(primitive.isValid());
        REQUIRE(constructed.isValid());
        CHECK_FALSE(primitive.isConstructed());
        CHECK(constructed.isConstructed());
        CHECK(primitive.tagClass() == EATAG_UNIVERSAL);
        CHECK(primitive.value() == uint32_t(EAUTAG_SEQ));
    }

    SUBCASE("the reserved universal tag number (15) is invalid") {
        CTag reserved(EUniversalTags(15));
        CHECK_FALSE(reserved.isValid());
    }

    SUBCASE("EAUTAG_MAX and beyond are invalid") {
        CTag atMax(EAUTAG_MAX);
        CTag beyondMax(EUniversalTags(100));

        CHECK_FALSE(atMax.isValid());
        CHECK_FALSE(beyondMax.isValid());
    }
}

TEST_CASE("ETagClass constructor") {
    SUBCASE("each defined class is valid") {
        CHECK(CTag(EATAG_UNIVERSAL, 5).isValid());
        CHECK(CTag(EATAG_APPLICATION, 5).isValid());
        CHECK(CTag(EATAG_CONTEXT_SPECIFIC, 5).isValid());
        CHECK(CTag(EATAG_PRIVATE, 5).isValid());
    }

    SUBCASE("class/value/constructed are preserved") {
        CTag tag(EATAG_CONTEXT_SPECIFIC, 3, true);

        CHECK(tag.tagClass() == EATAG_CONTEXT_SPECIFIC);
        CHECK(tag.value() == 3);
        CHECK(tag.isConstructed());
    }

    SUBCASE("a class value outside the four defined ones is invalid") {
        CTag bogus(ETagClass(0x20), 1);
        CHECK_FALSE(bogus.isValid());
    }
}

TEST_CASE("copy/move construction and assignment preserve the tag") {
    CTag original(EATAG_CONTEXT_SPECIFIC, 7, true);

    CTag copied(original);
    CHECK(copied.tagClass() == original.tagClass());
    CHECK(copied.value() == original.value());
    CHECK(copied.isConstructed() == original.isConstructed());

    CTag moved(std::move(copied));
    CHECK(moved.value() == 7);

    CTag assigned;
    assigned = original;
    CHECK(assigned.value() == 7);
    CHECK(assigned.isConstructed());

    CTag moveAssigned;
    moveAssigned = std::move(assigned);
    CHECK(moveAssigned.value() == 7);
}

TEST_CASE("asConstructed / asPrimitive toggle the constructed flag only") {
    CTag primitive(EATAG_CONTEXT_SPECIFIC, 9, false);

    CTag asConstructed = primitive.asConstructed();
    CHECK(asConstructed.isConstructed());
    CHECK(asConstructed.tagClass() == primitive.tagClass());
    CHECK(asConstructed.value() == primitive.value());

    CTag backToPrimitive = asConstructed.asPrimitive();
    CHECK_FALSE(backToPrimitive.isConstructed());
    CHECK(backToPrimitive.value() == primitive.value());
}

TEST_CASE("asConstructed / asPrimitive on an invalid tag stay invalid") {
    CTag invalid;

    CHECK_FALSE(invalid.asConstructed().isValid());
    CHECK_FALSE(invalid.asPrimitive().isValid());
}

TEST_CASE("encodedSize at each tag-number length boundary") {
    struct Case { uint32_t value; size_t expectedSize; };
    const Case cases[] = {
        { 0, 1 }, { 30, 1 },
        { 31, 2 }, { 127, 2 },
        { 128, 3 }, { 16383, 3 },
        { 16384, 4 }, { 2097151, 4 },
        { 2097152, 5 }, { 268435455, 5 },
        { 268435456, 6 },
    };

    for (const auto& c : cases) {
        CAPTURE(c.value);
        CTag tag(EATAG_CONTEXT_SPECIFIC, c.value);
        REQUIRE(tag.isValid());
        CHECK(tag.encodedSize() == c.expectedSize);
    }

    CHECK(CTag().encodedSize() == 0);
}

TEST_CASE("encode/decode round-trip across tag-number length boundaries") {
    const uint32_t values[] = { 0, 30, 31, 127, 128, 16383, 16384, 2097151, 2097152, 268435455 };

    for (uint32_t v : values) {
        CAPTURE(v);

        for (bool constructed : { false, true }) {
            CAPTURE(constructed);

            CTag tag(EATAG_CONTEXT_SPECIFIC, v, constructed);
            REQUIRE(tag.isValid());

            uint8_t buf[8];
            size_t written = 0;
            REQUIRE(tag.encode(TSpan<uint8_t>(buf, sizeof(buf)), written));
            CHECK(written == tag.encodedSize());

            size_t bytesRead = 0;
            CTag decoded = CTag::decode(TReadOnlySpan<uint8_t>(buf, written), bytesRead);

            REQUIRE(decoded.isValid());
            CHECK(bytesRead == written);
            CHECK(decoded.tagClass() == tag.tagClass());
            CHECK(decoded.isConstructed() == tag.isConstructed());
            CHECK(decoded.value() == tag.value());
            CHECK(decoded.hasSameClassAndValue(tag));
            CHECK(decoded == tag);
        }
    }
}

TEST_CASE("encode rejects a destination too small") {
    CTag tag(EATAG_CONTEXT_SPECIFIC, 1000); // needs 3 bytes
    uint8_t buf[2];
    size_t written = 0;

    CHECK_FALSE(tag.encode(TSpan<uint8_t>(buf, sizeof(buf)), written));
}

TEST_CASE("encode rejects an invalid tag") {
    CTag invalid;
    uint8_t buf[8];
    size_t written = 0;

    CHECK_FALSE(invalid.encode(TSpan<uint8_t>(buf, sizeof(buf)), written));
}

TEST_CASE("decode rejects empty input") {
    size_t bytesRead = 0;
    CTag decoded = CTag::decode(SReadOnlyByteSpan(nullptr, 0), bytesRead);

    CHECK_FALSE(decoded.isValid());
    CHECK(bytesRead == 0);
}

TEST_CASE("decode rejects a truncated multi-byte tag number") {
    const uint8_t data[] = { 0x1F, 0xFF }; // escape + a continuation byte with no terminator
    size_t bytesRead = 0;
    CTag decoded = CTag::decode(SReadOnlyByteSpan(data, sizeof(data)), bytesRead);

    CHECK_FALSE(decoded.isValid());
    CHECK(bytesRead == 0);
}

TEST_CASE("decode rejects a non-minimal multi-byte encoding of a small tag number") {
    // Tag number 5 fits in the short form; spelling it out via the escape form is invalid.
    const uint8_t data[] = { 0x1F, 0x05 };
    size_t bytesRead = 0;
    CTag decoded = CTag::decode(SReadOnlyByteSpan(data, sizeof(data)), bytesRead);

    CHECK_FALSE(decoded.isValid());
    CHECK(bytesRead == 0);
}

TEST_CASE("decode rejects a tag number that overflows the supported range") {
    const uint8_t data[] = { 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    size_t bytesRead = 0;
    CTag decoded = CTag::decode(SReadOnlyByteSpan(data, sizeof(data)), bytesRead);

    CHECK_FALSE(decoded.isValid());
    CHECK(bytesRead == 0);
}

TEST_CASE("equals / operator== compare tag identity, not incidental encoding bits") {
    // Regression test: CTag::decode() stores the raw first octet (whose low 5 bits carry the
    // short-form tag number, e.g. 0x02 for INTEGER) as _flags, while the ETagClass/Shortcut/
    // EUniversalTags constructors always leave _flags' low 5 bits at 0 (the tag number lives
    // in _value instead). A decoded tag and a constructed tag representing the identical
    // ASN.1 tag must still compare equal.
    const uint8_t encoded[] = { 0x02 }; // UNIVERSAL, primitive, tag number 2 (INTEGER)
    size_t bytesRead = 0;
    CTag decoded = CTag::decode(SReadOnlyByteSpan(encoded, sizeof(encoded)), bytesRead);

    CTag constructed(EAUTAG_INTEGER, false);

    REQUIRE(decoded.isValid());
    REQUIRE(constructed.isValid());
    CHECK(decoded.hasSameClassAndValue(constructed));
    CHECK(decoded.equals(constructed));
    CHECK(decoded == constructed);
    CHECK_FALSE(decoded != constructed);
}

TEST_CASE("equals / operator== treat any two invalid tags as equal") {
    CTag a, b;
    CHECK(a.equals(b));
    CHECK(a == b);
}

TEST_CASE("equals / operator== distinguish valid from invalid") {
    CTag valid(EAUTAG_INTEGER, false);
    CTag invalid;

    CHECK_FALSE(valid.equals(invalid));
    CHECK_FALSE(invalid.equals(valid));
    CHECK(valid != invalid);
}

TEST_CASE("hasSameClass / hasSameValue / hasSameClassAndValue") {
    CTag a(EATAG_CONTEXT_SPECIFIC, 5, false);
    CTag b(EATAG_CONTEXT_SPECIFIC, 5, true);   // same class/value, different constructed flag
    CTag c(EATAG_CONTEXT_SPECIFIC, 6, false);  // different value
    CTag d(EATAG_APPLICATION, 5, false);       // different class

    CHECK(a.hasSameClass(b));
    CHECK(a.hasSameValue(b));
    CHECK(a.hasSameClassAndValue(b));

    CHECK_FALSE(a.hasSameValue(c));
    CHECK_FALSE(a.hasSameClassAndValue(c));

    CHECK_FALSE(a.hasSameClass(d));
    CHECK_FALSE(a.hasSameClassAndValue(d));
}
