#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/utils/json.hpp>
#include <limits>

using namespace certpp::utils;
using namespace certpp;

TEST_CASE("parseJson parses nested arrays and objects") {
    CJsonPtr value = parseJson(R"({"name":"Ada","active":true,"scores":[10,2.5,null,{"ok":false}]})");

    REQUIRE(value);
    CHECK(value->type() == EJSON_OBJECT);
    CHECK(value->byKey("name").value->asString() == "Ada");
    CHECK(value->byKey("active").value->asBool());

    CJsonPtr scores = value->byKey("scores").value;
    REQUIRE(scores);
    CHECK(scores->type() == EJSON_ARRAY);
    CHECK(scores->byIndex(0).value->asNumber() == doctest::Approx(10.0));
    CHECK(scores->byIndex(1).value->asNumber() == doctest::Approx(2.5));
    REQUIRE(scores->byIndex(2).value);
    CHECK(scores->byIndex(2).value->isNull());
    REQUIRE(scores->byIndex(3).value);
    CHECK(scores->byIndex(3).value->byKey("ok").value->asBool(true) == false);
}

TEST_CASE("parseJson accepts empty containers and JSON primitives") {
    CJsonPtr emptyObject = parseJson("{}");
    CJsonPtr emptyArray = parseJson("[]");
    CJsonPtr text = parseJson(R"("text")");
    CJsonPtr boolean = parseJson("false");
    CJsonPtr number = parseJson("-1.25e+2");
    CJsonPtr nullValue = parseJson("null");

    REQUIRE(emptyObject);
    REQUIRE(emptyArray);
    REQUIRE(text);
    REQUIRE(boolean);
    REQUIRE(number);
    REQUIRE(nullValue);
    CHECK(emptyObject->type() == EJSON_OBJECT);
    CHECK(emptyArray->type() == EJSON_ARRAY);
    CHECK(text->asString() == "text");
    CHECK(boolean->asBool(true) == false);
    CHECK(number->asNumber() == doctest::Approx(-125.0));
    CHECK(nullValue->isNull());
    CHECK(CJson::wrap(std::string("1e2"))->asNumber() == doctest::Approx(100.0));
    CHECK(CJson::wrap(std::string("1-2"))->asNumber(9.0) == doctest::Approx(9.0));
}

TEST_CASE("parseJson decodes escaped strings and unicode surrogate pairs") {
    CJsonPtr value = parseJson(R"({"text":"line\nquote:\" slash:\\","symbol":"\uD83D\uDE00"})");

    REQUIRE(value);
    CHECK(value->byKey("text").value->asString() == "line\nquote:\" slash:\\");
    CHECK(value->byKey("symbol").value->asString() == std::string("\xf0\x9f\x98\x80"));
    CHECK_FALSE(parseJson("\"\\uD800\""));
    CHECK_FALSE(parseJson("\"\\q\""));
}

TEST_CASE("parseJson rejects malformed or trailing input") {
    CHECK_FALSE(parseJson(""));
    CHECK_FALSE(parseJson("{"));
    CHECK_FALSE(parseJson(R"({"key":})"));
    CHECK_FALSE(parseJson("[1,]"));
    CHECK_FALSE(parseJson(R"({"key":1,})"));
    CHECK_FALSE(parseJson("true false"));
    CHECK_FALSE(parseJson("01"));
    CHECK_FALSE(parseJson("1."));
    CHECK_FALSE(parseJson("+1"));
    CHECK_FALSE(parseJson(R"('single quoted')"));
    CHECK_FALSE(parseJson(R"({'key':1})"));
    CHECK_FALSE(parseJson("[1 2]"));
    CHECK_FALSE(parseJson("1e"));
    CHECK_FALSE(parseJson("1e+"));
    CHECK_FALSE(parseJson("1e10000"));
    CHECK_FALSE(parseJson(" \vtrue"));
    CHECK_FALSE(parseJson(std::string("\"line\nbreak\"")));
}

TEST_CASE("CJson::toString escapes strings and object keys and round-trips numbers") {
    const std::string key = "quote\" slash\\ tab\t control\x01";
    const std::string text = "quote\" slash\\ tab\t newline\n control\x02";
    CJsonPtr object = CJson::makeObject();
    CJsonPtr array = CJson::makeArray();
    REQUIRE(object);
    REQUIRE(array);
    CHECK(array->byKey("0", CJson::wrap(0.10000000000000002)));
    CHECK(array->byKey("1", CJsonPtr()));
    CHECK(object->byKey(key, CJson::wrap(text)));
    CHECK(object->byKey("values", array));

    const std::string encoded = object->toString();
    CJsonPtr decoded = parseJson(encoded);
    REQUIRE(decoded);
    CHECK(decoded->byKey(key).value->asString() == text);
    REQUIRE(decoded->byKey("values").value);
    CHECK(decoded->byKey("values").value->byIndex(0).value->asNumber() ==
          0.10000000000000002);
    REQUIRE(decoded->byKey("values").value->byIndex(1).value);
    CHECK(decoded->byKey("values").value->byIndex(1).value->isNull());
}

TEST_CASE("CJson::toString keeps output valid for depth limits and non-finite numbers") {
    CJsonPtr nested = CJson::makeArray();
    REQUIRE(nested);
    CHECK(nested->byKey("0", CJson::wrap(1.0)));
    CHECK(nested->toString(1) == "[null]");
    CHECK(nested->toString(0) == "null");
    CHECK(parseJson(nested->toString(1)));
    CHECK(CJson::wrap(std::numeric_limits<double>::infinity())->toString() == "null");
}

TEST_CASE("BSON round-trips nested JSON objects and arrays") {
    CJsonPtr value = parseJson(
        R"({"name":"Ada","active":true,"items":[1,-2.5,null,{"text":"a\u0000b"}]})");
    REQUIRE(value);

    CBuffer encoded;
    REQUIRE(value->toBson(encoded));
    CHECK(encoded.size() > 5);
    CJsonPtr decoded = parseBson(encoded.toSpan());
    REQUIRE(decoded);
    CHECK(decoded->type() == EJSON_OBJECT);
    CHECK(decoded->byKey("name").value->asString() == "Ada");
    CHECK(decoded->byKey("active").value->asBool());

    CJsonPtr items = decoded->byKey("items").value;
    REQUIRE(items);
    CHECK(items->type() == EJSON_ARRAY);
    CHECK(items->byIndex(0).value->asNumber() == doctest::Approx(1.0));
    CHECK(items->byIndex(1).value->asNumber() == doctest::Approx(-2.5));
    REQUIRE(items->byIndex(2).value);
    CHECK(items->byIndex(2).value->isNull());
    CHECK(items->byIndex(3).value->byKey("text").value->asString() ==
          std::string("a\0b", 3));

    CBuffer arrayBson;
    REQUIRE(items->toBson(arrayBson));
    CJsonPtr decodedArray = parseBson(arrayBson.toSpan(), true);
    REQUIRE(decodedArray);
    CHECK(decodedArray->type() == EJSON_ARRAY);
    CHECK(decodedArray->byIndex(3).value->byKey("text").value->asString() ==
          std::string("a\0b", 3));
}

TEST_CASE("toBson writes standard little-endian BSON document bytes") {
    CJsonPtr value = CJson::makeObject();
    REQUIRE(value);
    REQUIRE(value->byKey("x", CJson::wrap(1.0)));

    CBuffer encoded;
    REQUIRE(value->toBson(encoded));
    const uint8_t expected[] = {
        16, 0, 0, 0,
        0x01, 'x', 0,
        0, 0, 0, 0, 0, 0, 0xf0, 0x3f,
        0
    };
    REQUIRE(encoded.size() == sizeof(expected));
    for (size_t i = 0; i < sizeof(expected); ++i) {
        CHECK(encoded[i] == expected[i]);
    }
}

TEST_CASE("parseBson accepts integer BSON values as JSON numbers") {
    uint8_t int32Document[] = {
        12, 0, 0, 0,
        0x10, 'n', 0, 42, 0, 0, 0,
        0
    };
    CJsonPtr value = parseBson(SByteSpan(int32Document, sizeof(int32Document)));
    REQUIRE(value);
    CHECK(value->byKey("n").value->asNumber() == doctest::Approx(42.0));
}

TEST_CASE("BSON parsing rejects malformed lengths, array keys, and unsupported types") {
    uint8_t shortDocument[] = {4, 0, 0, 0};
    uint8_t wrongArrayKey[] = {
        12, 0, 0, 0,
        0x10, '1', 0, 1, 0, 0, 0,
        0
    };
    uint8_t invalidBoolean[] = {
        9, 0, 0, 0,
        0x08, 'b', 0, 2,
        0
    };
    uint8_t unsupportedType[] = {
        8, 0, 0, 0,
        0x09, 'd', 0,
        0
    };

    CHECK_FALSE(parseBson(SByteSpan(shortDocument, sizeof(shortDocument))));
    CHECK_FALSE(parseBson(SByteSpan(wrongArrayKey, sizeof(wrongArrayKey)), true));
    CHECK_FALSE(parseBson(SByteSpan(invalidBoolean, sizeof(invalidBoolean))));
    CHECK_FALSE(parseBson(SByteSpan(unsupportedType, sizeof(unsupportedType))));
    CHECK_FALSE(parseBson(SByteSpan()));
}

TEST_CASE("toBson rejects scalar roots and object keys containing null bytes") {
    CBuffer buffer;
    const uint8_t original[] = {1, 2, 3};
    REQUIRE(buffer.store(original, sizeof(original)));

    CJsonPtr scalar = CJson::wrap(true);
    CHECK_FALSE(scalar->toBson(buffer));
    CHECK(buffer.size() == sizeof(original));
    CHECK(buffer[0] == 1);

    CJsonPtr object = CJson::makeObject();
    REQUIRE(object);
    REQUIRE(object->byKey(std::string("bad\0key", 7), CJson::wrap(1.0)));
    CHECK_FALSE(object->toBson(buffer));
    CHECK(buffer.size() == sizeof(original));
}
