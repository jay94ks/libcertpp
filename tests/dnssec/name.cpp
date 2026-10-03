#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <string>

using namespace certpp;
using namespace certpp::dnssec;

namespace {
    std::string wireOf(const char* name) {
        TArray<uint8_t> wire;
        REQUIRE(CDnsName::toWire(CString(name), wire));

        // Rendered as a readable string so a failure prints something diagnosable: label
        // lengths as decimal in brackets, label bytes as themselves.
        std::string out;
        for (size_t i = 0; i < wire.size(); ++i) {
            out += '[';
            out += std::to_string(int(wire[i]));
            out += ']';

            const size_t length = wire[i];
            for (size_t j = 0; j < length && i + 1 + j < wire.size(); ++j) {
                out += char(wire[i + 1 + j]);
            }
            i += length;
        }
        return out;
    }

    std::string roundTrip(const char* name) {
        TArray<uint8_t> wire;
        REQUIRE(CDnsName::toWire(CString(name), wire));

        CString back;
        REQUIRE(CDnsName::fromWire(SReadOnlyByteSpan(wire.begin(), wire.size()), back));
        return std::string(back.toPtr() ? back.toPtr() : "");
    }
}

TEST_CASE("CDnsName: encodes length-prefixed labels and a root label") {
    CHECK(wireOf("example.net.") == "[7]example[3]net[0]");
    CHECK(wireOf("example.net") == "[7]example[3]net[0]");
    CHECK(wireOf("www.example.net.") == "[3]www[7]example[3]net[0]");
    CHECK(wireOf("net.") == "[3]net[0]");
}

TEST_CASE("CDnsName: the root name is a single zero octet") {
    TArray<uint8_t> wire;

    REQUIRE(CDnsName::toWire(CString("."), wire));
    CHECK(wire.size() == 1);
    CHECK(wire[0] == 0);

    REQUIRE(CDnsName::toWire(CString(""), wire));
    CHECK(wire.size() == 1);
    CHECK(wire[0] == 0);
}

TEST_CASE("CDnsName: folds ASCII uppercase, and nothing else") {
    // RFC 4034 6.2 folds uppercase US-ASCII letters. This is the whole reason the DS digests in
    // tests/dnssec/records.cpp reproduce the published values for a mixed-case owner name.
    CHECK(wireOf("ExAmPlE.NeT.") == "[7]example[3]net[0]");
    CHECK(wireOf("EXAMPLE.NET.") == "[7]example[3]net[0]");

    // Digits, hyphens and underscores pass through untouched -- underscores because they appear
    // in real names like _dmarc and SRV labels.
    CHECK(wireOf("_dmarc.example-1.net.") == "[6]_dmarc[9]example-1[3]net[0]");
}

TEST_CASE("CDnsName: round-trips back to a fully-qualified presentation name") {
    CHECK(roundTrip("example.net.") == "example.net.");
    CHECK(roundTrip("www.example.net") == "www.example.net.");
    CHECK(roundTrip(".") == ".");

    // Case is folded on the way in, so the round trip is lowercase -- deliberately, since the
    // wire form is the authoritative one once a name has been canonicalised.
    CHECK(roundTrip("ExAmPlE.NeT.") == "example.net.");
}

TEST_CASE("CDnsName: counts labels the way RRSIG's Labels field does") {
    TArray<uint8_t> wire;
    size_t labels = 0;

    REQUIRE(CDnsName::toWire(CString("www.example.net."), wire));
    REQUIRE(CDnsName::countLabels(SReadOnlyByteSpan(wire.begin(), wire.size()), labels));
    CHECK(labels == 3);

    REQUIRE(CDnsName::toWire(CString("example.net."), wire));
    REQUIRE(CDnsName::countLabels(SReadOnlyByteSpan(wire.begin(), wire.size()), labels));
    CHECK(labels == 2);

    // The root label is not counted, so the root name has zero.
    REQUIRE(CDnsName::toWire(CString("."), wire));
    REQUIRE(CDnsName::countLabels(SReadOnlyByteSpan(wire.begin(), wire.size()), labels));
    CHECK(labels == 0);
}

TEST_CASE("CDnsName: rejects malformed presentation names") {
    TArray<uint8_t> wire;

    // An empty label, from a doubled or leading dot, is not a name.
    CHECK_FALSE(CDnsName::toWire(CString("example..net."), wire));
    CHECK_FALSE(CDnsName::toWire(CString(".example.net."), wire));

    // A label over 63 octets cannot be length-prefixed.
    std::string tooLong(64, 'a');
    CHECK_FALSE(CDnsName::toWire(CString((tooLong + ".net.").c_str()), wire));

    // Exactly 63 is allowed.
    std::string atLimit(63, 'a');
    CHECK(CDnsName::toWire(CString((atLimit + ".net.").c_str()), wire));

    // And the whole name cannot exceed 255 octets.
    std::string huge;
    for (int i = 0; i < 5; ++i) {
        huge += std::string(60, 'a');
        huge += '.';
    }
    CHECK_FALSE(CDnsName::toWire(CString(huge.c_str()), wire));
}

TEST_CASE("CDnsName: rejects malformed wire names") {
    CString name;

    // No root label before the end of the span.
    uint8_t unterminated[4] = { 3, 'n', 'e', 't' };
    CHECK_FALSE(CDnsName::fromWire(SReadOnlyByteSpan(unterminated, 4), name));

    // A label length that runs past the end.
    uint8_t runaway[3] = { 9, 'n', 'e' };
    CHECK_FALSE(CDnsName::fromWire(SReadOnlyByteSpan(runaway, 3), name));

    // A compression pointer. The top two bits being set marks one, and DNSSEC forbids them in
    // the names it signs over -- accepting one here would mean accepting a name that cannot be
    // canonicalised without the rest of the message to resolve it against.
    uint8_t pointer[2] = { 0xC0, 0x0C };
    CHECK_FALSE(CDnsName::fromWire(SReadOnlyByteSpan(pointer, 2), name));

    // A length octet between 64 and 191 is simply invalid.
    uint8_t badLength[2] = { 0x7F, 0x00 };
    CHECK_FALSE(CDnsName::fromWire(SReadOnlyByteSpan(badLength, 2), name));

    // Trailing bytes after the root label mean the caller's framing is wrong.
    uint8_t trailing[6] = { 3, 'n', 'e', 't', 0, 0xAA };
    CHECK_FALSE(CDnsName::fromWire(SReadOnlyByteSpan(trailing, 6), name));

    CHECK_FALSE(CDnsName::fromWire(SReadOnlyByteSpan(nullptr, 0), name));
}

TEST_CASE("CDnsName: fromWirePrefix stops at the root label and reports what it used") {
    // This is what RRSIG RDATA needs: the signer's name is followed immediately by the
    // signature, with no length to separate them.
    uint8_t rdata[9] = { 3, 'n', 'e', 't', 0, 0xDE, 0xAD, 0xBE, 0xEF };

    CString name;
    size_t consumed = 0;
    REQUIRE(CDnsName::fromWirePrefix(SReadOnlyByteSpan(rdata, 9), name, consumed));

    CHECK(std::string(name.toPtr()) == "net.");
    CHECK(consumed == 5);
}

TEST_CASE("CDnsName: isCanonical reports whether a wire name holds ASCII uppercase") {
    uint8_t lower[6] = { 4, 'm', 'a', 'i', 'l', 0 };
    CHECK(CDnsName::isCanonical(SReadOnlyByteSpan(lower, 6)));

    uint8_t upper[6] = { 4, 'M', 'a', 'i', 'l', 0 };
    CHECK_FALSE(CDnsName::isCanonical(SReadOnlyByteSpan(upper, 6)));

    // A malformed name is not canonical either, rather than being reported as fine.
    uint8_t broken[3] = { 9, 'n', 'e' };
    CHECK_FALSE(CDnsName::isCanonical(SReadOnlyByteSpan(broken, 3)));

    // Everything toWire() produces is canonical by construction.
    TArray<uint8_t> wire;
    REQUIRE(CDnsName::toWire(CString("ExAmPlE.NeT."), wire));
    CHECK(CDnsName::isCanonical(SReadOnlyByteSpan(wire.begin(), wire.size())));
}
