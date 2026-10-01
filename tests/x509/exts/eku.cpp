#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::x509;

namespace {
    bool equalsHex(const COctet& value, const uint8_t* expected, size_t expectedSize) {
        return value.size() == expectedSize && std::memcmp(value.toPtr(), expected, expectedSize) == 0;
    }
}

TEST_CASE("CEkuExtensionBuilder: serverAuth + clientAuth") {
    // Verified against `openssl asn1parse` as SEQUENCE { OID serverAuth, OID clientAuth }.
    static constexpr uint8_t EXPECTED[] = {
        0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
    };

    CEkuExtensionBuilder builder;
    builder.addPurpose(CEkuExtension::OID_SERVER_AUTH).addPurpose(CEkuExtension::OID_CLIENT_AUTH);

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CEkuExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CEkuExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->purposes().size() == 2);
    CHECK(reparsed->has(CEkuExtension::OID_SERVER_AUTH));
    CHECK(reparsed->has(CEkuExtension::OID_CLIENT_AUTH));
    CHECK_FALSE(reparsed->has(CEkuExtension::OID_CODE_SIGNING));
}

TEST_CASE("CEkuExtensionBuilder: a malformed OID fails to build") {
    CEkuExtensionBuilder builder;
    builder.addPurpose(CString("not-an-oid"));

    CHECK_FALSE(builder.build());
}
