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

TEST_CASE("CAkiExtensionBuilder: keyIdentifier + authorityCertIssuer + authorityCertSerialNumber") {
    uint8_t kid[20];
    for (int i = 0; i < 20; ++i) {
        kid[i] = uint8_t(0xA0 + i);
    }

    // Verified against `openssl asn1parse` as SEQUENCE { cont[0] prim, cont[1] cons { cont[6] }, cont[2] prim }.
    static constexpr uint8_t EXPECTED[] = {
        0x30, 0x32, 0x80, 0x14, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
        0xa1, 0x17, 0x86, 0x15, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63,
        0x61, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
        0x6d, 0x82, 0x01, 0x2a,
    };

    CAkiExtensionBuilder builder;
    builder.setKeyIdentifier(COctet(kid, sizeof(kid)));
    builder.addAuthorityCertIssuer(CGeneralName(EGNAME_URI, CString("http://ca.example.com")));

    uint8_t serial[1] = { 0x2a };
    builder.setAuthorityCertSerialNumber(COctet(serial, 1));

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CAkiExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CAkiExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->hasKeyIdentifier());
    CHECK(reparsed->keyIdentifier().size() == 20);
    REQUIRE(reparsed->authorityCertIssuer().size() == 1);
    CHECK(reparsed->authorityCertIssuer()[0].type() == EGNAME_URI);
    CHECK(reparsed->authorityCertIssuer()[0].text().compare("http://ca.example.com") == 0);
    CHECK(reparsed->hasAuthorityCertSerialNumber());
    CHECK(reparsed->authorityCertSerialNumber().size() == 1);
    CHECK(reparsed->authorityCertSerialNumber().toPtr()[0] == 0x2a);
}

TEST_CASE("CAkiExtensionBuilder: an empty builder encodes an empty SEQUENCE (every field OPTIONAL)") {
    CAkiExtensionBuilder builder;

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);

    auto reparsed = std::static_pointer_cast<CAkiExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK_FALSE(reparsed->hasKeyIdentifier());
    CHECK(reparsed->authorityCertIssuer().empty());
    CHECK_FALSE(reparsed->hasAuthorityCertSerialNumber());
}
