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

TEST_CASE("CSanExtensionBuilder: two dNSNames and an iPAddress") {
    // Verified against `openssl asn1parse` as SEQUENCE { cont[2], cont[2], cont[7] }.
    static constexpr uint8_t EXPECTED[] = {
        0x30, 0x24, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x82, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x87, 0x04, 0x7f, 0x00,
        0x00, 0x01,
    };

    CSanExtensionBuilder builder;
    builder.addName(CGeneralName(EGNAME_DNS, CString("example.com")));
    builder.addName(CGeneralName(EGNAME_DNS, CString("www.example.com")));

    uint8_t ip4[4] = { 127, 0, 0, 1 };
    builder.addName(CGeneralName(EGNAME_IP_ADDRESS, COctet(ip4, 4)));

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CSanExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CSanExtension>(IExtension::create(ext->oid(), ext->value()));
    REQUIRE(reparsed->names().size() == 3);
    CHECK(reparsed->names()[0].type() == EGNAME_DNS);
    CHECK(reparsed->names()[0].text().compare("example.com") == 0);
    CHECK(reparsed->names()[1].text().compare("www.example.com") == 0);
    CHECK(reparsed->names()[2].type() == EGNAME_IP_ADDRESS);
    CHECK(reparsed->names()[2].raw().size() == 4);
}

TEST_CASE("CSanExtensionBuilder: a directoryName round-trips through CDistinguishedName") {
    CDistinguishedName name;
    REQUIRE(name.trySet(CName(ENAME_CN, "test.libcertpp.local")));

    CSanExtensionBuilder builder;
    builder.addName(CGeneralName(name));

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);

    auto reparsed = std::static_pointer_cast<CSanExtension>(IExtension::create(ext->oid(), ext->value()));
    REQUIRE(reparsed->names().size() == 1);
    CHECK(reparsed->names()[0].type() == EGNAME_DIRECTORY);

    CName cn;
    REQUIRE(reparsed->names()[0].directoryName().tryGet(ENAME_CN, cn));
    CHECK(cn.toString<char>().compare("test.libcertpp.local") == 0);
}
