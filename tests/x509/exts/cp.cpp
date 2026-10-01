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

TEST_CASE("CPoliciesExtensionBuilder: anyPolicy and a private-enterprise policy OID") {
    // Verified against `openssl asn1parse` as SEQUENCE { SEQUENCE { OID anyPolicy },
    // SEQUENCE { OID 1.3.6.1.4.1.44947.1.1.1 } }.
    static constexpr uint8_t EXPECTED[] = {
        0x30, 0x17, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x20, 0x00, 0x30, 0x0d,
        0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdf, 0x13, 0x01, 0x01,
        0x01,
    };

    CPoliciesExtensionBuilder builder;
    builder.addPolicy(CPolicyInformation(CPoliciesExtension::OID_ANY_POLICY, COctet()));
    builder.addPolicy(CPolicyInformation(CString("1.3.6.1.4.1.44947.1.1.1"), COctet()));

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CPoliciesExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CPoliciesExtension>(IExtension::create(ext->oid(), ext->value()));
    REQUIRE(reparsed->policies().size() == 2);
    CHECK(reparsed->policies()[0].policyIdentifier().compare(CPoliciesExtension::OID_ANY_POLICY) == 0);
    CHECK_FALSE(reparsed->policies()[0].hasPolicyQualifiers());
    CHECK(reparsed->policies()[1].policyIdentifier().compare("1.3.6.1.4.1.44947.1.1.1") == 0);
}

TEST_CASE("CPoliciesExtensionBuilder: a malformed policy OID fails to build") {
    CPoliciesExtensionBuilder builder;
    builder.addPolicy(CPolicyInformation(CString("not-an-oid"), COctet()));

    CHECK_FALSE(builder.build());
}
