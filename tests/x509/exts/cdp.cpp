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

TEST_CASE("CCdpExtensionBuilder: one distribution point with a fullName URI and reasons") {
    // Verified against `openssl asn1parse` as SEQUENCE { SEQUENCE { cont[0] cons { cont[0] cons
    // { cont[6] } } , cont[1] prim } }.
    static constexpr uint8_t EXPECTED[] = {
        0x30, 0x29, 0x30, 0x27, 0xa0, 0x21, 0xa0, 0x1f, 0x86, 0x1d, 0x68, 0x74,
        0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x61, 0x2e,
        0x63, 0x72, 0x6c, 0x81, 0x02, 0x05, 0x60,
    };

    TArray<CGeneralName> fullName;
    fullName.add(CGeneralName(EGNAME_URI, CString("http://crl.example.com/ca.crl")));

    CDistributionPoint point(fullName, COctet(), true, ECRLR_KEY_COMPROMISE | ECRLR_CA_COMPROMISE, TArray<CGeneralName>());

    CCdpExtensionBuilder builder;
    builder.addPoint(point);

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CCdpExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CCdpExtension>(IExtension::create(ext->oid(), ext->value()));
    REQUIRE(reparsed->points().size() == 1);
    const CDistributionPoint& dp = reparsed->points()[0];
    REQUIRE(dp.fullName().size() == 1);
    CHECK(dp.fullName()[0].text().compare("http://crl.example.com/ca.crl") == 0);
    CHECK(dp.hasReasons());
    CHECK(dp.reasons() == (ECRLR_KEY_COMPROMISE | ECRLR_CA_COMPROMISE));
}
