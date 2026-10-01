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

TEST_CASE("CNameConstraintsExtensionBuilder: a permitted and an excluded dNSName subtree") {
    // Verified against `openssl asn1parse` as SEQUENCE { cont[0] cons { SEQUENCE { cont[2] } },
    // cont[1] cons { SEQUENCE { cont[2], cont[1] } } }.
    static constexpr uint8_t EXPECTED[] = {
        0x30, 0x2c, 0xa0, 0x10, 0x30, 0x0e, 0x82, 0x0c, 0x2e, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xa1, 0x18, 0x30, 0x16,
        0x82, 0x11, 0x2e, 0x65, 0x76, 0x69, 0x6c, 0x2e, 0x65, 0x78, 0x61, 0x6d,
        0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x81, 0x01, 0x02,
    };

    CNameConstraintsExtensionBuilder builder;
    builder.addPermittedSubtree(CGeneralSubtree(CGeneralName(EGNAME_DNS, CString(".example.com")), 0, false, 0));
    builder.addExcludedSubtree(CGeneralSubtree(CGeneralName(EGNAME_DNS, CString(".evil.example.com")), 0, true, 2));

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CNameConstraintsExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CNameConstraintsExtension>(IExtension::create(ext->oid(), ext->value()));
    REQUIRE(reparsed->permittedSubtrees().size() == 1);
    CHECK(reparsed->permittedSubtrees()[0].base().text().compare(".example.com") == 0);
    CHECK(reparsed->permittedSubtrees()[0].minimum() == 0);
    CHECK_FALSE(reparsed->permittedSubtrees()[0].hasMaximum());

    REQUIRE(reparsed->excludedSubtrees().size() == 1);
    CHECK(reparsed->excludedSubtrees()[0].base().text().compare(".evil.example.com") == 0);
    CHECK(reparsed->excludedSubtrees()[0].hasMaximum());
    CHECK(reparsed->excludedSubtrees()[0].maximum() == 2);
}

TEST_CASE("CNameConstraintsExtensionBuilder: an empty builder encodes an empty SEQUENCE") {
    CNameConstraintsExtensionBuilder builder;

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);

    auto reparsed = std::static_pointer_cast<CNameConstraintsExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->permittedSubtrees().empty());
    CHECK(reparsed->excludedSubtrees().empty());
}
