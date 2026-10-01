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

TEST_CASE("CBasicConstraintsExtensionBuilder: cA=true with a pathLenConstraint") {
    // Verified against `openssl asn1parse` as SEQUENCE { BOOLEAN true, INTEGER 3 }.
    static constexpr uint8_t EXPECTED[] = { 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03 };

    CBasicConstraintsExtensionBuilder builder;
    builder.setIsCa(true).setPathLenConstraint(3);

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CBasicConstraintsExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CBasicConstraintsExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->isCa() == true);
    CHECK(reparsed->hasPathLenConstraint() == true);
    CHECK(reparsed->pathLenConstraint() == 3);
}

TEST_CASE("CBasicConstraintsExtensionBuilder: cA default (false) omits the BOOLEAN") {
    CBasicConstraintsExtensionBuilder builder;

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);

    auto reparsed = std::static_pointer_cast<CBasicConstraintsExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->isCa() == false);
    CHECK(reparsed->hasPathLenConstraint() == false);
}

TEST_CASE("CBasicConstraintsExtensionBuilder: clearPathLenConstraint removes a previously-set constraint") {
    CBasicConstraintsExtensionBuilder builder;
    builder.setIsCa(true).setPathLenConstraint(5).clearPathLenConstraint();

    IExtensionPtr ext = builder.build();
    auto reparsed = std::static_pointer_cast<CBasicConstraintsExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->isCa() == true);
    CHECK(reparsed->hasPathLenConstraint() == false);
}
