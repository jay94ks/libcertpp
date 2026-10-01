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

TEST_CASE("CSkiExtensionBuilder: a 20-byte key identifier") {
    uint8_t kid[20];
    for (int i = 0; i < 20; ++i) {
        kid[i] = uint8_t(i);
    }

    // Verified against `openssl asn1parse` as a top-level OCTET STRING (no SEQUENCE wrapper).
    static constexpr uint8_t EXPECTED[] = {
        0x04, 0x14, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    };

    CSkiExtensionBuilder builder;
    builder.setKeyIdentifier(COctet(kid, sizeof(kid)));

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CSkiExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CSkiExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->keyIdentifier().size() == 20);
    CHECK(std::memcmp(reparsed->keyIdentifier().toPtr(), kid, 20) == 0);
}
