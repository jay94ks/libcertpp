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

TEST_CASE("CKeyUsagesExtensionBuilder: digitalSignature + keyCertSign + crlSign") {
    // Verified against `openssl asn1parse`: BIT STRING, 1 unused bit, content 0x86 =
    // 1000_0110b -> named bits 0 (digitalSignature), 5 (keyCertSign), 6 (crlSign) set.
    static constexpr uint8_t EXPECTED[] = { 0x03, 0x02, 0x01, 0x86 };

    CKeyUsagesExtensionBuilder builder;
    builder.setBits(EKUSE_DIGITAL_SIGNATURE | EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN);

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CKeyUsagesExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CKeyUsagesExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->bits() == (EKUSE_DIGITAL_SIGNATURE | EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN));
}

TEST_CASE("CKeyUsagesExtensionBuilder: decipherOnly alone (the highest named bit)") {
    CKeyUsagesExtensionBuilder builder;
    builder.setBits(EKUSE_DECIPHER_ONLY);

    IExtensionPtr ext = builder.build();
    auto reparsed = std::static_pointer_cast<CKeyUsagesExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->bits() == EKUSE_DECIPHER_ONLY);
}

TEST_CASE("CKeyUsagesExtensionBuilder: no bits set encodes as an empty BIT STRING") {
    // BIT STRING with 0 content octets and 0 unused bits: tag(0x03) + length(0x01) + the
    // unused-bits count octet itself (0x00) -- there's no data to trim it away from.
    static constexpr uint8_t EXPECTED[] = { 0x03, 0x01, 0x00 };

    CKeyUsagesExtensionBuilder builder;

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CKeyUsagesExtension>(IExtension::create(ext->oid(), ext->value()));
    CHECK(reparsed->bits() == EKUSE_NONE);
}
