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

TEST_CASE("CAiaExtensionBuilder: an OCSP responder and the issuing CA's own certificate") {
    // Verified against `openssl asn1parse` as SEQUENCE { SEQUENCE { OID OCSP, cont[6] },
    // SEQUENCE { OID CA Issuers, cont[6] } }.
    static constexpr uint8_t EXPECTED[] = {
        0x30, 0x4f, 0x30, 0x23, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
        0x30, 0x01, 0x86, 0x17, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f,
        0x63, 0x73, 0x70, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x30, 0x28, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
        0x07, 0x30, 0x02, 0x86, 0x1c, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
        0x63, 0x61, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
        0x6f, 0x6d, 0x2f, 0x63, 0x61, 0x2e, 0x63, 0x72, 0x74,
    };

    CAiaExtensionBuilder builder;
    builder.addDescription(CAccessDescription(CAiaExtension::OID_OCSP_METHOD, CGeneralName(EGNAME_URI, CString("http://ocsp.example.com"))));
    builder.addDescription(CAccessDescription(CAiaExtension::OID_CA_ISSUERS_METHOD, CGeneralName(EGNAME_URI, CString("http://ca.example.com/ca.crt"))));

    IExtensionPtr ext = builder.build();
    REQUIRE(ext);
    CHECK(ext->oid().compare(CAiaExtension::OID) == 0);
    CHECK(equalsHex(ext->value(), EXPECTED, sizeof(EXPECTED)));

    auto reparsed = std::static_pointer_cast<CAiaExtension>(IExtension::create(ext->oid(), ext->value()));
    REQUIRE(reparsed->descriptions().size() == 2);
    CHECK(reparsed->descriptions()[0].accessMethod().compare(CAiaExtension::OID_OCSP_METHOD) == 0);
    CHECK(reparsed->descriptions()[0].accessLocation().text().compare("http://ocsp.example.com") == 0);
    CHECK(reparsed->descriptions()[1].accessMethod().compare(CAiaExtension::OID_CA_ISSUERS_METHOD) == 0);
}
