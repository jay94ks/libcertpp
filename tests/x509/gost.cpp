#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::x509;

TEST_CASE("RFC 9215 GOST 2012 certificate imports and verifies") {
    // RFC 9215 Appendix D.2.2: 256-bit parameter set A certificate.
    const char* body =
        "MIIBJTCB06ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw"
        "IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4"
        "YW1wbGUwXjAXBggqhQMHAQEBATALBgkqhQMHAQIBAQEDQwAEQHQnldS+6ITd8oUP"
        "7APqP68YROAdnaYLZFCTpV4m38OZePWWz01NDGzx0YlD2UST0WuewKFtUS0uEnzE"
        "aRpjGOKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoUDBwEBAwIDQQAUC02pEksJ"
        "yw1c6Sjuh0JzoxASlJLsDik2njt5EkhXjB0OHaW+NHxvG1JWx66sIArWSsd6b1s6"
        "DglzGOeubudp";

    CBuffer der;
    REQUIRE(CBase64::decode(der, CString(body)));

    CCert cert;
    REQUIRE(cert.importDer(COctet(der.toSpan())) == ERET_OK);
    CHECK(cert.keyAlgo().compare("GOST R 34.10-2012-256") == 0);
    CHECK(cert.signAlgo().compare("GOST R 34.10-2012-256") == 0);
    REQUIRE(cert.publicKey());
    CHECK(cert.publicKey()->algorithm() == crypto::EASYM_GOST256A);
    CHECK(cert.verifyBy(cert) == ERET_OK);
}

TEST_CASE("GOST certificate builder emits RFC 9215 wire forms") {
    crypto::IAsymmetricPtr algorithm = crypto::IAsymmetric::builtIn(crypto::EASYM_GOST256A);
    REQUIRE(algorithm);
    crypto::SKeyPair pair;
    REQUIRE(algorithm->generateKeyPair(crypto::SKeySize(256), pair) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.subject, CString("CN=GOST Test")));
    builder.issuer = builder.subject;
    builder.subjectKey = pair.publicKey;
    builder.issuerKeyPair = pair;
    builder.serialNumber = COctet(SReadOnlyByteSpan(
        reinterpret_cast<const uint8_t*>("\x01"), 1));
    builder.notBefore = SDateTime(2025, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2030, 1, 1, 0, 0, 0, 0, true);

    CCert cert;
    REQUIRE(builder.build(cert) == ERET_OK);
    CHECK(cert.keyAlgo().compare("GOST R 34.10-2012-256") == 0);
    CHECK(cert.signAlgo().compare("GOST R 34.10-2012-256") == 0);
    REQUIRE(cert.publicKey());
    CHECK(cert.publicKey()->compare(pair.publicKey) == 0);
    CHECK(cert.verifyBy(cert) == ERET_OK);

    // The SPKI key is unwrapped for callers; it is exactly x || y.
    CHECK(cert.rawPublicKey().size() == 64);
}

TEST_CASE("GOST certificate rejects an unknown parameter set") {
    const char* body =
        "MIIBJTCB06ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw"
        "IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4"
        "YW1wbGUwXjAXBggqhQMHAQEBATALBgkqhQMHAQIBAQEDQwAEQHQnldS+6ITd8oUP"
        "7APqP68YROAdnaYLZFCTpV4m38OZePWWz01NDGzx0YlD2UST0WuewKFtUS0uEnzE"
        "aRpjGOKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoUDBwEBAwIDQQAUC02pEksJ"
        "yw1c6Sjuh0JzoxASlJLsDik2njt5EkhXjB0OHaW+NHxvG1JWx66sIArWSsd6b1s6"
        "DglzGOeubudp";

    CBuffer der;
    REQUIRE(CBase64::decode(der, CString(body)));

    const uint8_t curveOid[] = { 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07,
                                 0x01, 0x02, 0x01, 0x01, 0x01 };
    size_t found = size_t(-1);
    for (size_t i = 0; i + sizeof(curveOid) <= der.size(); ++i) {
        if (std::memcmp(der.toPtr() + i, curveOid, sizeof(curveOid)) == 0) {
            found = i;
            break;
        }
    }
    REQUIRE(found != size_t(-1));
    der[found + sizeof(curveOid) - 1] = 0x09;

    CCert cert;
    CHECK(cert.importDer(COctet(der.toSpan())) != ERET_OK);
}
