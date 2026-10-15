#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>

using namespace certpp;

TEST_CASE("ML-KEM SPKI decodes and reproduces the RFC 9935 public-key example") {
    // RFC 9935 Appendix C.2, ML-KEM-512 PUBLIC KEY. This fixture independently checks the
    // OID, absent parameters, raw BIT STRING placement, and public-key length.
    const char* pemBody =
        "MIIDMjALBglghkgBZQMEBAEDggMhADmVgV5ZfRBDVc8pqlMzyTJRhp1bzb5IcST2"
        "Ari2pmwWxHYWSK12XPXYAGtRXpBafwrAdrDGLvoygVPnylcBaZ8TBfHmvG+QsOSb"
        "aTUSts6ZKouAFt38GmYsfj+WGcvYad13GvMIlszVkYrGy3dGbF53mZbWf/mqvJdQ"
        "Pyx7fi0ADYZFD7GAfKTKvaRlgloxx4mht6SRqzhydl0yDQtxkg+iE8lAk0Frg7gS"
        "Tmn2XmLLUADcw3qpoP/3OXDEdy81fSQYnKb1MFVowOI3ajdipoxgXlY8XSCVcuD8"
        "dTLKKUcpU1VntfxBPF6HktJGRTbMgI+YrddGZPFBVm+QFqkKVBgpqYoEZM5BqLtE"
        "wtT6PCwglGByjvFKGnxMm5jRIgO0zDUpFgqasteDj3/2tTrgWqMafWRrevpsRZMl"
        "JqPDdVYZvplMIRwqMcBbNEeDbLIVC+GCna5rBMVTXP9Ubjkrp5dBFyD5JPSQpaxU"
        "lfITVtVQt4KmTBaItrZVvMeEIZekNML2Vjtbfwmni8xIgjJ4NWHRb0y6tnVUAAUH"
        "gVcMZmBLgXrRJSKUc26LAYYaS1p0UZuLb+UUiaUHI5Llh2JscTd2V10zgGocjicy"
        "r5fCaA9RZmMxxOuLvAQxxPloMtrxs8RVKPuhU/bHixwZhwKUfM0zdyekb7U7oR3l"
        "y0GRNGhZUWy2rXJADzzyCbI2rvNaWArIfrPjD6/WaXPKin3SZ1r0H3oXthQzzRr4"
        "D3cIhp9mVIhJeYCxrBCgzctjagDthoGzXkKRJMqANQcluF+DperDpKPMFgCQPmUp"
        "NWC5szblrw1SnawaBIEZMCy3qbzBELlIUb8CEX8ZncSFqFK3Rz8JuDGmgx1bVMC3"
        "kNIlz2u5LZRiomzbM92lEjx6rw4moLg2Ve6ii/OoB0clAY/WuuS2Ac9huqtxp6PT"
        "UZejQ+dLSicsEl1UCJZCbYW3lY07OKa6mH7DciXHtEzbEt3kU5tKsII2NoPwS/eg"
        "nMXEHf6DChsWLgsyQzQ2LwhKFEZ3IzRLrdAA+NjFN8SPmY8FMHzr0e3guBw7xZoG"
        "WhttY7Js";

    CBuffer der;
    REQUIRE(CBase64::decode(der, CString(pemBody)));

    crypto::EKems which = crypto::EKEM_UNKNOWN;
    crypto::IKemPublicKeyPtr key;
    REQUIRE(x509::CKemSubjectPublicKeyInfo::decode(der.toSpan(), which, key) == ERET_OK);
    CHECK(which == crypto::EKEM_MLKEM512);
    REQUIRE(key);

    COctet raw;
    REQUIRE(key->serialize(raw) == ERET_OK);
    CHECK(raw.size() == 800);
    CHECK(raw.toPtr()[0] == 0x39);
    CHECK(raw.toPtr()[799] == 0x6c);

    CBuffer encoded;
    REQUIRE(x509::CKemSubjectPublicKeyInfo::encode(key, encoded) == ERET_OK);
    REQUIRE(encoded.size() == der.size());
    CHECK(std::memcmp(encoded.toPtr(), der.toPtr(), der.size()) == 0);
}

TEST_CASE("ML-KEM SPKI covers every parameter set and rejects parameters") {
    const crypto::EKems sets[] = {
        crypto::EKEM_MLKEM512, crypto::EKEM_MLKEM768, crypto::EKEM_MLKEM1024
    };
    for (crypto::EKems expected : sets) {
        crypto::IKemPtr kem = crypto::IKem::builtIn(expected);
        REQUIRE(kem);
        crypto::SKemKeyPair pair;
        const crypto::SKeySize keySize(expected == crypto::EKEM_MLKEM512 ? 512
            : expected == crypto::EKEM_MLKEM768 ? 768 : 1024);
        ERetCode generated = ERET_AGAIN;
        for (size_t attempt = 0; attempt < 8 && generated == ERET_AGAIN; ++attempt) {
            generated = kem->generateKeyPair(keySize, pair);
        }
        REQUIRE(generated == ERET_OK);

        CBuffer der;
        REQUIRE(x509::CKemSubjectPublicKeyInfo::encode(pair.publicKey, der) == ERET_OK);
        crypto::EKems actual = crypto::EKEM_UNKNOWN;
        crypto::IKemPublicKeyPtr decoded;
        REQUIRE(x509::CKemSubjectPublicKeyInfo::decode(der.toSpan(), actual, decoded) == ERET_OK);
        CHECK(actual == expected);
        CHECK(decoded->compare(pair.publicKey) == 0);
    }

    // SEQUENCE { SEQUENCE { id-alg-ml-kem-512, NULL }, BIT STRING (empty) }.
    const uint8_t withNull[] = {
        0x30,0x10, 0x30,0x0d, 0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x01,
        0x05,0x00, 0x03,0x01,0x00
    };
    crypto::EKems which = crypto::EKEM_UNKNOWN;
    crypto::IKemPublicKeyPtr key;
    CHECK(x509::CKemSubjectPublicKeyInfo::decode(
        SReadOnlyByteSpan(withNull, sizeof(withNull)), which, key) != ERET_OK);
}
