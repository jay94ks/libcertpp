#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <fstream>

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

/* Real, currently-valid certificates collected from live commercial sites and Certificate
 * Transparency logs (see each TEST_CASE below for its own provenance), kept as on-disk .der
 * files rather than embedded byte arrays -- unlike tests/x509/cert.cpp's
 * synthetic, self-generated fixtures, these are meant to be inspected/replaced as standalone
 * files, and a directory of real captured certificates reads far more naturally as "a
 * collection" than a few thousand lines of hex.
 *
 * certs/implemented/  -- ordinary certificates using algorithms this library implements
 *                         end-to-end (RSA, ECDSA), so importDer() plus every derived accessor
 *                         works fully.
 * certs/unimplemented/ -- real, currently-valid, commercially-issued certificates that
 *                         exercise a gap this library actually has: either an algorithm
 *                         importDer() can't resolve (falls back to the raw OID text, per its own
 *                         doc comment) or, more fundamentally, a subject/issuer Name attribute
 *                         CDistinguishedName doesn't recognize at all.
 */

namespace {
    /* Reads an entire file into an owning COctet. False if the file can't be opened or read. */
    bool readCertFile(const char* path, COctet& out) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            return false;
        }

        std::streamsize size = file.tellg();
        if (size <= 0) {
            return false;
        }
        file.seekg(0, std::ios::beg);

        TArray<uint8_t> buffer;
        if (!buffer.resize(static_cast<size_t>(size))) {
            return false;
        }

        if (!file.read(reinterpret_cast<char*>(buffer.begin()), size)) {
            return false;
        }

        out = COctet(SReadOnlyByteSpan(buffer.begin(), buffer.size()));
        return true;
    }

    // CERTPP_TEST_DIR is injected by CMakeLists.txt: the absolute path of the directory
    // containing this .cpp file, so these paths resolve regardless of the working directory
    // ctest happens to run the test binary from.
    constexpr const char* GITHUB_CERT_PATH      = CERTPP_TEST_DIR "/certs/implemented/github.com.der";
    constexpr const char* AMAZON_CERT_PATH      = CERTPP_TEST_DIR "/certs/implemented/amazon.com.der";
    constexpr const char* SOURCEFORGE_CERT_PATH = CERTPP_TEST_DIR "/certs/implemented/sourceforge.net.der";
    constexpr const char* RSAPSS_CA_CERT_PATH   = CERTPP_TEST_DIR "/certs/unimplemented/quovadis-rsassa-pss-ca.der";
    constexpr const char* MLDSA_ROOT_CERT_PATH  = CERTPP_TEST_DIR "/certs/unimplemented/identrust-mldsa-root.der";
}

// --------------------------------------------------------------------------------------------
// certs/implemented/ -- algorithms this library resolves and parses end-to-end.
// --------------------------------------------------------------------------------------------

TEST_CASE("CCert (real-world): github.com leaf certificate (ECDSA P-256/SHA-256, issued by Sectigo)") {
    COctet der;
    REQUIRE(readCertFile(GITHUB_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    CHECK(cert.keyAlgo() == CString("EC"));
    CHECK(cert.signAlgo() == CString("ecdsa-with-SHA256"));

    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "github.com"));

    REQUIRE(cert.issuer().tryGet(ENAME_C, name));
    CHECK(name == CName(ENAME_C, "GB"));
    REQUIRE(cert.issuer().tryGet(ENAME_O, name));
    CHECK(name == CName(ENAME_O, "Sectigo Limited"));
    REQUIRE(cert.issuer().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "Sectigo Public Server Authentication CA DV E36"));

    CHECK(cert.notBefore().year == 2026);
    CHECK(cert.notBefore().month == 9);
    CHECK(cert.notBefore().day == 1);
    CHECK(cert.notAfter().year == 2026);
    CHECK(cert.notAfter().month == 11);
    CHECK(cert.notAfter().day == 29);

    CHECK_FALSE(cert.serialNumber().empty());
    CHECK(cert.thumbprint().size() == 20);

    IPublicKeyPtr pub = cert.publicKey();
    REQUIRE(pub);
    CHECK(pub->keySize() == 256);

    IHasherPtr hasher = cert.createHasher();
    REQUIRE(hasher);
    CHECK(hasher->byteWidth() == 32); // --> SHA-256.
}

TEST_CASE("CCert (real-world): github.com leaf certificate's SAN/EKU/AIA/CertificatePolicies extensions") {
    // Ground truth cross-checked via `openssl x509 -in github.com.der -inform DER -text`.
    COctet der;
    REQUIRE(readCertFile(GITHUB_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    auto san = cert.extension<CSanExtension>();
    REQUIRE(san);
    REQUIRE(san->names().size() == 2);
    CHECK(san->names()[0].type() == EGNAME_DNS);
    CHECK(san->names()[0].text() == CString("github.com"));
    CHECK(san->names()[1].type() == EGNAME_DNS);
    CHECK(san->names()[1].text() == CString("www.github.com"));

    auto eku = cert.extension<CEkuExtension>();
    REQUIRE(eku);
    CHECK(eku->has(CEkuExtension::OID_SERVER_AUTH));
    CHECK_FALSE(eku->has(CEkuExtension::OID_CLIENT_AUTH));

    // No CRLDistributionPoints on this cert -- Sectigo relies on OCSP (AIA) instead.
    CHECK_FALSE(cert.extension<CCdpExtension>());

    auto aia = cert.extension<CAiaExtension>();
    REQUIRE(aia);
    REQUIRE(aia->descriptions().size() == 2);
    CHECK(aia->descriptions()[0].accessMethod() == CString(CAiaExtension::OID_CA_ISSUERS_METHOD));
    CHECK(aia->descriptions()[0].accessLocation().text() == CString("http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt"));
    CHECK(aia->descriptions()[1].accessMethod() == CString(CAiaExtension::OID_OCSP_METHOD));
    CHECK(aia->descriptions()[1].accessLocation().text() == CString("http://ocsp.sectigo.com"));

    auto cp = cert.extension<CPoliciesExtension>();
    REQUIRE(cp);
    REQUIRE(cp->policies().size() == 2);
    CHECK(cp->policies()[0].policyIdentifier() == CString("1.3.6.1.4.1.6449.1.2.2.7"));
    CHECK(cp->policies()[0].hasPolicyQualifiers());
    // --> 2.23.140.1.2.1 is the CA/Browser Forum Baseline Requirements' "domain-validated"
    // reserved policy identifier, not this library's own OID_ANY_POLICY (2.5.29.32.0).
    CHECK(cp->policies()[1].policyIdentifier() == CString("2.23.140.1.2.1"));
}

TEST_CASE("CCert (real-world): amazon.com leaf certificate (RSA-2048/SHA-256, issued by DigiCert/GeoTrust)") {
    COctet der;
    REQUIRE(readCertFile(AMAZON_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    CHECK(cert.keyAlgo() == CString("RSA"));
    CHECK(cert.signAlgo() == CString("sha256WithRSAEncryption"));

    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "*.peg.a2z.com"));

    REQUIRE(cert.issuer().tryGet(ENAME_C, name));
    CHECK(name == CName(ENAME_C, "US"));
    REQUIRE(cert.issuer().tryGet(ENAME_O, name));
    CHECK(name == CName(ENAME_O, "DigiCert Inc"));
    REQUIRE(cert.issuer().tryGet(ENAME_OU, name));
    CHECK(name == CName(ENAME_OU, "www.digicert.com"));
    REQUIRE(cert.issuer().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "GeoTrust TLS RSA CA G1"));

    CHECK(cert.notBefore().year == 2026);
    CHECK(cert.notBefore().month == 9);
    CHECK(cert.notBefore().day == 20);
    CHECK(cert.notAfter().year == 2027);
    CHECK(cert.notAfter().month == 4);
    CHECK(cert.notAfter().day == 5);

    IPublicKeyPtr pub = cert.publicKey();
    REQUIRE(pub);
    CHECK(pub->keySize() == 2048);
}

TEST_CASE("CCert (real-world): amazon.com leaf certificate's SAN/CDP/AIA/CertificatePolicies extensions") {
    // Ground truth cross-checked via `openssl x509 -in amazon.com.der -inform DER -text`.
    COctet der;
    REQUIRE(readCertFile(AMAZON_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    auto san = cert.extension<CSanExtension>();
    REQUIRE(san);
    REQUIRE(san->names().size() == 47);
    CHECK(san->names()[0].type() == EGNAME_DNS);
    CHECK(san->names()[0].text() == CString("amazon.co.uk"));

    auto cdp = cert.extension<CCdpExtension>();
    REQUIRE(cdp);
    REQUIRE(cdp->points().size() == 1);
    REQUIRE(cdp->points()[0].fullName().size() == 1);
    CHECK(cdp->points()[0].fullName()[0].type() == EGNAME_URI);
    CHECK(cdp->points()[0].fullName()[0].text() == CString("http://cdp.geotrust.com/GeoTrustTLSRSACAG1.crl"));
    CHECK_FALSE(cdp->points()[0].hasReasons());

    auto aia = cert.extension<CAiaExtension>();
    REQUIRE(aia);
    REQUIRE(aia->descriptions().size() == 2);
    CHECK(aia->descriptions()[0].accessMethod() == CString(CAiaExtension::OID_OCSP_METHOD));
    CHECK(aia->descriptions()[0].accessLocation().text() == CString("http://status.geotrust.com"));
    CHECK(aia->descriptions()[1].accessMethod() == CString(CAiaExtension::OID_CA_ISSUERS_METHOD));
    CHECK(aia->descriptions()[1].accessLocation().text() == CString("http://cacerts.geotrust.com/GeoTrustTLSRSACAG1.crt"));

    auto cp = cert.extension<CPoliciesExtension>();
    REQUIRE(cp);
    REQUIRE(cp->policies().size() == 1);
    // --> 2.23.140.1.2.1 is the CA/Browser Forum Baseline Requirements' "domain-validated"
    // reserved policy identifier, not this library's own OID_ANY_POLICY (2.5.29.32.0).
    CHECK(cp->policies()[0].policyIdentifier() == CString("2.23.140.1.2.1"));
    CHECK(cp->policies()[0].hasPolicyQualifiers());
}

TEST_CASE("CCert (real-world): sourceforge.net leaf certificate (ECDSA P-256/SHA-384, issued by Let's Encrypt)") {
    COctet der;
    REQUIRE(readCertFile(SOURCEFORGE_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    CHECK(cert.keyAlgo() == CString("EC"));
    CHECK(cert.signAlgo() == CString("ecdsa-with-SHA384"));

    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "sourceforge.net"));

    REQUIRE(cert.issuer().tryGet(ENAME_O, name));
    CHECK(name == CName(ENAME_O, "Let's Encrypt"));
    REQUIRE(cert.issuer().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "YE2"));

    CHECK(cert.notBefore().year == 2026);
    CHECK(cert.notBefore().month == 8);
    CHECK(cert.notBefore().day == 12);
    CHECK(cert.notAfter().year == 2026);
    CHECK(cert.notAfter().month == 11);
    CHECK(cert.notAfter().day == 10);

    IPublicKeyPtr pub = cert.publicKey();
    REQUIRE(pub);
    CHECK(pub->keySize() == 256);

    // signAlgo() is SHA-384 despite the key being the same P-256 curve as github.com's --
    // createHasher() must follow signAlgo(), not the key size.
    IHasherPtr hasher = cert.createHasher();
    REQUIRE(hasher);
    CHECK(hasher->byteWidth() == 48); // --> SHA-384.
}

TEST_CASE("CCert (real-world): sourceforge.net leaf certificate's SAN/CDP/AIA/CertificatePolicies extensions") {
    // Ground truth cross-checked via `openssl x509 -in sourceforge.net.der -inform DER -text`.
    // Unlike github.com/amazon.com's, this cert's AIA has only a CA Issuers entry (no OCSP), and
    // its one certificate policy carries no CPS qualifier -- both otherwise-untested shapes.
    COctet der;
    REQUIRE(readCertFile(SOURCEFORGE_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    auto san = cert.extension<CSanExtension>();
    REQUIRE(san);
    REQUIRE(san->names().size() == 3);
    CHECK(san->names()[0].text() == CString("*.sourceforge.net"));
    CHECK(san->names()[1].text() == CString("*.users.sourceforge.net"));
    CHECK(san->names()[2].text() == CString("sourceforge.net"));

    auto cdp = cert.extension<CCdpExtension>();
    REQUIRE(cdp);
    REQUIRE(cdp->points().size() == 1);
    REQUIRE(cdp->points()[0].fullName().size() == 1);
    CHECK(cdp->points()[0].fullName()[0].text() == CString("http://ye2.c.lencr.org/54.crl"));

    auto aia = cert.extension<CAiaExtension>();
    REQUIRE(aia);
    REQUIRE(aia->descriptions().size() == 1);
    CHECK(aia->descriptions()[0].accessMethod() == CString(CAiaExtension::OID_CA_ISSUERS_METHOD));
    CHECK(aia->descriptions()[0].accessLocation().text() == CString("http://ye2.i.lencr.org/"));

    auto cp = cert.extension<CPoliciesExtension>();
    REQUIRE(cp);
    REQUIRE(cp->policies().size() == 1);
    CHECK(cp->policies()[0].policyIdentifier() == CString("2.23.140.1.2.1"));
    CHECK_FALSE(cp->policies()[0].hasPolicyQualifiers());
}

// --------------------------------------------------------------------------------------------
// certs/unimplemented/ -- real, currently-valid, commercially-issued certificates that exercise
// an actual gap in this library, collected separately from the above.
// --------------------------------------------------------------------------------------------

TEST_CASE("CCert (real-world, unimplemented): QuoVadis RSASSA-PSS qualified CA -- fails structurally, not just on algorithm") {
    // "DigiCert QV G3 TS EUR RSA4096 RSASSA-PSS 2025 CA1", issued by QuoVadis Root CA 1 G3
    // (found via crt.sh, a real commercial CA's currently-valid intermediate as of 2025-2034).
    // Its own signatureAlgorithm is rsassaPss (1.2.840.113549.1.1.10, RFC 4055) -- not in this
    // library's SIG_ALGOS table -- which on its own would just leave signAlgo() at the raw OID
    // text, the same graceful fallback the ML-DSA case below demonstrates.
    //
    // But this particular certificate's subject also carries an ETSI EN 319 412
    // "organizationIdentifier" attribute (OID 2.5.4.97, common on EU-regulated/qualified
    // certificates), which isn't one of the 6 basic X.520 types CName recognizes (C/ST/L/O/OU/
    // CN) -- CDecoder::decodeDistinguishedName() fails the whole subject Name over that single
    // unrecognized attribute, so importDer() fails with ERET_BADREQ before it ever reaches the
    // signature algorithm at all. A real, structural gap, distinct from (and more fundamental
    // than) an unresolved algorithm OID.
    COctet der;
    REQUIRE(readCertFile(RSAPSS_CA_CERT_PATH, der));

    CCert cert;
    CHECK(cert.importDer(der) == ERET_BADREQ);
    CHECK(cert.empty());
}

TEST_CASE("CCert (real-world, unimplemented): IdenTrust ML-DSA pilot root -- parses fully, algorithm gracefully unresolved") {
    // "IdenTrust Pilot Root TLS ML-DSA CA 1", a real, currently-valid (2026-2027) self-signed
    // pilot root from IdenTrust (a long-established commercial CA) for ML-DSA (NIST FIPS 204,
    // post-quantum) -- found via crt.sh. Both the public key type and the signature algorithm
    // use the same OID (2.16.840.1.101.3.4.3.19); OpenSSL 3.2 itself can't even decode the
    // public key. Unlike the RSASSA-PSS certificate above, this one's subject/issuer only use
    // plain C/O/CN, so it's a clean demonstration of importDer()'s documented fallback: the
    // certificate parses completely, keyAlgo()/signAlgo() fall back to the dotted-decimal OID
    // text, and everything that depends on a resolved algorithm (publicKey(), createHasher(),
    // createAsymmetricContext()) is simply unavailable -- without that failing the importDer or
    // losing any of the certificate's other data.
    COctet der;
    REQUIRE(readCertFile(MLDSA_ROOT_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    CHECK(cert.keyAlgo() == CString("2.16.840.1.101.3.4.3.19"));
    CHECK(cert.signAlgo() == CString("2.16.840.1.101.3.4.3.19"));

    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_C, name));
    CHECK(name == CName(ENAME_C, "US"));
    REQUIRE(cert.subject().tryGet(ENAME_O, name));
    CHECK(name == CName(ENAME_O, "IdenTrust"));
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "IdenTrust Pilot Root TLS ML-DSA CA 1"));

    // Self-signed root.
    CHECK(cert.issuer() == cert.subject());

    CHECK(cert.notBefore().year == 2026);
    CHECK(cert.notBefore().month == 7);
    CHECK(cert.notAfter().year == 2027);
    CHECK(cert.notAfter().month == 7);

    CHECK_FALSE(cert.publicKey());              // --> _asym never resolved for this OID.
    CHECK_FALSE(cert.createHasher());            // --> _sigHashAlgo stays EHASH_UNKNOWN.
    CHECK_FALSE(cert.createAsymmetricContext());

    // Unaffected by the unresolved algorithm -- both are computed directly from rawData().
    CHECK_FALSE(cert.rawData().empty());
    CHECK(cert.thumbprint().size() == 20);
}
