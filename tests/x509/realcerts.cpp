#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
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
 *                         end-to-end (RSA with PKCS#1 v1.5 or PSS, ECDSA), so importDer() plus
 *                         every derived accessor works fully.
 * certs/unimplemented/ -- real, currently-valid, commercially-issued certificates whose
 *                         signature or public-key algorithm importDer() can't resolve, so it
 *                         falls back to the raw OID text per its own doc comment and everything
 *                         derived from a resolved algorithm goes unavailable.
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
    constexpr const char* RSAPSS_CA_CERT_PATH   = CERTPP_TEST_DIR "/certs/implemented/quovadis-rsassa-pss-ca.der";
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

TEST_CASE("CCert (real-world): QuoVadis/DigiCert RSASSA-PSS timestamping CA (RSA-4096, PSS-SHA256, organizationIdentifier)") {
    // "DigiCert QV G3 TS EUR RSA4096 RSASSA-PSS 2025 CA1", issued by QuoVadis Root CA 1 G3
    // (found via crt.sh, a real commercial CA's currently-valid intermediate as of 2025-2034).
    // Two independent things make it worth keeping as a fixture, and each on its own used to
    // make importDer() fail:
    //
    //  * its subject carries an ETSI EN 319 412 "organizationIdentifier" (2.5.4.97), which was
    //    not one of the 6 basic X.520 types CName originally recognized -- and
    //    CDecoder::decodeDistinguishedName() rejects an RDN whose attribute type it can't name,
    //    so that single unknown attribute failed the entire subject Name, before the signature
    //    algorithm was ever looked at;
    //  * its signatureAlgorithm is id-RSASSA-PSS (1.2.840.113549.1.1.10, RFC 4055), the one
    //    signature algorithm here whose AlgorithmIdentifier parameters carry information the
    //    verifier actually needs. All four RSASSA-PSS-params fields are DEFAULTed, and DER omits
    //    a field equal to its default, so what this file spells out is exactly its three
    //    non-default ones -- see the assertions below.
    COctet der;
    REQUIRE(readCertFile(RSAPSS_CA_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);
    REQUIRE_FALSE(cert.empty());

    // --- subject: C / O / organizationIdentifier / CN, exactly four attributes.
    CHECK(cert.subject().size() == 4);

    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_C, name));
    CHECK(name == CName(ENAME_C, "NL"));
    REQUIRE(cert.subject().tryGet(ENAME_O, name));
    CHECK(name == CName(ENAME_O, "DigiCert Europe Netherlands B.V."));
    REQUIRE(cert.subject().tryGet(ENAME_OI, name));
    CHECK(name == CName(ENAME_OI, "NTRNL-30237459"));
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "DigiCert QV G3 TS EUR RSA4096 RSASSA-PSS 2025 CA1"));

    // ENAME_OI's key is the whole word "organizationIdentifier" -- no standard short form for it
    // exists, so CName::typeOf() has to match it in full rather than as a string that merely
    // starts with "O".
    CHECK(CName::typeOf("organizationIdentifier") == ENAME_OI);
    CHECK(CName::typeOf("O") == ENAME_O);

    // --- issuer: the root that signed this intermediate; only the basic three attributes.
    CHECK(cert.issuer().size() == 3);
    REQUIRE(cert.issuer().tryGet(ENAME_C, name));
    CHECK(name == CName(ENAME_C, "BM"));
    REQUIRE(cert.issuer().tryGet(ENAME_O, name));
    CHECK(name == CName(ENAME_O, "QuoVadis Limited"));
    REQUIRE(cert.issuer().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "QuoVadis Root CA 1 G3"));

    CHECK(cert.issuer() != cert.subject()); // --> an intermediate, not a self-signed root

    // --- algorithms. rsassaPss resolves by OID; the digest behind it comes from the parameters
    // rather than from the OID (which names none), so createHasher() is what proves they were
    // read at all.
    CHECK(cert.keyAlgo() == CString("RSA"));
    CHECK(cert.signAlgo() == CString("rsassaPss"));

    IHasherPtr hasher = cert.createHasher();
    REQUIRE(hasher);
    CHECK(hasher->byteWidth() == 32); // --> SHA-256, per RSASSA-PSS-params.hashAlgorithm

    // --- RSASSA-PSS-params as this file actually encodes them: [0] hashAlgorithm = id-sha256,
    // [1] maskGenAlgorithm = id-mgf1 parameterized with id-sha256, [2] saltLength = 32. [3]
    // trailerField is absent, which under DER *means* trailerFieldBC (1) -- so 1 is what gets
    // reported, not "unspecified".
    SRsaPssParams pss;
    REQUIRE(cert.rsaPssParams(pss));
    CHECK(pss.hashAlgo == EHASH_SHA256);
    CHECK(pss.mgfHashAlgo == EHASH_SHA256);
    CHECK(pss.saltLength == 32);
    CHECK(pss.trailerField == 1);

    // --- the rest of the certificate.
    IPublicKeyPtr pub = cert.publicKey();
    REQUIRE(pub);
    CHECK(pub->algorithm() == EASYM_RSA);

    CHECK(cert.notBefore().year == 2025);
    CHECK(cert.notBefore().month == 6);
    CHECK(cert.notBefore().day == 24);
    CHECK(cert.notAfter().year == 2034);
    CHECK(cert.notAfter().month == 6);
    CHECK(cert.notAfter().day == 22);

    REQUIRE(cert.serialNumber().size() == 20);
    CHECK(cert.serialNumber().toPtr()[0] == 0x51);
    CHECK(cert.serialNumber().toPtr()[19] == 0xad);

    CHECK(cert.signature().size() == 512); // --> 4096-bit modulus, so a 512-byte PSS signature
    CHECK(cert.thumbprint().size() == 20);

    auto bc = cert.extension<CBasicConstraintsExtension>();
    REQUIRE(bc);
    CHECK(bc->isCa());
    REQUIRE(bc->hasPathLenConstraint());
    CHECK(bc->pathLenConstraint() == 0);

    const uint16_t ku = cert.keyUsages();
    CHECK((ku & EKUSE_DIGITAL_SIGNATURE) != 0);
    CHECK((ku & EKUSE_KEY_CERT_SIGN) != 0);
    CHECK((ku & EKUSE_CRL_SIGN) != 0);
    CHECK((ku & EKUSE_KEY_ENCIPHERMENT) == 0);

    auto eku = cert.extension<CEkuExtension>();
    REQUIRE(eku);
    REQUIRE(eku->purposes().size() == 1);
    CHECK(eku->purposes()[0] == CString(CEkuExtension::OID_TIME_STAMPING));

    auto ski = cert.extension<CSkiExtension>();
    REQUIRE(ski);
    CHECK(ski->keyIdentifier().size() == 20);

    auto aki = cert.extension<CAkiExtension>();
    REQUIRE(aki);
    REQUIRE(aki->hasKeyIdentifier());
    CHECK(aki->keyIdentifier().size() == 20);

    // --- verifyBy() routes this through verifyPss() rather than PKCS#1 v1.5's verify(). The
    // issuer ("QuoVadis Root CA 1 G3") isn't in this repository, so the only key available to
    // check against is this certificate's own -- the wrong key, which must come back a mismatch.
    // What matters here is *which* failure: ERET_BADREQ is what verifyPss() itself reports for a
    // signature it rejects, i.e. the PSS verifier genuinely ran with the parsed hash and salt
    // length, whereas ERET_NOTSUP would mean verifyBy() declined the algorithm before doing any
    // arithmetic at all. The next test case signs and verifies with these same parameters, which
    // is the part a missing parent certificate can't cover.
    CHECK(cert.verifyBy(cert) == ERET_BADREQ);
}

TEST_CASE("CCert (real-world): the QuoVadis CA's own PSS parameters, exercised end-to-end against a generated RSA key") {
    // The parent of the RSASSA-PSS intermediate above ("QuoVadis Root CA 1 G3") isn't in this
    // repository, so its real signature can only be rejected, never confirmed (see above). What
    // *can* be exercised is everything else on that path: the parameters as parsed out of the
    // real file, driving a real sign/verify round-trip over the real TBSCertificate bytes, with
    // a locally generated key standing in for the issuer's.
    COctet der;
    REQUIRE(readCertFile(RSAPSS_CA_CERT_PATH, der));

    CCert cert;
    REQUIRE(cert.importDer(der) == ERET_OK);

    SRsaPssParams pss;
    REQUIRE(cert.rsaPssParams(pss));

    // The message: the real certificate's own signed bytes, digested with the hash its own
    // RSASSA-PSS-params named.
    IHasherPtr hasher = cert.createHasher();
    REQUIRE(hasher);

    CBuffer digest;
    REQUIRE(digest.resize(hasher->byteWidth()));
    REQUIRE(hasher->push(cert.tbsCertificate()));
    REQUIRE(hasher->finish(SByteSpan(digest.toPtr(), digest.size())));

    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    REQUIRE(rsa);
    SKeyPair kp;
    REQUIRE(rsa->generateKeyPair(1024, kp) == ERET_OK);

    IAsymmetricContextPtr ctx = rsa->createContext();
    REQUIRE(ctx);
    ctx->keyPair(kp.publicKey, kp.privateKey);

    CBuffer signature;
    REQUIRE(signature.resize(128)); // --> 1024-bit modulus
    SByteSpan sigOut = signature.toSpan();
    REQUIRE(ctx->signPss(digest.toSpan(), pss.hashAlgo, pss.saltLength, sigOut) == ERET_OK);
    REQUIRE(sigOut.size == 128);

    const SReadOnlyByteSpan sig(sigOut.data, sigOut.size);

    // The parameters the certificate carries verify it.
    CHECK(ctx->verifyPss(digest.toSpan(), pss.hashAlgo, pss.saltLength, sig) == ERET_OK);

    // A tampered signature does not.
    CBuffer tampered = signature;
    tampered[0] = uint8_t(tampered[0] ^ 0x01);
    CHECK(ctx->verifyPss(digest.toSpan(), pss.hashAlgo, pss.saltLength, tampered.toSpan()) != ERET_OK);

    // Neither does a tampered message.
    CBuffer otherDigest = digest;
    otherDigest[0] = uint8_t(otherDigest[0] ^ 0x01);
    CHECK(ctx->verifyPss(otherDigest.toSpan(), pss.hashAlgo, pss.saltLength, sig) != ERET_OK);

    // Nor the right signature checked with the wrong salt length -- the whole reason saltLength
    // has to be read out of the file instead of assumed. 20 is RSASSA-PSS-params' own DEFAULT,
    // i.e. precisely the value a parser that ignored [2] would have used.
    CHECK(pss.saltLength != 20);
    CHECK(ctx->verifyPss(digest.toSpan(), pss.hashAlgo, 20, sig) != ERET_OK);
    CHECK(ctx->verifyPss(digest.toSpan(), pss.hashAlgo, pss.saltLength - 1, sig) != ERET_OK);
    CHECK(ctx->verifyPss(digest.toSpan(), pss.hashAlgo, pss.saltLength + 1, sig) != ERET_OK);

    // Nor with the wrong hash, which through this API is also the wrong MGF1 hash: verifyPss()
    // drives the digest comparison and MGF1's mask generation from the same hashAlg. EHASH_SHA1
    // is exactly what a parser that fell back to RSASSA-PSS-params' defaults for [0] and [1]
    // would have supplied.
    CHECK(ctx->verifyPss(digest.toSpan(), EHASH_SHA1, pss.saltLength, sig) != ERET_OK);
    CHECK(ctx->verifyPss(digest.toSpan(), EHASH_SHA512, pss.saltLength, sig) != ERET_OK);
}

TEST_CASE("CCert: verifyBy() declines an RSASSA-PSS certificate whose MGF1 hash differs from its hashAlgorithm") {
    // Nothing in the wild encodes maskGenAlgorithm with a hash other than hashAlgorithm's --
    // RFC 8017 recommends against it, and every issuer complies -- but the encoding permits it,
    // and this library's verifyPss() takes a single hash algorithm for both roles. Verifying such
    // a signature with the wrong MGF1 hash would reject every valid signature, which a caller
    // can't distinguish from a forgery, so verifyBy() has to decline instead of guessing.
    //
    // The fixture: the real certificate above, with its *outer* signatureAlgorithm parameters
    // edited so maskGenAlgorithm's own hash OID reads id-sha384 where hashAlgorithm still reads
    // id-sha256. Both OIDs are 9 content octets, so the edit is length-preserving and the DER
    // stays well-formed; importDer() compares only the OID between the TBSCertificate's copy of
    // the AlgorithmIdentifier and this one, and it's this outer copy that verifyBy() reads.
    COctet der;
    REQUIRE(readCertFile(RSAPSS_CA_CERT_PATH, der));

    // id-mgf1's OBJECT IDENTIFIER followed by its parameters, SEQUENCE { id-sha256, NULL }. It
    // occurs exactly twice -- once in each copy of the AlgorithmIdentifier -- and the second is
    // the outer one.
    static const uint8_t MGF1_SHA256[] = {
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,   // id-mgf1
        0x30, 0x0d,                                                          // SEQUENCE
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,   // id-sha256
        0x05, 0x00                                                           // NULL
    };
    constexpr size_t SHA_VARIANT_AT = 23; // --> the id-sha256 OID's last content octet

    CBuffer raw;
    REQUIRE(raw.resize(der.size()));
    std::memcpy(raw.toPtr(), der.toPtr(), der.size());

    size_t patchedAt = size_t(-1);
    for (size_t i = 0; i + sizeof(MGF1_SHA256) <= raw.size(); ++i) {
        if (std::memcmp(raw.toPtr() + i, MGF1_SHA256, sizeof(MGF1_SHA256)) == 0) {
            patchedAt = i; // --> keep going: the last match is the outer AlgorithmIdentifier's
        }
    }
    REQUIRE(patchedAt != size_t(-1));
    raw[patchedAt + SHA_VARIANT_AT] = 0x02; // id-sha256 -> id-sha384

    CCert cert;
    REQUIRE(cert.importDer(COctet(SReadOnlyByteSpan(raw.toPtr(), raw.size()))) == ERET_OK);

    SRsaPssParams pss;
    REQUIRE(cert.rsaPssParams(pss));
    CHECK(pss.hashAlgo == EHASH_SHA256);
    CHECK(pss.mgfHashAlgo == EHASH_SHA384); // --> the mismatch, read as encoded
    CHECK(pss.saltLength == 32);

    // Fails closed, and specifically before any verification arithmetic: compare the unmodified
    // certificate's ERET_BADREQ (a genuine signature mismatch) in the first test case above.
    CHECK(cert.verifyBy(cert) == ERET_NOTSUP);
}

// --------------------------------------------------------------------------------------------
// certs/unimplemented/ -- real, currently-valid, commercially-issued certificates that exercise
// an actual gap in this library, collected separately from the above.
// --------------------------------------------------------------------------------------------

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
