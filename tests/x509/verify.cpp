#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

namespace {

    /* Issues a certificate for subjectKey, signed by issuerKeyPair. Passing the same key pair as
     * both makes it self-signed. digest defaults to the builder's own default. */
    bool issue(
        CCert& out, const CString& subjectDn, const CString& issuerDn,
        const IPublicKeyPtr& subjectKey, const SKeyPair& issuerKeyPair, uint8_t serialByte
    ) {
        CCertBuilder builder;
        if (!CDistinguishedName::tryParse(builder.issuer, issuerDn)) {
            return false;
        }
        if (!CDistinguishedName::tryParse(builder.subject, subjectDn)) {
            return false;
        }

        uint8_t serial[1] = { serialByte };
        builder.serialNumber = COctet(serial, 1);
        builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
        builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
        builder.subjectKey = subjectKey;
        builder.issuerKeyPair = issuerKeyPair;

        return builder.build(out) == ERET_OK;
    }

    SKeyPair generate(EAsymmetrics which, SKeySize size) {
        IAsymmetricPtr algo = IAsymmetric::builtIn(which);
        SKeyPair kp;

        for (int attempt = 0; attempt < 8 && algo; ++attempt) {
            if (algo->generateKeyPair(size, kp) == ERET_OK) {
                break;
            }
        }

        return kp;
    }

} // namespace

/* tbsCertificate() has to hand back the issuer's *original* bytes, since that is what the
 * signature covers -- so the span must point into rawData() rather than at a re-encoding, and
 * must cover the element's whole TLV (tag and length included), not just its content. */
TEST_CASE("CCert::tbsCertificate(): spans the original TBS TLV inside rawData()") {
    SKeyPair kp = generate(EASYM_P256, 256);
    REQUIRE(kp.publicKey);

    CCert cert;
    REQUIRE(issue(cert, CString("CN=Self"), CString("CN=Self"), kp.publicKey, kp, 0x01));

    SReadOnlyByteSpan tbs = cert.tbsCertificate();
    REQUIRE_FALSE(tbs.empty());

    SReadOnlyByteSpan raw = cert.rawData().toSpan();

    // Points into rawData(), not at a copy.
    CHECK(tbs.data >= raw.data);
    CHECK(tbs.data + tbs.size <= raw.data + raw.size);

    // A TBSCertificate is a SEQUENCE, and the span starts at its tag, not its content.
    CHECK(tbs.data[0] == 0x30);

    // It begins immediately after the outer Certificate SEQUENCE's own header, and leaves room
    // for the signatureAlgorithm and signatureValue that follow it.
    CHECK(tbs.data > raw.data);
    CHECK(tbs.size < raw.size);
}

TEST_CASE("CCert::tbsCertificate(): empty for a certificate that was never imported") {
    CCert cert;
    CHECK(cert.tbsCertificate().empty());
    CHECK(cert.signature().empty());
}

TEST_CASE("CCert::signature(): exposes the signature bits for every signature algorithm") {
    struct Case { EAsymmetrics which; SKeySize size; const char* name; };
    const Case cases[] = {
        { EASYM_RSA,     1024, "RSA"     },
        { EASYM_P256,     256, "P-256"   },
        { EASYM_ED25519,  256, "Ed25519" },
    };

    for (const Case& c : cases) {
        CAPTURE(c.name);

        SKeyPair kp = generate(c.which, c.size);
        REQUIRE(kp.publicKey);

        CCert cert;
        REQUIRE(issue(cert, CString("CN=Self"), CString("CN=Self"), kp.publicKey, kp, 0x01));
        CHECK_FALSE(cert.signature().empty());
    }
}

/* verifyBy() against the certificate's own key: the self-signed case, across one hash-then-sign
 * algorithm per family plus the self-hashing EdDSA path, which is the one that used to be
 * reachable only by mistaking "unresolved algorithm" for "EdDSA". */
TEST_CASE("CCert::verifyBy(): accepts a genuine self-signature") {
    struct Case { EAsymmetrics which; SKeySize size; const char* name; };
    const Case cases[] = {
        { EASYM_RSA,     1024, "RSA"     },
        { EASYM_P256,     256, "P-256"   },
        { EASYM_ED25519,  256, "Ed25519" },
        { EASYM_ED448,    456, "Ed448"   },
    };

    for (const Case& c : cases) {
        CAPTURE(c.name);

        SKeyPair kp = generate(c.which, c.size);
        REQUIRE(kp.publicKey);

        CCert cert;
        REQUIRE(issue(cert, CString("CN=Self"), CString("CN=Self"), kp.publicKey, kp, 0x01));
        CHECK(cert.verifyBy(cert) == ERET_OK);
    }
}

TEST_CASE("CCert::verifyBy(): accepts a CA-issued certificate against its issuer, and only it") {
    SKeyPair caKey = generate(EASYM_P256, 256);
    SKeyPair leafKey = generate(EASYM_P256, 256);
    SKeyPair strangerKey = generate(EASYM_P256, 256);
    REQUIRE(caKey.publicKey);
    REQUIRE(leafKey.publicKey);
    REQUIRE(strangerKey.publicKey);

    CCert ca;
    REQUIRE(issue(ca, CString("CN=Test CA"), CString("CN=Test CA"), caKey.publicKey, caKey, 0x01));

    CCert leaf;
    REQUIRE(issue(leaf, CString("CN=Leaf"), CString("CN=Test CA"), leafKey.publicKey, caKey, 0x02));

    CCert stranger;
    REQUIRE(issue(
        stranger, CString("CN=Stranger"), CString("CN=Stranger"),
        strangerKey.publicKey, strangerKey, 0x03
    ));

    CHECK(leaf.verifyBy(ca) == ERET_OK);

    // A different CA's key must not verify it, even though the certificate is otherwise valid --
    // and the leaf is not self-signed, so its own key must not verify it either.
    CHECK(leaf.verifyBy(stranger) != ERET_OK);
    CHECK(leaf.verifyBy(leaf) != ERET_OK);

    // verifyBy() is a single-link signature check and says nothing about names or constraints:
    // the stranger really is self-signed, so that much still verifies.
    CHECK(stranger.verifyBy(stranger) == ERET_OK);
}

/* The point of verifying against the original bytes rather than a re-encoding: corrupting any
 * byte of the signed region has to break the signature. A re-encoding-based implementation would
 * quietly "repair" some of these. */
TEST_CASE("CCert::verifyBy(): rejects a certificate whose signed bytes were altered") {
    SKeyPair kp = generate(EASYM_P256, 256);
    REQUIRE(kp.publicKey);

    CCert cert;
    REQUIRE(issue(cert, CString("CN=Self"), CString("CN=Self"), kp.publicKey, kp, 0x01));
    REQUIRE(cert.verifyBy(cert) == ERET_OK);

    COctet der;
    REQUIRE(cert.exportDer(der) == ERET_OK);

    SReadOnlyByteSpan tbs = cert.tbsCertificate();
    REQUIRE_FALSE(tbs.empty());

    // Offset of a byte well inside the TBS region, relative to the start of the DER.
    size_t tbsOffset = size_t(tbs.data - cert.rawData().toSpan().data);
    size_t target = tbsOffset + tbs.size / 2;
    REQUIRE(target < der.size());

    CBuffer tampered(der.size());
    std::memcpy(tampered.toPtr(), der.toSpan().data, der.size());
    tampered.toPtr()[target] ^= 0x01;

    CCert altered;
    if (altered.importDer(COctet(tampered.toSpan())) == ERET_OK) {
        CHECK(altered.verifyBy(altered) != ERET_OK);
    }
    // If the flip happened to make the DER unparseable, importDer() rejecting it is an equally
    // good outcome -- either way the altered bytes never verify.
}

TEST_CASE("CCert::verifyBy(): reports a usable error instead of guessing") {
    SKeyPair kp = generate(EASYM_P256, 256);
    REQUIRE(kp.publicKey);

    CCert cert;
    REQUIRE(issue(cert, CString("CN=Self"), CString("CN=Self"), kp.publicKey, kp, 0x01));

    CCert empty;
    CHECK(cert.verifyBy(empty) == ERET_INVAL);
    CHECK(empty.verifyBy(cert) == ERET_INVAL);
    CHECK(empty.verifyBy(empty) == ERET_INVAL);
}

// ----------------------------------------------------------------------------------------------
// CCrlReader::verifyBy() -- the CRL half of the same API.
// ----------------------------------------------------------------------------------------------

namespace {

    /* A self-signed P-256 CA with its private key attached, usable as a CRL issuer. */
    CCert makeCrlCa(const char* cn) {
        SKeyPair kp = generate(EASYM_P256, 256);
        REQUIRE(kp.publicKey);

        CString dn("CN=");
        dn.append(cn);

        CCert ca;
        REQUIRE(issue(ca, dn, dn, kp.publicKey, kp, 0x01));
        REQUIRE(ca.privateKey(kp.privateKey) == ERET_OK);
        return ca;
    }

} // namespace

TEST_CASE("CCrlReader::verifyBy(): accepts a CRL against its issuer, and only it") {
    CCert ca = makeCrlCa("CRL Verify CA");
    CCert stranger = makeCrlCa("Unrelated CA");

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 1, 1, 0, 0, 0, 0, true));
    writer.nextUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    COctet der;
    REQUIRE(writer.build(ca, der) == ERET_OK);

    CCrlReader reader;
    REQUIRE(reader.decode(der) == ERET_OK);

    CHECK_FALSE(reader.signature().empty());
    CHECK_FALSE(reader.tbsCertList().empty());

    CHECK(reader.verifyBy(ca) == ERET_OK);
    CHECK(reader.verifyBy(stranger) != ERET_OK);
}

TEST_CASE("CCrlReader::tbsCertList(): spans the original TBS TLV inside rawData()") {
    CCert ca = makeCrlCa("CRL Span CA");

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 1, 1, 0, 0, 0, 0, true));

    COctet der;
    REQUIRE(writer.build(ca, der) == ERET_OK);

    CCrlReader reader;
    REQUIRE(reader.decode(der) == ERET_OK);

    SReadOnlyByteSpan tbs = reader.tbsCertList();
    SReadOnlyByteSpan raw = reader.rawData().toSpan();
    REQUIRE_FALSE(tbs.empty());

    CHECK(tbs.data > raw.data);                            // past the outer SEQUENCE header
    CHECK(tbs.data + tbs.size <= raw.data + raw.size);
    CHECK(tbs.data[0] == 0x30);                            // its own SEQUENCE tag
    CHECK(tbs.size < raw.size);                            // leaves room for sigAlgo + signature
}

TEST_CASE("CCrlReader::verifyBy(): rejects a CRL whose signed bytes were altered") {
    CCert ca = makeCrlCa("CRL Tamper CA");

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 1, 1, 0, 0, 0, 0, true));
    writer.nextUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    CCert revoked;
    SKeyPair leafKey = generate(EASYM_P256, 256);
    REQUIRE(leafKey.publicKey);
    REQUIRE(issue(revoked, CString("CN=Revoked"), CString("CN=Revoked"), leafKey.publicKey, leafKey, 0x42));
    REQUIRE(writer.add(revoked, SDateTime(2026, 1, 15, 0, 0, 0, 0, true), ECRLR_KEY_COMPROMISE) == ERET_OK);

    COctet der;
    REQUIRE(writer.build(ca, der) == ERET_OK);

    CCrlReader good;
    REQUIRE(good.decode(der) == ERET_OK);
    REQUIRE(good.verifyBy(ca) == ERET_OK);

    SReadOnlyByteSpan tbs = good.tbsCertList();
    size_t target = size_t(tbs.data - good.rawData().toSpan().data) + tbs.size / 2;
    REQUIRE(target < der.size());

    CBuffer tampered(der.size());
    std::memcpy(tampered.toPtr(), der.toSpan().data, der.size());
    tampered.toPtr()[target] ^= 0x01;

    CCrlReader altered;
    if (altered.decode(COctet(tampered.toSpan())) == ERET_OK) {
        CHECK(altered.verifyBy(ca) != ERET_OK);
    }
}

TEST_CASE("CCrlReader::verifyBy(): reports a usable error instead of guessing") {
    CCert ca = makeCrlCa("CRL Error CA");

    CCrlReader undecoded;
    CHECK(undecoded.verifyBy(ca) == ERET_INVAL);
    CHECK(undecoded.signature().empty());
    CHECK(undecoded.tbsCertList().empty());

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 1, 1, 0, 0, 0, 0, true));
    COctet der;
    REQUIRE(writer.build(ca, der) == ERET_OK);

    CCrlReader reader;
    REQUIRE(reader.decode(der) == ERET_OK);

    CCert empty;
    CHECK(reader.verifyBy(empty) == ERET_INVAL);
}
