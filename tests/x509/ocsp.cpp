#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <algorithm>
#include <vector>

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

namespace {

    /* The content octets of an OID, as they appear inside an encoded Extension. */
    std::vector<uint8_t> oidBytes(const SKnownOid& oid) {
        const COid id(oid);
        const size_t needed = asn1::CEncoder::encodedOidSize(id.raw());
        REQUIRE(needed > 0);

        CBuffer content;
        REQUIRE(content.resize(needed) == true);

        size_t written = 0;
        REQUIRE(asn1::CEncoder::encodeOid(content.toSpan(), id.raw(), written) == true);
        REQUIRE(written == needed);

        const uint8_t* p = content.toPtr();
        return std::vector<uint8_t>(p, p + written);
    }

    /* Returns `der` with the first occurrence of `from` replaced by `to`. Requires equal
     * lengths, so the encoding around the OID stays well-formed. */
    bool retargetOid(const COctet& der, const std::vector<uint8_t>& from,
                     const std::vector<uint8_t>& to, COctet& out) {
        if (from.size() != to.size() || from.empty() || der.empty()) {
            return false;
        }

        CBuffer buffer;
        if (!buffer.resize(der.size())) {
            return false;
        }

        std::copy(der.toPtr(), der.toPtr() + der.size(), buffer.toPtr());

        uint8_t* p = buffer.toPtr();
        for (size_t i = 0; i + from.size() <= der.size(); ++i) {
            if (std::equal(from.begin(), from.end(), p + i)) {
                std::copy(to.begin(), to.end(), p + i);
                out.store(buffer.toPtr(), buffer.size());
                return true;
            }
        }

        return false;
    }

    /* Builds a self-signed P-256 CA certificate with its own private key attached and a
     * SubjectKeyIdentifier extension, for use as an OCSP responder/issuer across these tests. */
    CCert makeCa(const char* cn, COctet& outSki) {
        IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
        SKeyPair kp;
        REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

        COctet pubBytes;
        REQUIRE(kp.publicKey->serialize(pubBytes) == ERET_OK);
        IHasherPtr sha1;
        REQUIRE(IHasher::create(EHASH_SHA1, sha1) == ERET_OK);
        uint8_t skiBytes[20];
        sha1->push(pubBytes.toSpan());
        sha1->finish(SByteSpan(skiBytes, sizeof(skiBytes)));
        outSki = COctet(skiBytes, sizeof(skiBytes));

        CCertBuilder builder;
        CString dn("C=US, O=libcertpp OCSP Test, CN=");
        dn.append(cn);
        REQUIRE(CDistinguishedName::tryParse(builder.issuer, dn));
        builder.subject = builder.issuer;

        uint8_t serial[1] = { 0x01 };
        builder.serialNumber = COctet(serial, 1);
        builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
        builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
        builder.subjectKey = kp.publicKey;
        builder.issuerKeyPair = kp;

        CBasicConstraintsExtensionBuilder bc;
        bc.setIsCa(true);
        builder.extensions.add(bc.build());

        CSkiExtensionBuilder ski;
        ski.setKeyIdentifier(outSki);
        builder.extensions.add(ski.build());

        CCert ca;
        REQUIRE(builder.build(ca) == ERET_OK);
        REQUIRE(ca.privateKey(kp.privateKey) == ERET_OK);
        return ca;
    }

    /* Builds a self-signed P-256 leaf certificate with the given serial byte, issued (in name
     * only -- not actually signed by it) under ca's own subject, carrying an
     * AuthorityKeyIdentifier pointing at caSki -- what COcspCertId::make(cert, out)'s AKI
     * shortcut needs. */
    CCert makeLeaf(const CCert& ca, const COctet& caSki, uint8_t serialByte) {
        IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
        SKeyPair kp;
        REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

        CCertBuilder builder;
        builder.issuer = ca.subject();
        REQUIRE(CDistinguishedName::tryParse(builder.subject, CString("C=US, O=libcertpp OCSP Test, CN=Leaf")));

        uint8_t serial[1] = { serialByte };
        builder.serialNumber = COctet(serial, 1);
        builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
        builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
        builder.subjectKey = kp.publicKey;
        builder.issuerKeyPair = kp; // self-signed in practice; issuer name/AKI below mimic a real chain

        CAkiExtensionBuilder aki;
        aki.setKeyIdentifier(caSki);
        builder.extensions.add(aki.build());

        CCert leaf;
        REQUIRE(builder.build(leaf) == ERET_OK);
        return leaf;
    }

}

TEST_CASE("COcspCertId: make() with the issuer certificate round-trips through encode()/decode()") {
    COctet caSki;
    CCert ca = makeCa("CertId CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x10);

    COcspCertId certId;
    REQUIRE(COcspCertId::make(leaf, ca, EHASH_SHA256, certId) == ERET_OK);
    CHECK_FALSE(certId.empty());
    CHECK(certId.hashAlgo() == EHASH_SHA256);
    CHECK(certId.serialNumber().toSpan().sequencialEqual(leaf.serialNumber().toSpan()));

    COctet rawTlv;
    REQUIRE(certId.encode(rawTlv) == ERET_OK);

    COcspCertId decoded;
    REQUIRE(COcspCertId::decode(rawTlv, decoded) == ERET_OK);
    CHECK(decoded.equals(certId));
    CHECK(decoded.isFor(leaf));
}

TEST_CASE("COcspCertId: AKI-shortcut make() matches the fully general make()") {
    COctet caSki;
    CCert ca = makeCa("Shortcut CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x11);

    COcspCertId viaAki;
    REQUIRE(COcspCertId::make(leaf, viaAki) == ERET_OK);
    CHECK(viaAki.hashAlgo() == EHASH_SHA1);

    COcspCertId viaIssuer;
    REQUIRE(COcspCertId::make(leaf, ca, EHASH_SHA1, viaIssuer) == ERET_OK);

    CHECK(viaAki.equals(viaIssuer));
    CHECK(viaAki.isFor(leaf));
}

TEST_CASE("COcspCertId: make() fails without a usable AuthorityKeyIdentifier") {
    COctet caSki;
    CCert ca = makeCa("No AKI CA", caSki);

    // ca itself is self-signed with no AKI extension of its own.
    COcspCertId certId;
    CHECK(COcspCertId::make(ca, certId) == ERET_NOTSUP);
}

TEST_CASE("COcspCertId: isFor() distinguishes certificates by serial, equals() by full content") {
    COctet caSki;
    CCert ca = makeCa("isFor CA", caSki);
    CCert leafA = makeLeaf(ca, caSki, 0x20);
    CCert leafB = makeLeaf(ca, caSki, 0x21);

    COcspCertId idA, idB;
    REQUIRE(COcspCertId::make(leafA, ca, EHASH_SHA256, idA) == ERET_OK);
    REQUIRE(COcspCertId::make(leafB, ca, EHASH_SHA256, idB) == ERET_OK);

    CHECK(idA.isFor(leafA));
    CHECK_FALSE(idA.isFor(leafB));
    CHECK_FALSE(idA.equals(idB));
    CHECK(idA.equals(idA));
}

TEST_CASE("COcspEntry: GOOD status round-trips through encode()/decode()") {
    COctet caSki;
    CCert ca = makeCa("Entry Good CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x30);

    COcspCertId certId;
    REQUIRE(COcspCertId::make(leaf, ca, EHASH_SHA256, certId) == ERET_OK);

    SDateTime thisUpdate(2026, 2, 1, 0, 0, 0, 0, true);
    SDateTime nextUpdate(2026, 2, 8, 0, 0, 0, 0, true);
    COcspEntry entry(certId, EOCSPENT_GOOD, ECRLR_NONE, thisUpdate, nextUpdate);

    COctet raw;
    REQUIRE(entry.encode(raw) == ERET_OK);

    COcspEntry decoded;
    REQUIRE(COcspEntry::decode(raw, decoded) == ERET_OK);
    CHECK(decoded.status() == EOCSPENT_GOOD);
    CHECK(decoded.certId().equals(certId));
    CHECK(decoded.thisUpdate().year == thisUpdate.year);
    CHECK(decoded.thisUpdate().month == thisUpdate.month);
    CHECK(decoded.thisUpdate().day == thisUpdate.day);
    CHECK(decoded.nextUpdate().day == nextUpdate.day);
}

TEST_CASE("COcspEntry: REVOKED status with a reason round-trips through encode()/decode()") {
    COctet caSki;
    CCert ca = makeCa("Entry Revoked CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x31);

    COcspCertId certId;
    REQUIRE(COcspCertId::make(leaf, ca, EHASH_SHA256, certId) == ERET_OK);

    SDateTime thisUpdate(2026, 2, 1, 0, 0, 0, 0, true);
    SDateTime revokedAt(2026, 1, 15, 0, 0, 0, 0, true);
    COcspEntry entry(certId, EOCSPENT_REVOKED, ECRLR_KEY_COMPROMISE, thisUpdate, SDateTime(), revokedAt);

    COctet raw;
    REQUIRE(entry.encode(raw) == ERET_OK);

    COcspEntry decoded;
    REQUIRE(COcspEntry::decode(raw, decoded) == ERET_OK);
    CHECK(decoded.status() == EOCSPENT_REVOKED);
    CHECK(decoded.reason() == ECRLR_KEY_COMPROMISE);
    CHECK(decoded.revocationTime().day == 15);
    CHECK(decoded.nextUpdate().isZero());
}

TEST_CASE("COcspEntry: UNKNOWN status round-trips through encode()/decode()") {
    COctet caSki;
    CCert ca = makeCa("Entry Unknown CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x32);

    COcspCertId certId;
    REQUIRE(COcspCertId::make(leaf, ca, EHASH_SHA256, certId) == ERET_OK);

    COcspEntry entry(certId, EOCSPENT_UNKNOWN, ECRLR_NONE, SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    COctet raw;
    REQUIRE(entry.encode(raw) == ERET_OK);

    COcspEntry decoded;
    REQUIRE(COcspEntry::decode(raw, decoded) == ERET_OK);
    CHECK(decoded.status() == EOCSPENT_UNKNOWN);
}

TEST_CASE("COcspEntry: encode() rejects a missing thisUpdate or a revoked entry missing revocationTime") {
    COctet caSki;
    CCert ca = makeCa("Entry Validation CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x33);

    COcspCertId certId;
    REQUIRE(COcspCertId::make(leaf, ca, EHASH_SHA256, certId) == ERET_OK);

    COcspEntry noThisUpdate(certId, EOCSPENT_GOOD);
    COctet raw;
    CHECK(noThisUpdate.encode(raw) == ERET_INVAL);

    COcspEntry revokedNoTime(certId, EOCSPENT_REVOKED, ECRLR_NONE, SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    CHECK(revokedNoTime.encode(raw) == ERET_INVAL);
}

TEST_CASE("COcspRequestBuilder: add()/build()/decode() round-trips the certificate IDs and nonce") {
    COctet caSki;
    CCert ca = makeCa("Request CA", caSki);
    CCert leaf1 = makeLeaf(ca, caSki, 0x40);
    CCert leaf2 = makeLeaf(ca, caSki, 0x41);

    COcspRequestBuilder builder;
    REQUIRE(builder.add(leaf1, ca, EHASH_SHA256) == ERET_OK);
    REQUIRE(builder.add(leaf2) == ERET_OK); // AKI shortcut overload
    REQUIRE(builder.generateNonce(16) == ERET_OK);
    CHECK(builder.nonceBytes().size() == 16);
    CHECK(builder.contains(leaf1));
    CHECK(builder.contains(leaf2));

    COctet encoded;
    REQUIRE(builder.build(encoded) == ERET_OK);
    REQUIRE_FALSE(encoded.empty());

    CBuffer encodedBuf;
    encodedBuf.resize(encoded.size());
    std::memcpy(encodedBuf.toPtr(), encoded.toPtr(), encoded.size());

    COcspRequest decoded;
    REQUIRE(decoded.decode(encodedBuf) == ERET_OK);
    REQUIRE(decoded.certIds().size() == 2);
    CHECK(decoded.contains(leaf1));
    CHECK(decoded.contains(leaf2));
    CHECK(decoded.nonceBytes().toSpan().sequencialEqual(builder.nonceBytes().toSpan()));
    CHECK(decoded.requestorName().empty()); // unsigned -- no requestorCert was set
}

TEST_CASE("COcspRequestBuilder: remove() removes a certificate ID and reports not-found afterward") {
    COctet caSki;
    CCert ca = makeCa("Request Remove CA", caSki);
    CCert leaf1 = makeLeaf(ca, caSki, 0x42);
    CCert leaf2 = makeLeaf(ca, caSki, 0x43);

    COcspRequestBuilder builder;
    REQUIRE(builder.add(leaf1, ca, EHASH_SHA256) == ERET_OK);
    REQUIRE(builder.add(leaf2, ca, EHASH_SHA256) == ERET_OK);

    REQUIRE(builder.remove(leaf1) == ERET_OK);
    CHECK_FALSE(builder.contains(leaf1));
    CHECK(builder.contains(leaf2));
    CHECK(builder.remove(leaf1) == ERET_INVAL);
}

TEST_CASE("COcspRequestBuilder: build() rejects an empty request; decode() rejects malformed data") {
    COcspRequestBuilder builder;
    COctet out;
    CHECK(builder.build(out) == ERET_INVAL);

    uint8_t garbage[] = { 0x01, 0x02, 0x03 };
    CBuffer bad;
    bad.resize(sizeof(garbage));
    std::memcpy(bad.toPtr(), garbage, sizeof(garbage));

    COcspRequest decoded;
    CHECK(decoded.decode(bad) == ERET_BADREQ);
}

TEST_CASE("COcspRequestBuilder: requestorCert() signs the request, and COcspRequest::verifySignature() accepts it") {
    COctet caSki;
    CCert ca = makeCa("Request Signer CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x44);

    // The requestor signs with its own key pair -- any certificate with an attached private key
    // works for this purpose (RFC 6960 doesn't require the requestor to be a CA at all).
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
    SKeyPair requestorKp;
    REQUIRE(ec->generateKeyPair(256, requestorKp) == ERET_OK);

    CCertBuilder requestorBuilder;
    REQUIRE(CDistinguishedName::tryParse(requestorBuilder.issuer, CString("C=US, O=libcertpp, CN=OCSP Requestor")));
    requestorBuilder.subject = requestorBuilder.issuer;
    uint8_t serial[1] = { 0x01 };
    requestorBuilder.serialNumber = COctet(serial, 1);
    requestorBuilder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    requestorBuilder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    requestorBuilder.subjectKey = requestorKp.publicKey;
    requestorBuilder.issuerKeyPair = requestorKp;

    CCert requestorCert;
    REQUIRE(requestorBuilder.build(requestorCert) == ERET_OK);
    REQUIRE(requestorCert.privateKey(requestorKp.privateKey) == ERET_OK);

    COcspRequestBuilder builder;
    REQUIRE(builder.add(leaf, ca, EHASH_SHA256) == ERET_OK);
    builder.requestorCert(requestorCert);

    COctet out;
    REQUIRE(builder.build(out) == ERET_OK);

    CBuffer outBuf;
    outBuf.resize(out.size());
    std::memcpy(outBuf.toPtr(), out.toPtr(), out.size());

    COcspRequest decoded;
    REQUIRE(decoded.decode(outBuf) == ERET_OK);
    CHECK(decoded.requestorName() == requestorCert.subject());
    CHECK(decoded.verifySignature(requestorCert) == ERET_OK);

    // A different certificate's public key must not verify.
    CHECK(decoded.verifySignature(ca) != ERET_OK);
}

TEST_CASE("COcspRequestBuilder: build() rejects a requestorCert with no private key attached") {
    COctet caSki;
    CCert ca = makeCa("Request Signer No Key CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x45);

    // ca itself has a private key attached (from makeCa()), but a freshly re-imported copy of
    // its DER doesn't.
    COctet caDer;
    REQUIRE(ca.exportDer(caDer) == ERET_OK);
    CCert caNoKey;
    REQUIRE(caNoKey.importDer(caDer) == ERET_OK);

    COcspRequestBuilder builder;
    REQUIRE(builder.add(leaf, ca, EHASH_SHA256) == ERET_OK);
    builder.requestorCert(caNoKey);

    COctet out;
    CHECK(builder.build(out) == ERET_KEY_EMPTY);
}

TEST_CASE("COcspResponse: build()/decode() round-trips a GOOD verdict, and verifySignature() accepts it") {
    COctet caSki;
    CCert ca = makeCa("Response Good CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x50);

    COcspResponseBuilder response;
    response.status(EOCSP_OK);
    response.producedAt(SDateTime(2026, 2, 1, 12, 0, 0, 0, true));

    REQUIRE(
        response.add(
            leaf, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 12, 0, 0, 0, true), SDateTime(2026, 2, 8, 12, 0, 0, 0, true)
        ) == ERET_OK
    );

    COctet out;
    REQUIRE(response.build(ca, out) == ERET_OK);
    REQUIRE_FALSE(out.empty());

    COcspResponse decoded;
    REQUIRE(decoded.decode(out) == ERET_OK);
    CHECK(decoded.status() == EOCSP_OK);
    CHECK(decoded.responderName() == ca.subject());
    CHECK(decoded.producedAt().year == 2026);
    REQUIRE(decoded.entries().size() == 1);
    CHECK(decoded.check(leaf) == ERET_OK);
    CHECK(decoded.verifySignature(ca) == ERET_OK);

    // Tampering with the signed bytes must make verification fail.
    std::vector<uint8_t> tamperedBytes(out.toPtr(), out.toPtr() + out.size());
    tamperedBytes[tamperedBytes.size() / 2] ^= 0xFF;
    COctet tampered(tamperedBytes.data(), tamperedBytes.size());

    COcspResponse tamperedResponse;
    if (tamperedResponse.decode(tampered) == ERET_OK) {
        CHECK(tamperedResponse.verifySignature(ca) != ERET_OK);
    }
}

TEST_CASE("COcspResponse: build()/decode() round-trips a REVOKED verdict with a reason") {
    COctet caSki;
    CCert ca = makeCa("Response Revoked CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x51);

    COcspResponseBuilder response;
    response.status(EOCSP_OK);
    response.producedAt(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(
        response.add(
            leaf, ca, EOCSPENT_REVOKED, SDateTime(2026, 2, 1, 0, 0, 0, 0, true), SDateTime(),
            ECRLR_CESSATION_OF_OPERATION, SDateTime(2026, 1, 20, 0, 0, 0, 0, true)
        ) == ERET_OK
    );

    COctet out;
    REQUIRE(response.build(ca, out) == ERET_OK);

    CCrlRevokationInfo unused; // just to confirm ECrlReasons is still usable the same way here
    (void)unused;

    COcspResponse decoded;
    REQUIRE(decoded.decode(out) == ERET_OK);
    CHECK(decoded.check(leaf) == ERET_ALREADY);

    COcspEntry entry;
    REQUIRE(decoded.find(leaf, entry) == ERET_OK);
    CHECK(entry.status() == EOCSPENT_REVOKED);
    CHECK(entry.reason() == ECRLR_CESSATION_OF_OPERATION);
    CHECK(entry.revocationTime().day == 20);
}

TEST_CASE("COcspResponse: a non-OK status round-trips through build()/decode() with no further data") {
    COcspResponseBuilder response;
    response.status(EOCSP_UNAUTHORIZED);

    COctet out;
    REQUIRE(response.build(CCert(), out) == ERET_OK); // responder is ignored for a non-OK status
    REQUIRE_FALSE(out.empty());

    COcspResponse decoded;
    REQUIRE(decoded.decode(out) == ERET_OK);
    CHECK(decoded.status() == EOCSP_UNAUTHORIZED);
    CHECK(decoded.entries().empty());
}

TEST_CASE("COcspResponse: build() rejects a missing responder private key or producedAt") {
    COctet caSki;
    CCert ca = makeCa("Response Validation CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x52);

    // A CA copy with no private key attached.
    COctet caDer;
    REQUIRE(ca.exportDer(caDer) == ERET_OK);
    CCert caNoKey;
    REQUIRE(caNoKey.importDer(caDer) == ERET_OK);

    COcspResponseBuilder response;
    response.status(EOCSP_OK);
    response.producedAt(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(response.add(leaf, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 0, 0, 0, 0, true)) == ERET_OK);

    COctet out;
    CHECK(response.build(caNoKey, out) == ERET_KEY_EMPTY);

    COcspResponseBuilder noProducedAt;
    noProducedAt.status(EOCSP_OK);
    REQUIRE(noProducedAt.add(leaf, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 0, 0, 0, 0, true)) == ERET_OK);
    CHECK(noProducedAt.build(ca, out) == ERET_INVAL);
}

TEST_CASE("COcspResponse: add() on an already-listed certificate replaces, not duplicates") {
    COctet caSki;
    CCert ca = makeCa("Response Replace CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x53);

    COcspResponseBuilder response;
    REQUIRE(response.add(leaf, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 0, 0, 0, 0, true)) == ERET_OK);
    REQUIRE(response.entries().size() == 1);

    REQUIRE(
        response.add(
            leaf, ca, EOCSPENT_REVOKED, SDateTime(2026, 2, 2, 0, 0, 0, 0, true), SDateTime(), ECRLR_SUPERSEDED,
            SDateTime(2026, 2, 2, 0, 0, 0, 0, true)
        ) == ERET_OK
    );
    REQUIRE(response.entries().size() == 1);
    CHECK(response.entries()[0].status() == EOCSPENT_REVOKED);
}

TEST_CASE("COcspResponse: remove() removes an entry and reports not-found afterward") {
    COctet caSki;
    CCert ca = makeCa("Response Remove CA", caSki);
    CCert leafA = makeLeaf(ca, caSki, 0x54);
    CCert leafB = makeLeaf(ca, caSki, 0x55);

    COcspResponseBuilder response;
    REQUIRE(response.add(leafA, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 0, 0, 0, 0, true)) == ERET_OK);
    REQUIRE(response.add(leafB, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 0, 0, 0, 0, true)) == ERET_OK);

    REQUIRE(response.remove(leafA) == ERET_OK);
    CHECK(response.entries().size() == 1);
    CHECK(response.remove(leafA) == ERET_INVAL);

    response.status(EOCSP_OK);
    response.producedAt(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    COctet out;
    REQUIRE(response.build(ca, out) == ERET_OK);

    COcspResponse decoded;
    REQUIRE(decoded.decode(out) == ERET_OK);
    CHECK(decoded.check(leafA) == ERET_INVAL);
    CHECK(decoded.check(leafB) == ERET_OK);
}

TEST_CASE("COcspResponse: nonceBytes() echoed from a request round-trips through build()/decode()") {
    COctet caSki;
    CCert ca = makeCa("Response Nonce CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x56);

    COcspRequestBuilder requestBuilder;
    REQUIRE(requestBuilder.add(leaf, ca, EHASH_SHA256) == ERET_OK);
    REQUIRE(requestBuilder.generateNonce(20) == ERET_OK);

    COcspResponseBuilder response;
    response.status(EOCSP_OK);
    response.producedAt(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    response.nonceBytes(requestBuilder.nonceBytes());
    REQUIRE(response.add(leaf, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 0, 0, 0, 0, true)) == ERET_OK);

    COctet out;
    REQUIRE(response.build(ca, out) == ERET_OK);

    COcspResponse decoded;
    REQUIRE(decoded.decode(out) == ERET_OK);
    CHECK(decoded.nonceBytes().toSpan().sequencialEqual(requestBuilder.nonceBytes().toSpan()));
}

TEST_CASE("COcspResponse: an extension that is not the nonce is not read as one") {
    // --> The nonce is picked out of the response's singleResponse[0].extnScope by matching the
    // extension's OID against id-pkix-ocsp-nonce. Everything else stays exactly as the builder
    // produced it, and only the OID changes -- to id-pkix-ocsp-basic, the adjacent OID, so the
    // encoding's lengths are untouched.
    //
    // The comparison used to be `extnOid == COid(OID_NONCE)` with extnOid a CString, and
    // CString == COid is always true. Every extension on every response was therefore read as a
    // nonce, and a response carrying, say, a CRL reference would have had that CRL reference's
    // bytes handed back as the request's nonce -- which is a replay-protection check answering
    // with data it was never asked for. Nothing caught it because the only other test touching
    // this path builds a response whose sole extension is the nonce.
    COctet caSki;
    CCert ca = makeCa("Nonce Retarget CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x57);

    COcspResponseBuilder response;
    response.status(EOCSP_OK);
    response.producedAt(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    response.nonceBytes(COctet(reinterpret_cast<const uint8_t*>("a nonce this long"), 16));
    REQUIRE(response.add(leaf, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 0, 0, 0, 0, true)) == ERET_OK);

    COctet built;
    REQUIRE(response.build(ca, built) == ERET_OK);

    // --> The control: unmodified, the nonce is read back.
    COcspResponse asBuilt;
    REQUIRE(asBuilt.decode(built) == ERET_OK);
    REQUIRE(asBuilt.nonceBytes().size() == 16);

    COctet altered;
    REQUIRE(retargetOid(built, oidBytes(COid::OCSP_NONCE),
                        oidBytes(COid::OCSP_BASIC_RESPONSE), altered));

    COcspResponse decoded;
    REQUIRE(decoded.decode(altered) == ERET_OK);

    // --> The rest of the response still decodes -- an unrecognised extension is skipped, not a
    // rejection -- but there is no nonce, because the OID that named one is no longer there.
    CHECK(decoded.nonceBytes().empty());
    CHECK(decoded.entries().size() == 1);
}

TEST_CASE("COcspResponse/COcspRequest: Ed25519 responder signs and verifies a response") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    SKeyPair kp;
    REQUIRE(ed->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Ed25519 OCSP Responder")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CCert responder;
    REQUIRE(builder.build(responder) == ERET_OK);
    REQUIRE(responder.privateKey(kp.privateKey) == ERET_OK);

    COctet caSki;
    CCert ca = makeCa("Ed25519 Chain CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x60);

    COcspResponseBuilder response;
    response.status(EOCSP_OK);
    response.producedAt(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(response.add(leaf, ca, EOCSPENT_GOOD, SDateTime(2026, 2, 1, 0, 0, 0, 0, true)) == ERET_OK);

    COctet out;
    REQUIRE(response.build(responder, out) == ERET_OK);

    COcspResponse decoded;
    REQUIRE(decoded.decode(out) == ERET_OK);
    CHECK(decoded.verifySignature(responder) == ERET_OK);
    CHECK(decoded.check(leaf) == ERET_OK);
}
