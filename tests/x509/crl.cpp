#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <algorithm>
#include <vector>

using namespace certpp;
using namespace certpp::x509;
using namespace certpp::crypto;

namespace {

    /* Builds a self-signed P-256 CA certificate with its own private key attached, for use as a
     * CRL issuer across these tests. */
    CCert makeCa(const char* cn) {
        IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
        SKeyPair kp;
        REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

        CCertBuilder builder;
        CString dn("C=US, O=libcertpp CRL Test, CN=");
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

        CCert ca;
        REQUIRE(builder.build(ca) == ERET_OK);
        REQUIRE(ca.privateKey(kp.privateKey) == ERET_OK);
        return ca;
    }

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

    std::vector<uint8_t> reasonCodeOidBytes() {
        return oidBytes(COid::EXT_CRL_REASON_CODE);
    }

    std::vector<uint8_t> certificatePoliciesOidBytes() {
        return oidBytes(COid::EXT_CERTIFICATE_POLICIES);
    }

    /* Returns `der` with the first occurrence of `from` replaced by `to`. Requires equal
     * lengths, so the encoding around the OID stays well-formed -- which is what lets this test
     * change an OID without rebuilding the structure around it.
     *
     * Works through a CBuffer because COctet deliberately hands out its bytes as const (see
     * COctet::secureClear()'s own comment on why), and this is not the one use that earns a
     * mutable pointer on COctet itself. */
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

    /* Builds a self-signed P-256 leaf certificate with the given one-byte serial number -- only
     * its serialNumber() matters for CRL matching, so it needn't be signed by any particular
     * issuer. */
    CCert makeLeaf(uint8_t serialByte) {
        IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
        SKeyPair kp;
        REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

        CCertBuilder builder;
        REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp CRL Test, CN=Leaf")));
        builder.subject = builder.issuer;

        uint8_t serial[1] = { serialByte };
        builder.serialNumber = COctet(serial, 1);
        builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
        builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
        builder.subjectKey = kp.publicKey;
        builder.issuerKeyPair = kp;

        CCert leaf;
        REQUIRE(builder.build(leaf) == ERET_OK);
        return leaf;
    }

}

TEST_CASE("CCrlWriter: build() rejects a missing issuer private key") {
    IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
    SKeyPair kp;
    REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=No Key CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CCert caNoKey;
    REQUIRE(builder.build(caNoKey) == ERET_OK);
    // --> build() never attaches a private key -- caNoKey has none.

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    COctet out;
    CHECK(writer.build(caNoKey, out) == ERET_KEY_EMPTY);
    CHECK(out.empty());
}

TEST_CASE("CCrlWriter: build() rejects a missing thisUpdate") {
    CCert ca = makeCa("thisUpdate CA");

    CCrlWriter writer; // thisUpdate left unset
    COctet out;
    CHECK(writer.build(ca, out) == ERET_INVAL);
    CHECK(out.empty());
}

TEST_CASE("CCrlWriter: build() rejects an explicit issuer that doesn't match the issuer certificate's subject") {
    CCert ca = makeCa("Mismatch CA");

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    CDistinguishedName wrongIssuer;
    REQUIRE(CDistinguishedName::tryParse(wrongIssuer, CString("C=US, O=Somebody Else, CN=Not The CA")));
    writer.issuer(wrongIssuer);

    COctet out;
    CHECK(writer.build(ca, out) == ERET_INVAL);
    CHECK(out.empty());
}

TEST_CASE("CCrlWriter: build() an empty CRL (no revoked certificates) round-trips through CCrlReader") {
    CCert ca = makeCa("Empty CRL CA");

    CCrlWriter writer;
    SDateTime thisUpdate(2026, 2, 1, 0, 0, 0, 0, true);
    SDateTime nextUpdate(2026, 3, 1, 0, 0, 0, 0, true);
    writer.thisUpdate(thisUpdate);
    writer.nextUpdate(nextUpdate);

    COctet out;
    REQUIRE(writer.build(ca, out) == ERET_OK);
    REQUIRE_FALSE(out.empty());

    CCrlReader reader;
    REQUIRE(reader.decode(out) == ERET_OK);
    CHECK(reader.version() == 0); // --> v1: no entry needed crlEntryExtensions
    CHECK(reader.issuer() == ca.subject());
    CHECK(reader.thisUpdate().year == thisUpdate.year);
    CHECK(reader.thisUpdate().month == thisUpdate.month);
    CHECK(reader.thisUpdate().day == thisUpdate.day);
    CHECK(reader.nextUpdate().year == nextUpdate.year);
    CHECK(reader.revokations().empty());
}

TEST_CASE("CCrlWriter: add()/build() a CRL with one reason-less entry stays v1") {
    CCert ca = makeCa("V1 Entry CA");
    CCert leaf = makeLeaf(0x2A);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    SDateTime revokedAt(2026, 1, 15, 12, 0, 0, 0, true);
    REQUIRE(writer.add(leaf, revokedAt, ECRLR_NONE) == ERET_OK);
    REQUIRE(writer.revokations().size() == 1);

    COctet out;
    REQUIRE(writer.build(ca, out) == ERET_OK);

    CCrlReader reader;
    REQUIRE(reader.decode(out) == ERET_OK);
    CHECK(reader.version() == 0); // --> still v1: the one entry carries no crlEntryExtensions
    REQUIRE(reader.revokations().size() == 1);

    CCrlRevokationInfo found;
    REQUIRE(reader.find(leaf, found) == ERET_OK);
    CHECK(found.reason() == ECRLR_NONE);
    CHECK(found.timestamp().year == revokedAt.year);
    CHECK(found.timestamp().month == revokedAt.month);
    CHECK(found.timestamp().day == revokedAt.day);
    CHECK(found.timestamp().hour == revokedAt.hour);
}

TEST_CASE("CCrlWriter: a reason bumps the encoded version to v2, and decodes back correctly") {
    CCert ca = makeCa("V2 Entry CA");
    CCert leaf = makeLeaf(0x2B);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    SDateTime revokedAt(2026, 1, 20, 9, 30, 0, 0, true);
    REQUIRE(writer.add(leaf, revokedAt, ECRLR_KEY_COMPROMISE) == ERET_OK);

    COctet out;
    REQUIRE(writer.build(ca, out) == ERET_OK);
    CHECK(writer.version() == 1); // --> build() reflects the auto-bumped version back

    CCrlReader reader;
    REQUIRE(reader.decode(out) == ERET_OK);
    CHECK(reader.version() == 1);

    CCrlRevokationInfo found;
    REQUIRE(reader.find(leaf, found) == ERET_OK);
    CHECK(found.reason() == ECRLR_KEY_COMPROMISE);
}

TEST_CASE("CCrlWriter: every ECrlReasons value CCrlWriter::add() accepts round-trips through build()/decode()") {
    CCert ca = makeCa("All Reasons CA");

    struct { ECrlReasons reason; uint8_t serialByte; } cases[] = {
        { ECRLR_KEY_COMPROMISE, 0x10 },
        { ECRLR_CA_COMPROMISE, 0x11 },
        { ECRLR_AFFILIATION_CHANGED, 0x12 },
        { ECRLR_SUPERSEDED, 0x13 },
        { ECRLR_CESSATION_OF_OPERATION, 0x14 },
        { ECRLR_CERTIFICATE_HOLD, 0x15 },
        { ECRLR_PRIVILEGE_WITHDRAWN, 0x16 },
        { ECRLR_AA_COMPROMISE, 0x17 },
    };

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    TArray<CCert> leaves;
    for (const auto& c : cases) {
        CCert leaf = makeLeaf(c.serialByte);
        REQUIRE(writer.add(leaf, SDateTime(2026, 1, 10, 0, 0, 0, 0, true), c.reason) == ERET_OK);
        leaves.add(leaf);
    }

    COctet out;
    REQUIRE(writer.build(ca, out) == ERET_OK);

    CCrlReader reader;
    REQUIRE(reader.decode(out) == ERET_OK);
    REQUIRE(reader.revokations().size() == sizeof(cases) / sizeof(cases[0]));

    for (size_t i = 0; i < leaves.size(); ++i) {
        CAPTURE(i);
        CCrlRevokationInfo found;
        REQUIRE(reader.find(leaves[i], found) == ERET_OK);
        CHECK(found.reason() == cases[i].reason);
    }
}

TEST_CASE("CCrlWriter: add() on an already-listed certificate replaces, not duplicates") {
    CCert ca = makeCa("Replace CA");
    CCert leaf = makeLeaf(0x30);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    REQUIRE(writer.add(leaf, SDateTime(2026, 1, 1, 0, 0, 0, 0, true), ECRLR_SUPERSEDED) == ERET_OK);
    REQUIRE(writer.revokations().size() == 1);

    REQUIRE(writer.add(leaf, SDateTime(2026, 1, 5, 0, 0, 0, 0, true), ECRLR_KEY_COMPROMISE) == ERET_OK);
    REQUIRE(writer.revokations().size() == 1); // --> replaced, not appended

    CCrlRevokationInfo info;
    REQUIRE(writer.revokations()[0].isFor(leaf) == ERET_OK);
    CHECK(writer.revokations()[0].reason() == ECRLR_KEY_COMPROMISE);
    CHECK(writer.revokations()[0].timestamp().day == 5);
}

TEST_CASE("CCrlWriter: remove() removes a listed certificate and reports not-found afterward") {
    CCert ca = makeCa("Remove CA");
    CCert leafA = makeLeaf(0x40);
    CCert leafB = makeLeaf(0x41);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(writer.add(leafA, SDateTime(2026, 1, 1, 0, 0, 0, 0, true), ECRLR_NONE) == ERET_OK);
    REQUIRE(writer.add(leafB, SDateTime(2026, 1, 1, 0, 0, 0, 0, true), ECRLR_NONE) == ERET_OK);
    REQUIRE(writer.revokations().size() == 2);

    REQUIRE(writer.remove(leafA) == ERET_OK);
    REQUIRE(writer.revokations().size() == 1);
    CHECK(writer.revokations()[0].isFor(leafB) == ERET_OK);

    CHECK(writer.remove(leafA) == ERET_INVAL); // --> already gone
}

TEST_CASE("CCrlWriter: add() rejects an empty certificate or a zero revocation timestamp") {
    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    CCert empty;
    CHECK(writer.add(empty, SDateTime(2026, 1, 1, 0, 0, 0, 0, true), ECRLR_NONE) == ERET_INVAL);

    CCert leaf = makeLeaf(0x50);
    CHECK(writer.add(leaf, SDateTime(), ECRLR_NONE) == ERET_INVAL);
}

TEST_CASE("CCrlReader: check() and find() agree on revoked vs. non-revoked certificates") {
    CCert ca = makeCa("Check CA");
    CCert revoked = makeLeaf(0x60);
    CCert clean = makeLeaf(0x61);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(writer.add(revoked, SDateTime(2026, 1, 1, 0, 0, 0, 0, true), ECRLR_CERTIFICATE_HOLD) == ERET_OK);

    COctet out;
    REQUIRE(writer.build(ca, out) == ERET_OK);

    CCrlReader reader;
    REQUIRE(reader.decode(out) == ERET_OK);

    CHECK(reader.check(revoked) == ERET_ALREADY);
    CHECK(reader.check(clean) == ERET_OK);

    CCrlRevokationInfo info;
    CHECK(reader.find(revoked, info) == ERET_OK);
    CHECK(reader.find(clean, info) == ERET_INVAL);
}

TEST_CASE("CCrlRevokationInfo: isFor() distinguishes certificates by serial number") {
    CCert a = makeLeaf(0x70);
    CCert b = makeLeaf(0x71);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(writer.add(a, SDateTime(2026, 1, 1, 0, 0, 0, 0, true), ECRLR_NONE) == ERET_OK);

    const CCrlRevokationInfo& info = writer.revokations()[0];
    CHECK(info.isFor(a) == ERET_OK);
    CHECK(info.isFor(b) == ERET_INVAL);
    CHECK_FALSE(info.empty());
    CHECK_FALSE(info.serialNumber().empty());
    CHECK_FALSE(info.rawData().empty());
}

TEST_CASE("CCrlRevokationInfo: encode()/decode() round-trips independently of CCrlWriter") {
    CCert leaf = makeLeaf(0x80);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(writer.add(leaf, SDateTime(2026, 1, 1, 8, 0, 0, 0, true), ECRLR_AFFILIATION_CHANGED) == ERET_OK);

    COctet rawEntry;
    REQUIRE(writer.revokations()[0].encode(rawEntry) == ERET_OK);

    CCrlRevokationInfo decoded;
    REQUIRE(CCrlRevokationInfo::decode(rawEntry, decoded) == ERET_OK);
    CHECK(decoded.isFor(leaf) == ERET_OK);
    CHECK(decoded.reason() == ECRLR_AFFILIATION_CHANGED);
    CHECK(decoded.timestamp().hour == 8);
}

TEST_CASE("CCrlRevokationInfo: an entry extension that is not the reason code is not read as one") {
    // --> The reason is read out of a crlEntryExtensions entry by matching the extension's OID
    // against id-ce-cRLReasons. Everything else about the entry stays exactly as the writer
    // produced it -- same ENUMERATED payload, same structure, same lengths -- and only the OID
    // changes, to certificatePolicies. A decode that matched on anything but the OID would
    // still report keyCompromise.
    //
    // It did exactly that, silently. The comparison was `extnOid == COid(OID_REASON_CODE)` with
    // extnOid a CString, and CString == COid is always true, so *every* extension on *every* CRL
    // entry was read as a reason code. Nothing caught it because every other test in this file
    // either writes no entry extensions at all or writes the reason code -- the one extension
    // whose OID does match.
    CCert leaf = makeLeaf(0x81);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(writer.add(leaf, SDateTime(2026, 1, 1, 8, 0, 0, 0, true), ECRLR_KEY_COMPROMISE) == ERET_OK);

    COctet withReason;
    REQUIRE(writer.revokations()[0].encode(withReason) == ERET_OK);

    // --> The control: unmodified, the entry does report the reason.
    CCrlRevokationInfo asWritten;
    REQUIRE(CCrlRevokationInfo::decode(withReason, asWritten) == ERET_OK);
    REQUIRE(asWritten.reason() == ECRLR_KEY_COMPROMISE);

    COctet altered;
    REQUIRE(retargetOid(withReason, reasonCodeOidBytes(), certificatePoliciesOidBytes(), altered));

    CCrlRevokationInfo decoded;
    REQUIRE(CCrlRevokationInfo::decode(altered, decoded) == ERET_OK);

    // --> The entry still decodes -- an unrecognised extension is skipped, not a rejection --
    // but it carries no reason, because nothing in it says which.
    CHECK(decoded.reason() == ECRLR_NONE);
    CHECK(decoded.timestamp().hour == 8); // the rest of the entry is untouched
}

TEST_CASE("CCrlReader: decode() rejects empty or structurally malformed data") {
    CCrlReader reader;
    CHECK(reader.decode(COctet()) == ERET_INVAL);

    uint8_t garbage[] = { 0x01, 0x02, 0x03 };
    CHECK(reader.decode(COctet(garbage, sizeof(garbage))) == ERET_BADREQ);
}

TEST_CASE("CCrlReader/CCrlWriter: Ed25519 issuer signs and round-trips a CRL") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    SKeyPair kp;
    REQUIRE(ed->generateKeyPair(256, kp) == ERET_OK);

    CCertBuilder builder;
    REQUIRE(CDistinguishedName::tryParse(builder.issuer, CString("C=US, O=libcertpp, CN=Ed25519 CRL CA")));
    builder.subject = builder.issuer;
    uint8_t serial[1] = { 0x01 };
    builder.serialNumber = COctet(serial, 1);
    builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
    builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
    builder.subjectKey = kp.publicKey;
    builder.issuerKeyPair = kp;

    CCert ca;
    REQUIRE(builder.build(ca) == ERET_OK);
    REQUIRE(ca.privateKey(kp.privateKey) == ERET_OK);

    CCert leaf = makeLeaf(0x90);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));
    REQUIRE(writer.add(leaf, SDateTime(2026, 1, 1, 0, 0, 0, 0, true), ECRLR_SUPERSEDED) == ERET_OK);

    COctet out;
    REQUIRE(writer.build(ca, out) == ERET_OK);

    CCrlReader reader;
    REQUIRE(reader.decode(out) == ERET_OK);
    CHECK(reader.issuer() == ca.subject());
    CHECK(reader.check(leaf) == ERET_ALREADY);
}
