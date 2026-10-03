#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;
using namespace certpp::x509;

// CCertCollection, exercised against a real three-level hierarchy built here rather than against
// hand-written fixtures: the point of the class is the issuer linkage, and only genuinely issued
// certificates have linkage to find.
//
// The helpers below are the same shape as tests/x509/verify.cpp's, which is deliberate -- that
// file already establishes that this is how a certificate gets issued in a test.

namespace {

    /* Issues a certificate for subjectKey, signed by issuerKeyPair. Passing the same key pair as
     * both makes it self-signed. */
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

    SKeyPair generate() {
        IAsymmetricPtr algo = IAsymmetric::builtIn(EASYM_P256);
        SKeyPair kp;

        for (int attempt = 0; attempt < 8 && algo; ++attempt) {
            if (algo->generateKeyPair(SKeySize(256), kp) == ERET_OK) {
                break;
            }
        }

        return kp;
    }

    /* A root, an intermediate under it, and a leaf under that -- plus the key pairs, since a
     * test that wants to check key pairing needs them. */
    struct SHierarchy {
        SKeyPair rootKey, interKey, leafKey;
        CCert root, inter, leaf;

        bool build() {
            rootKey = generate();
            interKey = generate();
            leafKey = generate();

            if (!rootKey.publicKey || !interKey.publicKey || !leafKey.publicKey) {
                return false;
            }

            return issue(root, CString("CN=Root"), CString("CN=Root"),
                         rootKey.publicKey, rootKey, 0x01)
                && issue(inter, CString("CN=Intermediate"), CString("CN=Root"),
                         interKey.publicKey, rootKey, 0x02)
                && issue(leaf, CString("CN=Leaf"), CString("CN=Intermediate"),
                         leafKey.publicKey, interKey, 0x03);
        }
    };

    CDistinguishedName dn(const char* text) {
        CDistinguishedName out;
        REQUIRE(CDistinguishedName::tryParse(out, CString(text)));
        return out;
    }

} // namespace

TEST_CASE("CCertCollection: add, count, at, remove") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    CHECK(col.empty());
    CHECK(col.count() == 0);

    size_t leafIdx = 0, interIdx = 0, rootIdx = 0;
    REQUIRE(col.add(h.leaf, h.leafKey.privateKey, leafIdx) == ERET_OK);
    REQUIRE(col.add(h.inter, interIdx) == ERET_OK);
    REQUIRE(col.add(h.root, rootIdx) == ERET_OK);

    CHECK(col.count() == 3);
    CHECK_FALSE(col.empty());
    CHECK(leafIdx == 0);
    CHECK(rootIdx == 2);

    SCertEntry entry;
    REQUIRE(col.at(leafIdx, entry) == ERET_OK);
    CHECK(entry.hasPrivateKey());
    REQUIRE(col.at(rootIdx, entry) == ERET_OK);
    CHECK_FALSE(entry.hasPrivateKey());

    // Out of range is rejected rather than returning a default-constructed entry, which would
    // read as "an empty certificate is here".
    CHECK(col.at(3, entry) == ERET_BADREQ);
    CHECK(col.at(size_t(-1), entry) == ERET_BADREQ);

    // An empty certificate is not an entry.
    size_t unused = 0;
    CHECK(col.add(CCert(), unused) == ERET_BADREQ);
    CHECK(col.count() == 3);

    REQUIRE(col.removeAt(1) == ERET_OK);
    CHECK(col.count() == 2);
    CHECK(col.removeAt(2) == ERET_BADREQ);

    col.clear();
    CHECK(col.empty());
}

TEST_CASE("CCertCollection: lookups") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    size_t idx = 0;
    REQUIRE(col.add(h.leaf, idx) == ERET_OK);
    REQUIRE(col.add(h.inter, idx) == ERET_OK);
    REQUIRE(col.add(h.root, idx) == ERET_OK);

    CHECK(col.findBySubject(dn("CN=Leaf")) == 0);
    CHECK(col.findBySubject(dn("CN=Intermediate")) == 1);
    CHECK(col.findBySubject(dn("CN=Root")) == 2);
    CHECK(col.findBySubject(dn("CN=Absent")) == CCertCollection::NOT_FOUND);

    // Issuer + serial is the identifier X.509 treats as unique.
    uint8_t three[1] = { 0x03 };
    CHECK(col.findByIssuerAndSerial(dn("CN=Intermediate"),
                                    SReadOnlyByteSpan(three, 1)) == 0);
    uint8_t nine[1] = { 0x09 };
    CHECK(col.findByIssuerAndSerial(dn("CN=Intermediate"),
                                    SReadOnlyByteSpan(nine, 1))
          == CCertCollection::NOT_FOUND);

    // PKCS#9 attributes, which is what a PFX pairs its bags with.
    REQUIRE(col.setFriendlyName(0, CString("my leaf")) == ERET_OK);
    CHECK(col.findByFriendlyName(CString("my leaf")) == 0);
    CHECK(col.findByFriendlyName(CString("other")) == CCertCollection::NOT_FOUND);

    // An empty name never matches, rather than matching every entry that has none.
    CHECK(col.findByFriendlyName(CString("")) == CCertCollection::NOT_FOUND);

    uint8_t keyId[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    REQUIRE(col.setLocalKeyId(0, SReadOnlyByteSpan(keyId, sizeof(keyId))) == ERET_OK);
    CHECK(col.findByLocalKeyId(SReadOnlyByteSpan(keyId, sizeof(keyId))) == 0);

    // Same rule for an absent identifier: entries 1 and 2 have no localKeyId, and an empty
    // needle must not find them.
    CHECK(col.findByLocalKeyId(SReadOnlyByteSpan(nullptr, 0))
          == CCertCollection::NOT_FOUND);

    uint8_t otherId[4] = { 0x00, 0x11, 0x22, 0x33 };
    CHECK(col.findByLocalKeyId(SReadOnlyByteSpan(otherId, sizeof(otherId)))
          == CCertCollection::NOT_FOUND);
}

TEST_CASE("CCertCollection: isSelfIssued and findIssuerOf") {
    SHierarchy h;
    REQUIRE(h.build());

    CHECK(CCertCollection::isSelfIssued(h.root));
    CHECK_FALSE(CCertCollection::isSelfIssued(h.inter));
    CHECK_FALSE(CCertCollection::isSelfIssued(h.leaf));
    CHECK_FALSE(CCertCollection::isSelfIssued(CCert()));

    CCertCollection col;
    size_t idx = 0;
    REQUIRE(col.add(h.leaf, idx) == ERET_OK);
    REQUIRE(col.add(h.inter, idx) == ERET_OK);
    REQUIRE(col.add(h.root, idx) == ERET_OK);

    CHECK(col.findIssuerOf(h.leaf) == 1);
    CHECK(col.findIssuerOf(h.inter) == 2);

    // A root is deliberately not reported as its own issuer: that would make every root a
    // one-element cycle instead of the end of a chain.
    CHECK(col.findIssuerOf(h.root) == CCertCollection::NOT_FOUND);

    TArray<size_t> roots;
    CHECK(col.collectSelfIssued(roots) == 1);
    CHECK(roots[0] == 2);
}

TEST_CASE("CCertCollection: buildChain orders leaf to root") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    size_t idx = 0;
    // Added deliberately out of order, so a pass that merely echoed insertion order would fail.
    REQUIRE(col.add(h.root, idx) == ERET_OK);
    REQUIRE(col.add(h.leaf, idx) == ERET_OK);
    REQUIRE(col.add(h.inter, idx) == ERET_OK);

    TArray<size_t> chain;
    REQUIRE(col.buildChain(1, chain) == ECHAINRES_OK);
    REQUIRE(chain.size() == 3);
    CHECK(chain[0] == 1);   // leaf
    CHECK(chain[1] == 2);   // intermediate
    CHECK(chain[2] == 0);   // root

    // Every link's signature holds, which is the other half of the chain being real.
    CHECK(col.verifyLinks(chain) == ERET_OK);

    // Starting from the root is a one-element chain, not an error.
    TArray<size_t> rootOnly;
    CHECK(col.buildChain(0, rootOnly) == ECHAINRES_OK);
    CHECK(rootOnly.size() == 1);

    CHECK(col.buildChain(99, chain) == ECHAINRES_NOT_FOUND);
}

TEST_CASE("CCertCollection: an incomplete chain reports PARTIAL and keeps what it found") {
    SHierarchy h;
    REQUIRE(h.build());

    // The root is missing, so the walk runs out above the intermediate.
    CCertCollection col;
    size_t idx = 0;
    REQUIRE(col.add(h.leaf, idx) == ERET_OK);
    REQUIRE(col.add(h.inter, idx) == ERET_OK);

    TArray<size_t> chain;
    CHECK(col.buildChain(0, chain) == ECHAINRES_PARTIAL);

    // The partial chain is kept rather than discarded -- it is what the caller needs in order
    // to go and fetch the missing issuer.
    REQUIRE(chain.size() == 2);
    CHECK(chain[0] == 0);
    CHECK(chain[1] == 1);

    // verifyLinks() still holds over the part that is present, and does not try to verify the
    // top certificate against itself, since it is not self-issued.
    CHECK(col.verifyLinks(chain) == ERET_OK);
}

TEST_CASE("CCertCollection: buildChainFor starts from a certificate not in the collection") {
    SHierarchy h;
    REQUIRE(h.build());

    // The CA certificates are held; the leaf arrived separately, which is the ordinary case.
    CCertCollection col;
    size_t idx = 0;
    REQUIRE(col.add(h.inter, idx) == ERET_OK);
    REQUIRE(col.add(h.root, idx) == ERET_OK);

    TArray<size_t> above;
    REQUIRE(col.buildChainFor(h.leaf, above) == ECHAINRES_OK);
    REQUIRE(above.size() == 2);
    CHECK(above[0] == 0);   // intermediate
    CHECK(above[1] == 1);   // root

    // A self-issued leaf has nothing above it; that is a success with an empty result, not a
    // failure.
    TArray<size_t> none;
    CHECK(col.buildChainFor(h.root, none) == ECHAINRES_OK);
    CHECK(none.size() == 0);

    CHECK(col.buildChainFor(CCert(), none) == ECHAINRES_PARTIAL);
}

TEST_CASE("CCertCollection: verifyLinks rejects a chain whose links do not actually sign") {
    SHierarchy a;
    SHierarchy b;
    REQUIRE(a.build());
    REQUIRE(b.build());

    // a.leaf and b.root have no relationship at all. Assembling them by hand and asking
    // verifyLinks() must fail -- otherwise every other "verifies" result in this file is
    // vacuous.
    CCertCollection col;
    size_t idx = 0;
    REQUIRE(col.add(a.leaf, idx) == ERET_OK);
    REQUIRE(col.add(b.root, idx) == ERET_OK);

    TArray<size_t> forged;
    forged.add(size_t(0));
    forged.add(size_t(1));

    CHECK(col.verifyLinks(forged) != ERET_OK);

    // An empty chain and an out-of-range index are both rejected.
    TArray<size_t> emptyChain;
    CHECK(col.verifyLinks(emptyChain) == ERET_BADREQ);

    TArray<size_t> bogus;
    bogus.add(size_t(42));
    CHECK(col.verifyLinks(bogus) == ERET_BADREQ);
}

TEST_CASE("CCertCollection: checkKeyPairing accepts the right key and rejects a wrong one") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    size_t correct = 0, wrong = 0, none = 0;

    // The leaf with its own key.
    REQUIRE(col.add(h.leaf, h.leafKey.privateKey, correct) == ERET_OK);

    // The leaf with the *intermediate's* key -- structurally fine, cryptographically unrelated.
    // This is exactly the mistake a container format makes when it pairs bags by position
    // instead of by localKeyId, and it fails on first use with a confusing symptom unless
    // something checks.
    REQUIRE(col.add(h.leaf, h.interKey.privateKey, wrong) == ERET_OK);

    // And one with no key at all.
    REQUIRE(col.add(h.root, none) == ERET_OK);

    CHECK(col.checkKeyPairing(correct) == ERET_OK);
    CHECK(col.checkKeyPairing(wrong) == ERET_KEY_ERROR);
    CHECK(col.checkKeyPairing(none) == ERET_KEY_EMPTY);
    CHECK(col.checkKeyPairing(99) == ERET_BADREQ);
}

TEST_CASE("CCertCollection: a cycle is reported as a cycle, not as too deep") {
    // Two certificates that name each other as issuer. This cannot arise from honest issuance,
    // but a collection is caller-supplied data, so the walk has to terminate on it -- and
    // saying CYCLE tells the caller something true about their input, where TOO_DEEP would only
    // say the walk gave up.
    SKeyPair keyA = generate();
    SKeyPair keyB = generate();
    REQUIRE(keyA.publicKey);
    REQUIRE(keyB.publicKey);

    CCert aCert, bCert;
    REQUIRE(issue(aCert, CString("CN=A"), CString("CN=B"), keyA.publicKey, keyB, 0x01));
    REQUIRE(issue(bCert, CString("CN=B"), CString("CN=A"), keyB.publicKey, keyA, 0x02));

    CCertCollection col;
    size_t idx = 0;
    REQUIRE(col.add(aCert, idx) == ERET_OK);
    REQUIRE(col.add(bCert, idx) == ERET_OK);

    TArray<size_t> chain;
    CHECK(col.buildChain(0, chain) == ECHAINRES_CYCLE);

    // The walk stopped at the repeat rather than running to MAX_DEPTH.
    CHECK(chain.size() == 2);
}

TEST_CASE("EChainFormats and IChainFormat::detect distinguish PEM from DER") {
    const char* pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    CHECK(IChainFormat::detect(SReadOnlyByteSpan(
        reinterpret_cast<const uint8_t*>(pem), std::strlen(pem))) == ECHAINFMT_PEM);

    // A PFX is DER, so it opens with a SEQUENCE tag.
    uint8_t der[4] = { 0x30, 0x82, 0x0A, 0x00 };
    CHECK(IChainFormat::detect(SReadOnlyByteSpan(der, sizeof(der))) == ECHAINFMT_PFX);

    // Neither, and nothing at all.
    uint8_t junk[4] = { 0x00, 0x01, 0x02, 0x03 };
    CHECK(IChainFormat::detect(SReadOnlyByteSpan(junk, sizeof(junk))) == ECHAINFMT_UNKNOWN);
    CHECK(IChainFormat::detect(SReadOnlyByteSpan(nullptr, 0)) == ECHAINFMT_UNKNOWN);
}
