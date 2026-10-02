#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <fstream>
#include <vector>

using namespace certpp;
using namespace certpp::asn1;
using namespace certpp::x509;
using namespace certpp::crypto;

/* Adversarial / negative-input tests for the x509 parsing boundary.
 *
 * Every other test under tests/x509/ is a build-then-reparse round trip against this library's
 * own CCertBuilder/CCrlWriter/COcspResponseBuilder output, or a real certificate from a public
 * CA -- in other words, every one of them feeds the parser bytes some conforming encoder
 * produced. Nothing exercised what happens when the bytes are hostile. These tests start from a
 * known-good document and corrupt exactly one thing in it, naming the clause that forbids the
 * result.
 *
 * A TEST_CASE whose name starts with "known gap" documents input this library currently accepts
 * but the relevant RFC/ASN.1 definition forbids. Its assertions state the *correct* behavior and
 * use WARN rather than CHECK, so the suite stays green while reporting the gap on every run. Do
 * not downgrade those assertions to match the current behavior -- if one starts passing, the
 * library was fixed and the WARN should become a CHECK.
 */

namespace {

    // CERTPP_TEST_DIR is injected by CMakeLists.txt: the absolute path of this .cpp's directory.
    constexpr const char* GITHUB_CERT_PATH = CERTPP_TEST_DIR "/certs/implemented/github.com.der";
    constexpr const char* AMAZON_CERT_PATH = CERTPP_TEST_DIR "/certs/implemented/amazon.com.der";

    /* Reads an entire file into a byte vector, so a test can corrupt it in place. */
    bool readDerFile(const char* path, std::vector<uint8_t>& out) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            return false;
        }

        const std::streamsize size = file.tellg();
        if (size <= 0) {
            return false;
        }

        file.seekg(0, std::ios::beg);
        out.resize(static_cast<size_t>(size));
        return bool(file.read(reinterpret_cast<char*>(out.data()), size));
    }

    /* Runs CCert::importDer() over raw bytes. */
    ERetCode importCert(const std::vector<uint8_t>& bytes, CCert& out) {
        return out.importDer(COctet(bytes.data(), bytes.size()));
    }

    ERetCode importCert(const std::vector<uint8_t>& bytes) {
        CCert cert;
        return importCert(bytes, cert);
    }

    /* One member of a constructed value: its tag, its content octets, and its complete
     * header-included byte range, which is what gets spliced when a document is rebuilt. */
    struct Tlv {
        CTag tag;
        SReadOnlyByteSpan whole;
        SReadOnlyByteSpan content;
    };

    /* Splits a constructed value's content octets into its member TLVs. */
    bool splitElements(SReadOnlyByteSpan content, std::vector<Tlv>& out) {
        out.clear();
        SReadOnlyByteSpan cursor = content;

        while (!cursor.empty()) {
            const uint8_t* start = cursor.data;

            // --> Measured as a size difference, not a pointer difference: TSpan::slice() hands
            // back a null data pointer once the cursor is exhausted, so after the final element
            // `cursor.data - start` is meaningless.
            const size_t before = cursor.size;

            Tlv tlv;
            if (!CDecoder::readNextElement(cursor, EAENC_DER, tlv.tag, tlv.content)) {
                return false;
            }

            tlv.whole = SReadOnlyByteSpan(start, before - cursor.size);
            out.push_back(tlv);
        }

        return true;
    }

    /* Splits a DER document's outer SEQUENCE into its members. */
    bool splitDocument(SReadOnlyByteSpan der, std::vector<Tlv>& out) {
        CTag tag;
        SReadOnlyByteSpan content;
        size_t bytesRead = 0;

        if (!CDecoder::readEncodedValue(der, EAENC_DER, tag, content, bytesRead)) {
            return false;
        }

        return splitElements(content, out);
    }

    /* The byte offset of part's first octet within the document doc -- both are views over the
     * same buffer, so a test can turn a located field back into an index to corrupt. */
    size_t offsetIn(const std::vector<uint8_t>& doc, SReadOnlyByteSpan part) {
        return size_t(part.data - doc.data());
    }

    /* Index of the first (last=false) or last (last=true) member of elements that is a universal
     * SEQUENCE. In a TBSCertificate the first such member is the inner `signature`
     * AlgorithmIdentifier and the last is subjectPublicKeyInfo, which is how these tests locate
     * both without hard-coding element positions that the OPTIONAL version field shifts around. */
    bool sequenceIndex(const std::vector<Tlv>& elements, bool last, size_t& outIndex) {
        bool found = false;

        for (size_t i = 0; i < elements.size(); ++i) {
            if (elements[i].tag.tagClass() != EATAG_UNIVERSAL) {
                continue;
            }

            if (elements[i].tag.value() != uint32_t(EAUTAG_SEQ) || !elements[i].tag.isConstructed()) {
                continue;
            }

            if (!found || last) {
                outIndex = i;
                found = true;
            }

            if (found && !last) {
                break;
            }
        }

        return found;
    }

    /* Locates TBSCertificate's [3] EXPLICIT extensions wrapper inside a certificate. */
    bool findExtensionsWrapper(SReadOnlyByteSpan der, Tlv& outWrapper) {
        std::vector<Tlv> certElements;
        if (!splitDocument(der, certElements) || certElements.empty()) {
            return false;
        }

        std::vector<Tlv> tbsElements;
        if (!splitElements(certElements[0].content, tbsElements)) {
            return false;
        }

        for (const Tlv& e : tbsElements) {
            if (e.tag.tagClass() == EATAG_CONTEXT_SPECIFIC && e.tag.value() == 3) {
                outWrapper = e;
                return true;
            }
        }

        return false;
    }

    /* Rebuilds a certificate with TBSCertificate's [3] extensions wrapper replaced by
     * `replacement` (one complete TLV), recomputing every enclosing length. Plain byte surgery
     * can't be used here: changing a nested value's size invalidates the length octets of every
     * SEQUENCE above it. */
    bool rebuildWithExtensionsWrapper(
        SReadOnlyByteSpan der,
        SReadOnlyByteSpan replacement,
        std::vector<uint8_t>& out
    ) {
        std::vector<Tlv> certElements;
        if (!splitDocument(der, certElements) || certElements.size() != 3) {
            return false;
        }

        std::vector<Tlv> tbsElements;
        if (!splitElements(certElements[0].content, tbsElements)) {
            return false;
        }

        CBuffer tbsContent;
        bool replaced = false;

        for (const Tlv& e : tbsElements) {
            const bool isWrapper = e.tag.tagClass() == EATAG_CONTEXT_SPECIFIC && e.tag.value() == 3;
            const SReadOnlyByteSpan bytes = isWrapper ? replacement : e.whole;

            if (isWrapper) {
                replaced = true;
            }

            if (!CDer::appendRaw(tbsContent, bytes)) {
                return false;
            }
        }

        if (!replaced) {
            return false;
        }

        CBuffer certContent;
        if (!CDer::appendTlv(certContent, CTag::SEQ, tbsContent.toSpan())
            || !CDer::appendRaw(certContent, certElements[1].whole)
            || !CDer::appendRaw(certContent, certElements[2].whole)) {
            return false;
        }

        CBuffer document;
        if (!CDer::appendTlv(document, CTag::SEQ, certContent.toSpan())) {
            return false;
        }

        out.assign(document.toPtr(), document.toPtr() + document.size());
        return true;
    }

    /* Builds a self-signed P-256 CA with its private key attached, a SubjectKeyIdentifier and
     * BasicConstraints -- the issuer/responder the CRL and OCSP cases below need. */
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
        CString dn("C=US, O=libcertpp Malformed Test, CN=");
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

    /* Builds a self-signed P-256 leaf naming ca as its issuer and carrying an
     * AuthorityKeyIdentifier pointing at caSki, which is what COcspCertId::make() needs. */
    CCert makeLeaf(const CCert& ca, const COctet& caSki, uint8_t serialByte) {
        IAsymmetricPtr ec = IAsymmetric::builtIn(EASYM_P256);
        SKeyPair kp;
        REQUIRE(ec->generateKeyPair(256, kp) == ERET_OK);

        CCertBuilder builder;
        builder.issuer = ca.subject();
        REQUIRE(CDistinguishedName::tryParse(builder.subject, CString("C=US, O=libcertpp Malformed Test, CN=Leaf")));

        uint8_t serial[1] = { serialByte };
        builder.serialNumber = COctet(serial, 1);
        builder.notBefore = SDateTime(2026, 1, 1, 0, 0, 0, 0, true);
        builder.notAfter = SDateTime(2036, 1, 1, 0, 0, 0, 0, true);
        builder.subjectKey = kp.publicKey;
        builder.issuerKeyPair = kp;

        CAkiExtensionBuilder aki;
        aki.setKeyIdentifier(caSki);
        builder.extensions.add(aki.build());

        CCert leaf;
        REQUIRE(builder.build(leaf) == ERET_OK);
        return leaf;
    }

    /* True if the certificate still carries the two extensions github.com.der is known to have
     * (see tests/x509/realcerts.cpp, cross-checked against openssl). CCert exposes no extension
     * list, only per-OID lookup, so this stands in for "the extensions survived the import" --
     * a corruption that makes it go false has silently dropped security-relevant constraints
     * rather than failing. */
    bool keepsKnownExtensions(const CCert& cert) {
        return bool(cert.extension<CSanExtension>()) && bool(cert.extension<CEkuExtension>());
    }

    /* Returns bytes with `extra` appended -- the trailing-garbage corruption. */
    std::vector<uint8_t> withTrailing(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& extra) {
        std::vector<uint8_t> result = bytes;
        result.insert(result.end(), extra.begin(), extra.end());
        return result;
    }

}

// --------------------------------------------------------------------------------------------
// Gates that ARE enforced. These use ordinary CHECK/REQUIRE.
// --------------------------------------------------------------------------------------------

TEST_CASE("CCert::importDer rejects a truncated certificate") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));
    REQUIRE(importCert(der) == ERET_OK);

    SUBCASE("cut in half") {
        der.resize(der.size() / 2);
        CHECK(importCert(der) != ERET_OK);
    }

    SUBCASE("one byte short") {
        der.pop_back();
        CHECK(importCert(der) != ERET_OK);
    }

    SUBCASE("header only") {
        der.resize(4);
        CHECK(importCert(der) != ERET_OK);
    }
}

/* X.690 8.9.1: a SEQUENCE is always constructed, so the primitive form of the tag is not a
 * SEQUENCE at all and must not be read as one. */
TEST_CASE("CCert::importDer rejects a primitive outer SEQUENCE tag") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));
    REQUIRE(der[0] == 0x30);

    der[0] = 0x10; // --> universal tag 16, primitive
    CHECK(importCert(der) != ERET_OK);
}

/* X.690 10.1: DER requires the minimum number of length octets, so the outer SEQUENCE's length
 * may not be padded. A parser that tolerates this gives every certificate many encodings, which
 * breaks any cache, allowlist or revocation record keyed on the certificate's bytes. */
TEST_CASE("CCert::importDer rejects a non-minimal length on the outer SEQUENCE") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));
    REQUIRE(der[0] == 0x30);
    REQUIRE(der[1] == 0x82); // two length octets -- the real, minimal encoding

    // Re-emit the same length in three octets instead of two, padding with a leading 0x00.
    std::vector<uint8_t> padded;
    padded.push_back(0x30);
    padded.push_back(0x83);
    padded.push_back(0x00);
    padded.push_back(der[2]);
    padded.push_back(der[3]);
    padded.insert(padded.end(), der.begin() + 4, der.end());

    CHECK(importCert(padded) != ERET_OK);
}

/* X.690 10.1: DER has no indefinite-length form. BER's EOC-terminated encoding of the very same
 * certificate must still be refused when the document is declared to be DER. */
TEST_CASE("CCert::importDer rejects an indefinite-length outer SEQUENCE") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));
    REQUIRE(der[0] == 0x30);
    REQUIRE(der[1] == 0x82);

    std::vector<uint8_t> indefinite;
    indefinite.push_back(0x30);
    indefinite.push_back(0x80); // indefinite length
    indefinite.insert(indefinite.end(), der.begin() + 4, der.end());
    indefinite.push_back(0x00); // end-of-contents
    indefinite.push_back(0x00);

    CHECK(importCert(indefinite) != ERET_OK);
}

/* A SubjectPublicKeyInfo is always byte-aligned, so its BIT STRING's unused-bit count is 0; a
 * non-zero count would silently shorten the key. This one the parser does check -- it is the
 * direct counterpart of the signatureValue gap recorded further down, which makes the omission
 * there look like an oversight rather than a decision. */
TEST_CASE("CCert::importDer rejects a SubjectPublicKeyInfo BIT STRING with a non-zero unused-bit count") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));
    REQUIRE(importCert(der) == ERET_OK);

    std::vector<Tlv> certElements;
    REQUIRE(splitDocument(SReadOnlyByteSpan(der.data(), der.size()), certElements));
    REQUIRE(certElements.size() == 3);

    std::vector<Tlv> tbsElements;
    REQUIRE(splitElements(certElements[0].content, tbsElements));

    size_t spkiIndex = 0;
    REQUIRE(sequenceIndex(tbsElements, true, spkiIndex)); // last SEQUENCE in TBS = SPKI

    std::vector<Tlv> spkiElements;
    REQUIRE(splitElements(tbsElements[spkiIndex].content, spkiElements));
    REQUIRE(spkiElements.size() == 2);
    REQUIRE(spkiElements[1].tag.value() == uint32_t(EAUTAG_STRING_BIT));
    REQUIRE(spkiElements[1].content.size > 1);

    const size_t unusedBitsAt = offsetIn(der, spkiElements[1].content);
    REQUIRE(der[unusedBitsAt] == 0x00);

    // --> Claim one unused bit and zero it in the final octet, so the BIT STRING itself stays a
    // legal DER encoding (X.690 11.2.1) and only the x509-level "must be 0" rule is violated.
    der[unusedBitsAt] = 0x01;
    der[unusedBitsAt + spkiElements[1].content.size - 1] &= 0xFE;

    CHECK(importCert(der) != ERET_OK);
}

TEST_CASE("CBasicConstraintsExtension tolerates the all-default and oversized encodings") {
    SUBCASE("an empty SEQUENCE is the legal all-default encoding, meaning cA=FALSE") {
        const uint8_t value[] = { 0x30, 0x00 };
        CBasicConstraintsExtension bc(COctet(value, sizeof(value)));

        CHECK_FALSE(bc.isCa());
        CHECK_FALSE(bc.hasPathLenConstraint());
    }

    SUBCASE("a pathLenConstraint too wide for an int64_t is dropped, not misread") {
        // 9 content octets exceeds what CDecoder::decodeInteger will decode, so the field is
        // simply not reported -- a conservative outcome, worth pinning so it stays conservative.
        const uint8_t value[] = {
            0x30, 0x0E,
            0x01, 0x01, 0xFF,                                                   // cA TRUE
            0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF    // pathLen 2^64-1
        };
        CBasicConstraintsExtension bc(COctet(value, sizeof(value)));

        CHECK(bc.isCa());
        CHECK_FALSE(bc.hasPathLenConstraint());
    }
}

// --------------------------------------------------------------------------------------------
// Known gaps. Assertions state the correct behavior and use WARN; see the file header.
// --------------------------------------------------------------------------------------------

/* RFC 5280 4.1: a Certificate *is* the outer SEQUENCE, so there is nothing after it. The
 * decoder's readEncodedValue() reports how many bytes it consumed, but CCert::importDer never
 * compares that against the input length (no atEnd() check on the outermost CReader), so any
 * suffix is silently ignored.
 *
 * Currently: ERET_OK, with the appended bytes discarded. Required: rejected.
 *
 * This is the same class of bug as the already-fixed CDer::readOuterSequence one, and it is the
 * most exploitable item in this file: two different byte strings import as the same certificate,
 * so anything that identifies a certificate by its DER -- a pin, an allowlist, a revocation
 * record, a dedupe cache -- can be bypassed by appending a byte. */
TEST_CASE("CCert::importDer(): rejects trailing bytes after the outer SEQUENCE") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));
    REQUIRE(importCert(der) == ERET_OK);

    SUBCASE("a single trailing zero byte") {
        CHECK(importCert(withTrailing(der, { 0x00 })) != ERET_OK);
    }

    SUBCASE("trailing non-zero garbage") {
        CHECK(importCert(withTrailing(der, { 0xDE, 0xAD, 0xBE, 0xEF })) != ERET_OK);
    }

    SUBCASE("a whole second, well-formed TLV appended") {
        CHECK(importCert(withTrailing(der, { 0x02, 0x01, 0x2A })) != ERET_OK);
    }

    SUBCASE("a whole second certificate appended") {
        std::vector<uint8_t> other;
        REQUIRE(readDerFile(AMAZON_CERT_PATH, other));
        CHECK(importCert(withTrailing(der, other)) != ERET_OK);
    }

    SUBCASE("rejection is what keeps thumbprint() and exportDer() honest") {
        // --> Why the rejection above matters rather than being pedantry. importDer() stores its
        // input verbatim as _rawData, and thumbprint(), equals() and exportDer() all read from
        // that -- so had a suffix been accepted, one certificate would have had unlimited
        // distinct fingerprints (sidestepping anything keyed on thumbprint(): a blocklist, a
        // revocation record, a dedupe cache) and exportDer() would have replayed the non-DER
        // suffix to whatever peer it serialized to.
        CCert original;
        REQUIRE(importCert(der, original) == ERET_OK);

        CCert suffixed;
        REQUIRE(importCert(withTrailing(der, { 0x00 }), suffixed) != ERET_OK);
        CHECK(suffixed.empty());

        COctet exported;
        REQUIRE(original.exportDer(exported) == ERET_OK);
        CHECK(exported.size() == der.size());
    }
}

/* RFC 5280 5.1: a CertificateList is the outer SEQUENCE and nothing more. Same missing
 * atEnd() check as the certificate path. Currently: ERET_OK. Required: rejected. */
TEST_CASE("CCrlReader::decode(): rejects trailing bytes after the outer SEQUENCE") {
    COctet caSki;
    CCert ca = makeCa("CRL Trailing CA", caSki);

    CCrlWriter writer;
    writer.thisUpdate(SDateTime(2026, 2, 1, 0, 0, 0, 0, true));

    COctet crl;
    REQUIRE(writer.build(ca, crl) == ERET_OK);

    std::vector<uint8_t> bytes(crl.toPtr(), crl.toPtr() + crl.size());

    CCrlReader clean;
    REQUIRE(clean.decode(COctet(bytes.data(), bytes.size())) == ERET_OK);

    const std::vector<uint8_t> suffixed = withTrailing(bytes, { 0xDE, 0xAD, 0xBE, 0xEF });
    CCrlReader reader;
    CHECK(reader.decode(COctet(suffixed.data(), suffixed.size())) != ERET_OK);
}

/* RFC 6960 4.2.1: an OCSPResponse is the outer SEQUENCE and nothing more. Same missing
 * atEnd() check. Currently: ERET_OK. Required: rejected.
 *
 * Worth noting separately from the certificate case because an OCSP response arrives straight
 * off the wire from a URL named in the certificate being validated -- it is the least
 * authenticated input any of these parsers handle. */
TEST_CASE("COcspResponse::decode(): rejects trailing bytes after the outer SEQUENCE") {
    COctet caSki;
    CCert ca = makeCa("OCSP Trailing CA", caSki);
    CCert leaf = makeLeaf(ca, caSki, 0x60);

    COcspResponseBuilder response;
    response.status(EOCSP_OK);
    response.producedAt(SDateTime(2026, 2, 1, 12, 0, 0, 0, true));
    REQUIRE(
        response.add(
            leaf, ca, EOCSPENT_GOOD,
            SDateTime(2026, 2, 1, 12, 0, 0, 0, true),
            SDateTime(2026, 2, 8, 12, 0, 0, 0, true)
        ) == ERET_OK
    );

    COctet encoded;
    REQUIRE(response.build(ca, encoded) == ERET_OK);

    std::vector<uint8_t> bytes(encoded.toPtr(), encoded.toPtr() + encoded.size());

    COcspResponse clean;
    REQUIRE(clean.decode(COctet(bytes.data(), bytes.size())) == ERET_OK);

    const std::vector<uint8_t> suffixed = withTrailing(bytes, { 0xDE, 0xAD, 0xBE, 0xEF });
    COcspResponse decoded;
    CHECK(decoded.decode(COctet(suffixed.data(), suffixed.size())) != ERET_OK);
}

/* RFC 5280 4.1: extensions is `[3] EXPLICIT Extensions OPTIONAL`, and an EXPLICIT context tag
 * wrapping a SEQUENCE is always constructed -- 0xA3, never the primitive 0x83.
 *
 * Currently: ERET_OK, with every extension silently dropped. The tag comparison does require
 * isConstructed(), so the 0x83 wrapper correctly fails to match, but the non-match is treated as
 * "no extensions present" rather than as an error, and parseExtensions() returns void so it has
 * no way to fail the import at all. Required: rejected.
 *
 * This fails open in the worst direction: BasicConstraints, KeyUsage, ExtendedKeyUsage and
 * NameConstraints all vanish, so a certificate carrying cA=FALSE and a name constraint imports
 * as one carrying no constraints whatsoever. */
TEST_CASE("CCert::importDer(): rejects a malformed [3] extensions wrapper instead of dropping the extensions") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));

    CCert original;
    REQUIRE(importCert(der, original) == ERET_OK);
    REQUIRE(keepsKnownExtensions(original));

    Tlv wrapper;
    REQUIRE(findExtensionsWrapper(SReadOnlyByteSpan(der.data(), der.size()), wrapper));

    const size_t tagAt = offsetIn(der, wrapper.whole);
    REQUIRE(der[tagAt] == 0xA3);

    SUBCASE("the constructed bit cleared") {
        der[tagAt] = 0x83;

        CCert cert;
        const ERetCode status = importCert(der, cert);

        // --> Either outcome is defensible; silently importing with no extensions is not.
        const bool rejectedOrKept = status != ERET_OK || keepsKnownExtensions(cert);
        CHECK(rejectedOrKept);
    }

    SUBCASE("a [3] wrapper whose declared length runs past the TBSCertificate") {
        // The wrapper's length octet is the one after its single-octet identifier. Growing it
        // makes readNextElement() fail, which lands in the same "no extensions present" branch.
        const size_t lengthAt = tagAt + 1;
        REQUIRE((der[lengthAt] & 0x80) != 0); // long form -- github.com's extensions exceed 127 octets
        der[lengthAt + 1] = 0xFF;             // inflate the high length octet

        CCert cert;
        const ERetCode status = importCert(der, cert);
        const bool rejectedOrKept = status != ERET_OK || keepsKnownExtensions(cert);
        CHECK(rejectedOrKept);
    }
}

/* RFC 5280 4.1.1.2: "This field MUST contain the same algorithm identifier as the signature
 * field in the sequence tbsCertificate". CCert::importDer reads TBSCertificate.signature past
 * (the grammar requires it) and then never looks at it -- there is no comparison of any kind
 * against Certificate.signatureAlgorithm.
 *
 * Currently: ERET_OK, reporting the outer algorithm. Required: rejected.
 *
 * The inner copy is the one covered by the signature; the outer copy is the one this library
 * reports through signAlgo() and uses to pick the hash for verification. A mismatch is therefore
 * an unauthenticated field steering signature verification -- the exact shape of an algorithm
 * substitution/downgrade attack, and the reason RFC 5280 makes them MUST-match. */
TEST_CASE("CCert::importDer(): rejects TBSCertificate.signature disagreeing with Certificate.signatureAlgorithm") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));
    REQUIRE(importCert(der) == ERET_OK);

    std::vector<Tlv> certElements;
    REQUIRE(splitDocument(SReadOnlyByteSpan(der.data(), der.size()), certElements));
    REQUIRE(certElements.size() == 3);

    std::vector<Tlv> tbsElements;
    REQUIRE(splitElements(certElements[0].content, tbsElements));

    size_t innerAlgoIndex = 0;
    REQUIRE(sequenceIndex(tbsElements, false, innerAlgoIndex)); // first SEQUENCE in TBS

    std::vector<Tlv> innerAlgo;
    REQUIRE(splitElements(tbsElements[innerAlgoIndex].content, innerAlgo));
    REQUIRE_FALSE(innerAlgo.empty());
    REQUIRE(innerAlgo[0].tag.value() == uint32_t(EAUTAG_OBJ_ID));

    // --> Bump the OID's final arc. github.com is ecdsa-with-SHA256 (1.2.840.10045.4.3.2); .3 is
    // ecdsa-with-SHA384, so this stays a well-formed OID of identical length -- the only thing
    // that changes is that the inner and outer algorithm identifiers no longer agree.
    const size_t lastArcAt = offsetIn(der, innerAlgo[0].content) + innerAlgo[0].content.size - 1;
    const uint8_t originalArc = der[lastArcAt];
    REQUIRE(originalArc < 0x7F);
    der[lastArcAt] = uint8_t(originalArc + 1);

    CCert cert;
    const ERetCode status = importCert(der, cert);
    CHECK(status != ERET_OK);
}

/* RFC 5280 4.1.1.3: signatureValue is a BIT STRING holding the signature, which is always a
 * whole number of octets -- its unused-bit count is 0. CCert::importDer reads the count into a
 * local and never tests it, unlike the SubjectPublicKeyInfo BIT STRING a few lines earlier,
 * which it does check (see the enforced case above).
 *
 * Currently: ERET_OK, and _signature keeps all the bits regardless. Required: rejected.
 *
 * Exploitability: the unused-bit count is not covered by the signature, so an attacker can
 * change it freely. It yields up to 8 extra accepted encodings of any certificate (certificate
 * malleability, same consequence as the trailing-bytes case), and any consumer that honours the
 * count when reconstructing the signature disagrees with one that ignores it. */
TEST_CASE("CCert::importDer(): rejects a signatureValue BIT STRING with a non-zero unused-bit count") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));
    REQUIRE(importCert(der) == ERET_OK);

    std::vector<Tlv> certElements;
    REQUIRE(splitDocument(SReadOnlyByteSpan(der.data(), der.size()), certElements));
    REQUIRE(certElements.size() == 3);
    REQUIRE(certElements[2].tag.value() == uint32_t(EAUTAG_STRING_BIT));
    REQUIRE(certElements[2].content.size > 1);

    const size_t unusedBitsAt = offsetIn(der, certElements[2].content);
    REQUIRE(der[unusedBitsAt] == 0x00);

    // --> Claim one unused bit and zero it in the final octet, so the BIT STRING stays valid DER
    // (X.690 11.2.1) and the only rule broken is the x509-level "must be 0".
    der[unusedBitsAt] = 0x01;
    der[unusedBitsAt + certElements[2].content.size - 1] &= 0xFE;

    CHECK(importCert(der) != ERET_OK);
}

/* RFC 5280 4.1: `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`. A zero-entry extensions
 * list is not a legal encoding -- a certificate with no extensions omits the whole [3] wrapper.
 *
 * Currently: ERET_OK with zero extensions, because parseExtensions() just finds an empty list
 * and falls out of its loop; it returns void and cannot fail the import. Required: rejected. */
TEST_CASE("known gap: an empty Extensions SEQUENCE, which ASN.1 constrains to SIZE (1..MAX)") {
    std::vector<uint8_t> der;
    REQUIRE(readDerFile(GITHUB_CERT_PATH, der));

    CCert original;
    REQUIRE(importCert(der, original) == ERET_OK);
    REQUIRE(keepsKnownExtensions(original));

    const SReadOnlyByteSpan source(der.data(), der.size());

    SUBCASE("the rebuild helper itself is faithful") {
        // --> Re-splicing the original wrapper must reproduce an importable certificate with the
        // same extensions, so a failure below is the empty SEQUENCE talking, not the surgery.
        Tlv wrapper;
        REQUIRE(findExtensionsWrapper(source, wrapper));

        std::vector<uint8_t> rebuilt;
        REQUIRE(rebuildWithExtensionsWrapper(source, wrapper.whole, rebuilt));

        CCert cert;
        REQUIRE(importCert(rebuilt, cert) == ERET_OK);
        CHECK(keepsKnownExtensions(cert));
    }

    SUBCASE("an empty extensions list") {
        const uint8_t emptyWrapper[] = { 0xA3, 0x02, 0x30, 0x00 }; // [3] { SEQUENCE {} }

        std::vector<uint8_t> rebuilt;
        REQUIRE(rebuildWithExtensionsWrapper(source, SReadOnlyByteSpan(emptyWrapper, sizeof(emptyWrapper)), rebuilt));

        WARN(importCert(rebuilt) != ERET_OK);
    }

    SUBCASE("an empty [3] wrapper with no SEQUENCE inside it at all") {
        const uint8_t emptyWrapper[] = { 0xA3, 0x00 };

        std::vector<uint8_t> rebuilt;
        REQUIRE(rebuildWithExtensionsWrapper(source, SReadOnlyByteSpan(emptyWrapper, sizeof(emptyWrapper)), rebuilt));

        WARN(importCert(rebuilt) != ERET_OK);
    }
}

/* RFC 5280 4.2.1.9: `pathLenConstraint INTEGER (0..MAX) OPTIONAL`. CBasicConstraintsExtension
 * decodes it with CReader::readInteger into a signed int64_t and never range-checks it, so the
 * (0..MAX) constraint is simply not applied.
 *
 * Currently: hasPathLenConstraint() is true and pathLenConstraint() returns the negative value.
 * Required: either rejected, or at minimum not reported as a usable constraint.
 *
 * A negative constraint is a path-validation hazard rather than a parsing one: RFC 5280 6.1.4(l)
 * decrements max_path_length and fails at 0, so a caller that stores this in an unsigned depth
 * counter, or that compares with the wrong signedness, turns "no further CAs permitted" into an
 * effectively unlimited chain. */
TEST_CASE("CBasicConstraintsExtension: a negative pathLenConstraint is not reported as a constraint") {
    SUBCASE("pathLenConstraint -1") {
        const uint8_t value[] = {
            0x30, 0x06,
            0x01, 0x01, 0xFF,  // cA TRUE
            0x02, 0x01, 0xFF   // pathLenConstraint -1
        };
        CBasicConstraintsExtension bc(COctet(value, sizeof(value)));

        REQUIRE(bc.isCa());
        const bool reportsNegative = bc.hasPathLenConstraint() && bc.pathLenConstraint() < 0;
        CHECK_FALSE(reportsNegative);
    }

    SUBCASE("a large negative pathLenConstraint") {
        const uint8_t value[] = {
            0x30, 0x07,
            0x01, 0x01, 0xFF,
            0x02, 0x02, 0x80, 0x00 // pathLenConstraint -32768
        };
        CBasicConstraintsExtension bc(COctet(value, sizeof(value)));

        const bool reportsNegative = bc.hasPathLenConstraint() && bc.pathLenConstraint() < 0;
        CHECK_FALSE(reportsNegative);
    }

    SUBCASE("a non-negative pathLenConstraint is of course still accepted") {
        const uint8_t value[] = {
            0x30, 0x06,
            0x01, 0x01, 0xFF,
            0x02, 0x01, 0x03
        };
        CBasicConstraintsExtension bc(COctet(value, sizeof(value)));

        CHECK(bc.isCa());
        REQUIRE(bc.hasPathLenConstraint());
        CHECK(bc.pathLenConstraint() == 3);
    }
}

/* RFC 5280 4.2.1.9: "CAs MUST NOT include the pathLenConstraint field unless the cA boolean is
 * asserted". Unlike the negative-value case above, this one is still unenforced: the field
 * decodes and survives as a usable constraint on a non-CA certificate. Not a decoding error, and
 * harmless to a validator that checks cA first -- which is why it is recorded rather than fixed. */
TEST_CASE("known gap: pathLenConstraint present with cA FALSE") {
    const uint8_t value[] = {
        0x30, 0x06,
        0x01, 0x01, 0x00,  // cA FALSE
        0x02, 0x01, 0x00   // pathLenConstraint 0
    };
    CBasicConstraintsExtension bc(COctet(value, sizeof(value)));

    REQUIRE_FALSE(bc.isCa());
    WARN_FALSE(bc.hasPathLenConstraint());
}

/* RFC 5280 4.1.2.4: "The issuer field MUST contain a non-empty distinguished name". An empty
 * RDNSequence decodes as a valid, empty CDistinguishedName -- decodeDistinguishedName's loop
 * simply never runs -- and importDer applies no emptiness check to either issuer or subject.
 *
 * Currently: decodes successfully as an empty name. Required: an empty issuer rejected. (An
 * empty *subject* is legal per 4.1.2.6 when a subjectAltName is present and critical, so the two
 * fields genuinely differ; this library distinguishes neither.) */
TEST_CASE("known gap: an empty RDNSequence decodes as a valid distinguished name") {
    CDistinguishedName name;

    // The content octets of `30 00` -- an RDNSequence with no RelativeDistinguishedNames.
    const bool decoded = CDecoder::decodeDistinguishedName(SReadOnlyByteSpan(nullptr, 0), name);

    const bool acceptedAsEmpty = decoded && name.empty();
    WARN_FALSE(acceptedAsEmpty);
}
