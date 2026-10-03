// CPfxFormat (PKCS#12/PFX, RFC 7292).
//
// The containers under fixtures/ were produced by OpenSSL 3.2.1, not by this library, and that
// is the point of them: a PFX this code wrote and read back proves that two bugs cancel, not
// that the format was implemented. They were generated once with `openssl pkcs12 -export` and
// checked in, so the suite does not need openssl on PATH to run.
//
// The reverse direction -- something else reading what this writes -- cannot be asserted from
// inside a test without shelling out, so the round-trip cases below write
// `pfx-written-by-certpp.p12` into the working directory (the build tree, under ctest) as a
// by-product. The companion manual check is:
//
//     openssl pkcs12 -info -in pfx-written-by-certpp.p12 -passin pass:correct-horse -nodes
//
// which is how the interoperability claim in docs/changelog.md was actually established.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <fstream>

using namespace certpp;
using namespace certpp::crypto;
using namespace certpp::x509;

namespace {

    // CERTPP_TEST_DIR is injected by CMakeLists.txt: the absolute path of this .cpp's own
    // directory, so these resolve wherever ctest runs the binary from.
    constexpr const char* FIXTURE_EC        = CERTPP_TEST_DIR "/fixtures/openssl-ec-aes256-sha256.p12";
    constexpr const char* FIXTURE_CHAIN     = CERTPP_TEST_DIR "/fixtures/openssl-chain-aes256.p12";
    constexpr const char* FIXTURE_RSA       = CERTPP_TEST_DIR "/fixtures/openssl-rsa-aes256.p12";
    constexpr const char* FIXTURE_MAC_SHA1  = CERTPP_TEST_DIR "/fixtures/openssl-ec-macsha1.p12";
    constexpr const char* FIXTURE_LEGACY    = CERTPP_TEST_DIR "/fixtures/openssl-legacy-3des.p12";
    constexpr const char* FIXTURE_UTF8_PASSWORD = CERTPP_TEST_DIR "/fixtures/openssl-utf8-password.p12";

    constexpr const char* FIXTURE_PASSWORD = "correct-horse";

    /* Reads an entire file into an owning COctet. False if it can't be opened or read. */
    bool readFile(const char* path, COctet& out) {
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

    /* Writes a buffer out, for the manual openssl cross-check described at the top of the file. */
    void writeFile(const char* path, const CBuffer& data) {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (file) {
            file.write(reinterpret_cast<const char*>(data.toPtr()), std::streamsize(data.size()));
        }
    }

    /* A C string as a byte span, without its terminator -- which is how a password reaches
     * load()/save(), since the terminator is not part of it. */
    SReadOnlyByteSpan textSpan(const char* text) {
        return SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text));
    }

    /* A copy of data with one byte XORed, for the tampering cases. */
    COctet withFlippedByte(const COctet& data, size_t offset) {
        REQUIRE(offset < data.size());

        TArray<uint8_t> copy;
        REQUIRE(copy.resize(data.size()));
        std::memcpy(copy.begin(), data.toPtr(), data.size());
        copy.begin()[offset] = uint8_t(copy.begin()[offset] ^ 0x01u);

        return COctet(SReadOnlyByteSpan(copy.begin(), copy.size()));
    }

    /* Issues a certificate for subjectKey, signed by issuerKeyPair. The same shape as
     * tests/x509/chain.cpp's, which is where the convention comes from. */
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

    SKeyPair generate(EAsymmetrics which, SKeySize bits) {
        IAsymmetricPtr algo = IAsymmetric::builtIn(which);
        SKeyPair kp;

        for (int attempt = 0; attempt < 8 && algo; ++attempt) {
            if (algo->generateKeyPair(bits, kp) == ERET_OK) {
                break;
            }
        }

        return kp;
    }

    struct SHierarchy {
        SKeyPair rootKey, interKey, leafKey;
        CCert root, inter, leaf;

        bool build() {
            rootKey = generate(EASYM_P256, SKeySize(256));
            interKey = generate(EASYM_P256, SKeySize(256));
            leafKey = generate(EASYM_P256, SKeySize(256));

            if (!rootKey.publicKey || !interKey.publicKey || !leafKey.publicKey) {
                return false;
            }

            return issue(root, CString("CN=Round Trip Root"), CString("CN=Round Trip Root"),
                         rootKey.publicKey, rootKey, 0x01)
                && issue(inter, CString("CN=Round Trip Intermediate"), CString("CN=Round Trip Root"),
                         interKey.publicKey, rootKey, 0x02)
                && issue(leaf, CString("CN=Round Trip Leaf"), CString("CN=Round Trip Intermediate"),
                         leafKey.publicKey, interKey, 0x03);
        }
    };

    /* A fast handler for the round-trip cases. DEFAULT_ITERATIONS is 600,000 by design and costs
     * roughly a third of a second per derivation; a test that writes and reads a dozen containers
     * would spend its whole runtime in PBKDF2 proving nothing the iteration count is responsible
     * for. One case below deliberately uses the default anyway, so the shipped setting is
     * exercised rather than merely declared. */
    IChainFormatPtr fastPfx() {
        return std::make_shared<CPfxFormat>(2048);
    }

    size_t findSubject(const CCertCollection& col, const char* dn) {
        CDistinguishedName name;
        REQUIRE(CDistinguishedName::tryParse(name, CString(dn)));
        return col.findBySubject(name);
    }

} // namespace

TEST_CASE("CPfxFormat: builtIn and detect") {
    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    REQUIRE(pfx);
    CHECK(pfx->format() == ECHAINFMT_PFX);
    CHECK(pfx->needsPassword());

    CHECK_FALSE(IChainFormat::builtIn(ECHAINFMT_UNKNOWN));

    // detect() is a guess from the first bytes and nothing more -- a PFX is DER, so a SEQUENCE
    // tag is all there is to go on.
    COctet der;
    REQUIRE(readFile(FIXTURE_EC, der));
    CHECK(IChainFormat::detect(der.toSpan()) == ECHAINFMT_PFX);
}

// -------------------------------------------------------------------- reading OpenSSL's output

TEST_CASE("CPfxFormat: reads an EC container OpenSSL 3 produced with its own defaults") {
    COctet der;
    REQUIRE(readFile(FIXTURE_EC, der));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    CCertCollection col;
    REQUIRE(pfx->load(der.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_OK);

    REQUIRE(col.count() == 1);

    SCertEntry entry;
    REQUIRE(col.at(0, entry) == ERET_OK);
    CString subjectText;
    entry.cert.subject().toString(subjectText);
    CHECK(subjectText.compare("CN=Interop Leaf") == 0);

    // The PKCS#9 attributes OpenSSL wrote. friendlyName arrives as a BMPString and comes back
    // as UTF-8; localKeyId is the SHA-1 of the certificate, which is why it equals thumbprint().
    CHECK(entry.friendlyName.compare("interop leaf") == 0);
    REQUIRE_FALSE(entry.localKeyId.empty());
    CHECK(entry.localKeyId.size() == 20);
    CHECK(std::memcmp(entry.localKeyId.toPtr(), entry.cert.thumbprint().toPtr(), 20) == 0);

    // The key: present, and genuinely the certificate's own. checkKeyPairing() signs with the
    // private key and verifies against the certificate, which is the only check that establishes
    // the pairing rather than assuming it.
    REQUIRE(entry.hasPrivateKey());
    CHECK(entry.privateKey->algorithm() == EASYM_P256);
    CHECK(col.checkKeyPairing(0) == ERET_OK);
}

TEST_CASE("CPfxFormat: reads an RSA container OpenSSL produced") {
    COctet der;
    REQUIRE(readFile(FIXTURE_RSA, der));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    CCertCollection col;
    REQUIRE(pfx->load(der.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_OK);

    REQUIRE(col.count() == 1);

    SCertEntry entry;
    REQUIRE(col.at(0, entry) == ERET_OK);
    CString subjectText;
    entry.cert.subject().toString(subjectText);
    CHECK(subjectText.compare("CN=Interop RSA") == 0);
    REQUIRE(entry.hasPrivateKey());
    CHECK(entry.privateKey->algorithm() == EASYM_RSA);

    // RSA's PKCS#8 inner blob is the PKCS#1 RSAPrivateKey directly, where EC's is a SEC1
    // ECPrivateKey -- two different conventions behind the same OCTET STRING, so both are worth
    // a pairing check rather than just a parse.
    CHECK(col.checkKeyPairing(0) == ERET_OK);
}

TEST_CASE("CPfxFormat: reads a two-certificate chain and pairs the key to the right one") {
    COctet der;
    REQUIRE(readFile(FIXTURE_CHAIN, der));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    CCertCollection col;
    REQUIRE(pfx->load(der.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_OK);

    REQUIRE(col.count() == 2);

    const size_t leafIdx = findSubject(col, "CN=Interop Leaf 2");
    const size_t rootIdx = findSubject(col, "CN=Interop Root");
    REQUIRE(leafIdx != CCertCollection::NOT_FOUND);
    REQUIRE(rootIdx != CCertCollection::NOT_FOUND);

    // The whole job of localKeyId: with two certificates in the container, the key must land on
    // the leaf and not on the root. A reader that attached it to whichever came first would pass
    // every other check in this file.
    SCertEntry leafEntry, rootEntry;
    REQUIRE(col.at(leafIdx, leafEntry) == ERET_OK);
    REQUIRE(col.at(rootIdx, rootEntry) == ERET_OK);
    CHECK(leafEntry.hasPrivateKey());
    CHECK_FALSE(rootEntry.hasPrivateKey());
    CHECK(col.checkKeyPairing(leafIdx) == ERET_OK);

    // And the pair really is a chain.
    TArray<size_t> chain;
    CHECK(col.buildChain(leafIdx, chain) == ECHAINRES_OK);
    REQUIRE(chain.size() == 2);
    CHECK(col.verifyLinks(chain) == ERET_OK);
}

TEST_CASE("CPfxFormat: verifies a SHA-1 MacData, which is what files written before ~2021 have") {
    COctet der;
    REQUIRE(readFile(FIXTURE_MAC_SHA1, der));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    CCertCollection col;

    // SHA-256 is what save() writes, but refusing to *verify* a SHA-1 MAC would mean refusing
    // most containers in existence. The Appendix B KDF runs over a different block size and
    // digest length here, which is the part worth exercising.
    REQUIRE(pfx->load(der.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_OK);
    CHECK(col.count() == 1);
    CHECK(col.checkKeyPairing(0) == ERET_OK);
}

TEST_CASE("CPfxFormat: reads a container whose password is not ASCII") {
    // This is the only case in the file that actually validates the BMPString conversion, and it
    // is worth being blunt about why. The PFX password reaches two KDFs in two encodings: PBES2
    // takes the bytes as given, and RFC 7292 Appendix B's KDF takes them as a NUL-terminated
    // UTF-16BE BMPString. For an ASCII password those differ only by the interleaved zero bytes,
    // and a round trip through this library alone agrees with itself whichever it does. So does a
    // round trip with a non-ASCII password. Only a container somebody else wrote pins it -- and
    // OpenSSL 3 converts UTF-8 to UTF-16, so this fixture fails if this library zero-extends each
    // byte Latin-1 style instead, which is what the older OPENSSL_asc2uni did and what a
    // plausible reading of "BMPString" would suggest.
    COctet der;
    REQUIRE(readFile(FIXTURE_UTF8_PASSWORD, der));

    // "passwörd" in UTF-8: nine bytes, eight characters, and the o-umlaut is two bytes here
    // against one UTF-16 unit there.
    const uint8_t password[] = { 'p', 'a', 's', 's', 'w', 0xC3, 0xB6, 'r', 'd' };

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    CCertCollection col;
    REQUIRE(pfx->load(der.toSpan(), SReadOnlyByteSpan(password, sizeof(password)), col)
            == ERET_OK);

    REQUIRE(col.count() == 1);
    CHECK(col.checkKeyPairing(0) == ERET_OK);

    SCertEntry entry;
    REQUIRE(col.at(0, entry) == ERET_OK);
    CHECK(entry.friendlyName.compare("umlaut password") == 0);
}

TEST_CASE("CPfxFormat: the legacy PKCS#12 ciphers are refused, not guessed at") {
    COctet der;
    REQUIRE(readFile(FIXTURE_LEGACY, der));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    CCertCollection col;

    // pbeWithSHAAnd3-KeyTripleDES-CBC under PBES1. The MAC verifies -- it is the same Appendix B
    // derivation either way -- and then the content encryption turns out to be something this
    // library does not implement. ERET_NOTSUP, which tells the caller "I cannot read this",
    // rather than ERET_BADREQ, which would say "this is not a PFX", or a silent partial load.
    CHECK(pfx->load(der.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_NOTSUP);
    CHECK(col.empty());
}

// ------------------------------------------------------------------------ the security contract

TEST_CASE("CPfxFormat: a wrong password and a tampered file are indistinguishable") {
    COctet der;
    REQUIRE(readFile(FIXTURE_EC, der));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);

    CCertCollection wrongPw;
    CHECK(pfx->load(der.toSpan(), textSpan("incorrect-horse"), wrongPw) == ERET_KEY_ERROR);
    CHECK(wrongPw.empty());

    // A password that differs in one byte, and one that differs in length: both the same code.
    CCertCollection nearMiss;
    CHECK(pfx->load(der.toSpan(), textSpan("correct-horsf"), nearMiss) == ERET_KEY_ERROR);
    CHECK(pfx->load(der.toSpan(), textSpan("correct-hors"), nearMiss) == ERET_KEY_ERROR);
    CHECK(nearMiss.empty());

    // Now tamper with the container itself, inside the encrypted certificate bag. The MAC covers
    // the whole AuthenticatedSafe, so this must fail with the *same* code as a wrong password --
    // a reader that reported these differently would let an attacker ask "was my guess right?"
    // and get an answer.
    const COctet tampered = withFlippedByte(der, der.size() / 2);
    CCertCollection corrupt;
    CHECK(pfx->load(tampered.toSpan(), textSpan(FIXTURE_PASSWORD), corrupt) == ERET_KEY_ERROR);
    CHECK(corrupt.empty());
}

TEST_CASE("CPfxFormat: every byte the MAC covers is rejected before anything is decrypted") {
    // The negative control for MAC-then-decrypt. Every byte of the AuthenticatedSafe -- which is
    // exactly the range the MAC covers, and everything an attacker would want to change -- is
    // flipped in turn, and the result must come back ERET_KEY_ERROR. Never ERET_OK, obviously,
    // and never ERET_BADREQ either: ERET_BADREQ is what a reader that decrypted first and then
    // tripped over the resulting garbage reports, so its absence here is the evidence that the
    // order is right. Swapping the MAC check in pfx.cpp to after the decryption turns a large
    // share of these into ERET_BADREQ.
    COctet der;
    REQUIRE(readFile(FIXTURE_EC, der));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);

    // Locate the MAC-covered range rather than guessing at it from the file's length: the span
    // the reader hands back points into `der`, so the difference is its offset.
    using namespace certpp::asn1;

    SReadOnlyByteSpan authenticated;
    {
        CReader reader(der.toSpan(), EAENC_DER);
        CReader pfxSeq, authSafe;
        int64_t version = 0;
        CString oid;
        CTag tag;
        SReadOnlyByteSpan wrapped;
        REQUIRE(reader.readSequence(pfxSeq));
        REQUIRE(pfxSeq.readInteger(version));
        REQUIRE(pfxSeq.readSequence(authSafe));
        REQUIRE(authSafe.readOidString(oid));
        REQUIRE(authSafe.readNextElement(tag, wrapped));

        CReader octet(wrapped, EAENC_DER);
        REQUIRE(octet.readOctetString(authenticated));
    }

    const size_t begin = size_t(authenticated.data - der.toPtr());
    const size_t end = begin + authenticated.size;
    REQUIRE(begin > 0);
    REQUIRE(end <= der.size());

    size_t checked = 0;
    for (size_t offset = begin; offset < end; ++offset) {
        const COctet tampered = withFlippedByte(der, offset);
        CCertCollection col;
        const ERetCode rc = pfx->load(tampered.toSpan(), textSpan(FIXTURE_PASSWORD), col);

        CHECK(rc == ERET_KEY_ERROR);
        CHECK(col.empty());
        ++checked;
    }

    CHECK(checked == authenticated.size);

    // The bytes *outside* that range -- the outer DER headers and MacData itself -- are a
    // different matter, and the honest statement is that they are not integrity-protected,
    // because they cannot be: MacData holds the MAC, so nothing can MAC it. A bit flipped in
    // MacData's own structure is therefore a parse failure (ERET_BADREQ), an unrecognised digest
    // (ERET_NOTSUP), or -- where it lands in a field this reader does not use, such as the NULL
    // in the digest AlgorithmIdentifier's `parameters` -- no change at all, and the container
    // still loads because it is still authentic. That is not a gap in the MAC; it is what the
    // MAC's scope is. What matters is that nothing an attacker could put a payload in falls
    // outside it, and the sweep above is over all of that.
    CHECK(end < der.size());
}

TEST_CASE("CPfxFormat: a container with no MacData is refused rather than read unauthenticated") {
    // RFC 7292 makes MacData OPTIONAL, which is a statement about the ASN.1 and not a licence to
    // trust a container nothing vouches for. Built here by re-encoding a real container's first
    // two fields and stopping, which is exactly what a stripped MacData looks like on the wire.
    COctet der;
    REQUIRE(readFile(FIXTURE_EC, der));

    using namespace certpp::asn1;

    CReader reader(der.toSpan(), EAENC_DER);
    CReader pfxSeq;
    REQUIRE(reader.readSequence(pfxSeq));

    CTag versionTag, authSafeTag;
    SReadOnlyByteSpan versionContent, authSafeContent;
    REQUIRE(pfxSeq.readNextElement(versionTag, versionContent));
    REQUIRE(pfxSeq.readNextElement(authSafeTag, authSafeContent));

    CBuffer body, stripped;
    REQUIRE(CDer::appendTlv(body, versionTag, versionContent));
    REQUIRE(CDer::appendTlv(body, authSafeTag, authSafeContent));
    REQUIRE(CDer::appendSequence(stripped, body.toSpan()));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    CCertCollection col;

    // The same ERET_KEY_ERROR a failed MAC gets: "nothing authenticated this" and "something
    // authenticated it wrongly" are the same answer to the caller.
    CHECK(pfx->load(stripped.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_KEY_ERROR);
    CHECK(col.empty());
}

TEST_CASE("CPfxFormat: an absurd MacData iteration count is refused, not run") {
    // The MAC key has to be derived before the MAC can be checked, so this is the one iteration
    // count in the format that an attacker chooses. A container claiming two billion is a
    // 200-byte file that costs minutes of CPU to open, which is why there is a ceiling.
    // Rebuilt here from a real container with only MacData's `iterations` replaced -- the MAC
    // itself is then wrong too, but the point is that the refusal arrives *before* the KDF runs,
    // which is observable as the call returning promptly rather than in minutes.
    COctet der;
    REQUIRE(readFile(FIXTURE_EC, der));

    using namespace certpp::asn1;

    CReader reader(der.toSpan(), EAENC_DER);
    CReader pfxSeq;
    REQUIRE(reader.readSequence(pfxSeq));

    CTag versionTag, authSafeTag, macDataTag;
    SReadOnlyByteSpan versionContent, authSafeContent, macDataContent;
    REQUIRE(pfxSeq.readNextElement(versionTag, versionContent));
    REQUIRE(pfxSeq.readNextElement(authSafeTag, authSafeContent));
    REQUIRE(pfxSeq.readNextElement(macDataTag, macDataContent));

    // MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER }
    CReader macData(macDataContent, EAENC_DER);
    CTag digestInfoTag, saltTag, itersTag;
    SReadOnlyByteSpan digestInfoContent, saltContent, itersContent;
    REQUIRE(macData.readNextElement(digestInfoTag, digestInfoContent));
    REQUIRE(macData.readNextElement(saltTag, saltContent));
    REQUIRE(macData.readNextElement(itersTag, itersContent));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);

    auto withIterations = [&](int64_t iterations, CBuffer& out) {
        CBuffer macBody, macSeq, pfxBody;
        REQUIRE(CDer::appendTlv(macBody, digestInfoTag, digestInfoContent));
        REQUIRE(CDer::appendTlv(macBody, saltTag, saltContent));

        uint8_t intBuf[16];
        size_t written = 0;
        REQUIRE(CEncoder::encodeInteger(
            TSpan<uint8_t>(intBuf, sizeof(intBuf)), iterations, written));
        REQUIRE(CDer::appendTlv(macBody, CTag::INTEGER, SReadOnlyByteSpan(intBuf, written)));

        REQUIRE(CDer::appendSequence(macSeq, macBody.toSpan()));
        REQUIRE(CDer::appendTlv(pfxBody, versionTag, versionContent));
        REQUIRE(CDer::appendTlv(pfxBody, authSafeTag, authSafeContent));
        REQUIRE(CDer::appendRaw(pfxBody, macSeq.toSpan()));
        REQUIRE(CDer::appendSequence(out, pfxBody.toSpan()));
    };

    CCertCollection col;

    // Past the ceiling: refused as malformed, without deriving anything.
    CBuffer absurd;
    withIterations(int64_t(CPfxFormat::MAX_MAC_ITERATIONS) + 1, absurd);
    CHECK(pfx->load(absurd.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_BADREQ);

    // Zero is not "no stretching" either.
    CBuffer zero;
    withIterations(0, zero);
    CHECK(pfx->load(zero.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_BADREQ);

    // And a count inside the ceiling is honoured -- it is the wrong count for this container, so
    // the MAC fails, but it fails as an integrity check rather than as a malformed field. That
    // distinction is what shows the bound is a bound and not a blanket rejection.
    CBuffer allowed;
    withIterations(4096, allowed);
    CHECK(pfx->load(allowed.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_KEY_ERROR);

    // The original count still loads, so the rebuild itself is faithful.
    CBuffer original;
    withIterations(2048, original);
    CHECK(pfx->load(original.toSpan(), textSpan(FIXTURE_PASSWORD), col) == ERET_OK);
    CHECK(col.count() == 1);
}

TEST_CASE("CPfxFormat: save refuses an empty password") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    size_t index = 0;
    REQUIRE(col.add(h.leaf, h.leafKey.privateKey, index) == ERET_OK);

    IChainFormatPtr pfx = fastPfx();
    CBuffer out;

    // needsPassword() is true for this format, so an empty password is not "no encryption
    // wanted" -- it is a request for a container shaped like protection that has none.
    CHECK(pfx->save(col, SReadOnlyByteSpan(nullptr, 0), out) == ERET_BADREQ);
    CHECK(out.empty());

    // A one-byte password is weak and is nonetheless a password; the refusal is about empty, not
    // about strength, which this class is in no position to judge.
    CHECK(pfx->save(col, textSpan("x"), out) == ERET_OK);
    CHECK_FALSE(out.empty());
}

TEST_CASE("CPfxFormat: load refuses an empty password and an oversized container") {
    COctet der;
    REQUIRE(readFile(FIXTURE_EC, der));

    IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
    CCertCollection col;

    CHECK(pfx->load(der.toSpan(), SReadOnlyByteSpan(nullptr, 0), col) == ERET_BADREQ);
    CHECK(pfx->load(SReadOnlyByteSpan(nullptr, 0), textSpan(FIXTURE_PASSWORD), col) == ERET_BADREQ);
    CHECK(col.empty());

    // Not a PFX at all.
    const uint8_t garbage[] = { 'h', 'e', 'l', 'l', 'o' };
    CHECK(pfx->load(SReadOnlyByteSpan(garbage, sizeof(garbage)),
                    textSpan(FIXTURE_PASSWORD), col) == ERET_BADREQ);
    CHECK(col.empty());
}

// --------------------------------------------------------------------------------- round-tripping

TEST_CASE("CPfxFormat: round-trips a three-level hierarchy with its leaf key") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection original;
    size_t leafIdx = 0, interIdx = 0, rootIdx = 0;
    REQUIRE(original.add(h.leaf, h.leafKey.privateKey, leafIdx) == ERET_OK);
    REQUIRE(original.add(h.inter, interIdx) == ERET_OK);
    REQUIRE(original.add(h.root, rootIdx) == ERET_OK);
    REQUIRE(original.setFriendlyName(leafIdx, CString("my round-trip leaf")) == ERET_OK);

    IChainFormatPtr pfx = fastPfx();
    CBuffer container;
    REQUIRE(pfx->save(original, textSpan(FIXTURE_PASSWORD), container) == ERET_OK);
    REQUIRE_FALSE(container.empty());

    writeFile("pfx-written-by-certpp.p12", container);

    CCertCollection loaded;
    REQUIRE(pfx->load(container.toSpan(), textSpan(FIXTURE_PASSWORD), loaded) == ERET_OK);
    REQUIRE(loaded.count() == 3);

    const size_t loadedLeaf = findSubject(loaded, "CN=Round Trip Leaf");
    const size_t loadedInter = findSubject(loaded, "CN=Round Trip Intermediate");
    const size_t loadedRoot = findSubject(loaded, "CN=Round Trip Root");
    REQUIRE(loadedLeaf != CCertCollection::NOT_FOUND);
    REQUIRE(loadedInter != CCertCollection::NOT_FOUND);
    REQUIRE(loadedRoot != CCertCollection::NOT_FOUND);

    SCertEntry leafEntry;
    REQUIRE(loaded.at(loadedLeaf, leafEntry) == ERET_OK);

    // The end-to-end proof the task asks for: the key survived the PBES2 round trip *and* the
    // localKeyId pairing put it back on the certificate it belongs to.
    REQUIRE(leafEntry.hasPrivateKey());
    CHECK(loaded.checkKeyPairing(loadedLeaf) == ERET_OK);

    // The PKCS#9 attributes survived too. save() invented a localKeyId for the keyed entry
    // because none was set, since without one the key bag has nothing to pair back to.
    CHECK(leafEntry.friendlyName.compare("my round-trip leaf") == 0);
    REQUIRE_FALSE(leafEntry.localKeyId.empty());

    // The CA certificates came back without keys, which is the normal case and not an omission.
    SCertEntry interEntry, rootEntry;
    REQUIRE(loaded.at(loadedInter, interEntry) == ERET_OK);
    REQUIRE(loaded.at(loadedRoot, rootEntry) == ERET_OK);
    CHECK_FALSE(interEntry.hasPrivateKey());
    CHECK_FALSE(rootEntry.hasPrivateKey());

    // And the certificates are byte-identical, not merely equivalent.
    COctet before, after;
    REQUIRE(h.leaf.exportDer(before) == ERET_OK);
    REQUIRE(leafEntry.cert.exportDer(after) == ERET_OK);
    REQUIRE(before.size() == after.size());
    CHECK(std::memcmp(before.toPtr(), after.toPtr(), before.size()) == 0);

    // The chain still assembles and still verifies.
    TArray<size_t> chain;
    CHECK(loaded.buildChain(loadedLeaf, chain) == ECHAINRES_OK);
    REQUIRE(chain.size() == 3);
    CHECK(loaded.verifyLinks(chain) == ERET_OK);
}

TEST_CASE("CPfxFormat: round-trips at the shipped default iteration count") {
    // The cases above use 2048 iterations so they run quickly; this one uses what save() actually
    // ships with, so that DEFAULT_ITERATIONS is exercised and not just documented. It is the
    // slowest test in the file by design -- the cost is the feature.
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection original;
    size_t index = 0;
    REQUIRE(original.add(h.leaf, h.leafKey.privateKey, index) == ERET_OK);

    CPfxFormat pfx;
    CHECK(pfx.iterations() == CPfxFormat::DEFAULT_ITERATIONS);

    CBuffer container;
    REQUIRE(pfx.save(original, textSpan(FIXTURE_PASSWORD), container) == ERET_OK);

    // Dropped alongside the other written container for the manual openssl check, because
    // 600,000 and 2048 do not encode the same way -- a four-byte INTEGER against a two-byte one,
    // in both PBKDF2-params and MacData -- and the file written at the shipped default is the one
    // a user will actually hand to another tool.
    writeFile("pfx-written-by-certpp-default-iters.p12", container);

    CCertCollection loaded;
    REQUIRE(pfx.load(container.toSpan(), textSpan(FIXTURE_PASSWORD), loaded) == ERET_OK);
    REQUIRE(loaded.count() == 1);
    CHECK(loaded.checkKeyPairing(0) == ERET_OK);

    // A container written at 600,000 iterations is read at 600,000 iterations because that is
    // what it says, not because the reader was configured to match -- so a handler with a
    // different setting reads it just the same.
    CCertCollection other;
    CPfxFormat mismatched(2048);
    REQUIRE(mismatched.load(container.toSpan(), textSpan(FIXTURE_PASSWORD), other) == ERET_OK);
    CHECK(other.count() == 1);
}

TEST_CASE("CPfxFormat: round-trips an RSA key, and a container with no keys at all") {
    SKeyPair rsa = generate(EASYM_RSA, SKeySize(2048));
    REQUIRE(rsa.publicKey);

    CCert cert;
    REQUIRE(issue(cert, CString("CN=RSA Round Trip"), CString("CN=RSA Round Trip"),
                  rsa.publicKey, rsa, 0x11));

    IChainFormatPtr pfx = fastPfx();

    SUBCASE("with the key") {
        CCertCollection col;
        size_t index = 0;
        REQUIRE(col.add(cert, rsa.privateKey, index) == ERET_OK);

        CBuffer container;
        REQUIRE(pfx->save(col, textSpan(FIXTURE_PASSWORD), container) == ERET_OK);

        CCertCollection loaded;
        REQUIRE(pfx->load(container.toSpan(), textSpan(FIXTURE_PASSWORD), loaded) == ERET_OK);
        REQUIRE(loaded.count() == 1);

        SCertEntry entry;
        REQUIRE(loaded.at(0, entry) == ERET_OK);
        REQUIRE(entry.hasPrivateKey());
        CHECK(entry.privateKey->algorithm() == EASYM_RSA);
        CHECK(loaded.checkKeyPairing(0) == ERET_OK);
    }

    SUBCASE("certificates only") {
        // A trust-store-shaped container: no key bags at all, so AuthenticatedSafe has one
        // ContentInfo rather than two. Still MACed, still encrypted, still a valid PFX.
        CCertCollection col;
        size_t index = 0;
        REQUIRE(col.add(cert, index) == ERET_OK);

        CBuffer container;
        REQUIRE(pfx->save(col, textSpan(FIXTURE_PASSWORD), container) == ERET_OK);

        CCertCollection loaded;
        REQUIRE(pfx->load(container.toSpan(), textSpan(FIXTURE_PASSWORD), loaded) == ERET_OK);
        REQUIRE(loaded.count() == 1);

        SCertEntry entry;
        REQUIRE(loaded.at(0, entry) == ERET_OK);
        CHECK_FALSE(entry.hasPrivateKey());

        // No key means no localKeyId was invented, since there is nothing to pair.
        CHECK(entry.localKeyId.empty());
    }
}

TEST_CASE("CPfxFormat: load appends rather than replacing") {
    SHierarchy h;
    REQUIRE(h.build());

    IChainFormatPtr pfx = fastPfx();

    CCertCollection one;
    size_t index = 0;
    REQUIRE(one.add(h.leaf, h.leafKey.privateKey, index) == ERET_OK);

    CBuffer container;
    REQUIRE(pfx->save(one, textSpan(FIXTURE_PASSWORD), container) == ERET_OK);

    // Pre-populate with something unrelated, then load on top: the documented behaviour is that
    // two containers loaded into one collection merge.
    CCertCollection merged;
    REQUIRE(merged.add(h.root, index) == ERET_OK);
    REQUIRE(pfx->load(container.toSpan(), textSpan(FIXTURE_PASSWORD), merged) == ERET_OK);
    CHECK(merged.count() == 2);

    // And a failed load leaves what was there alone rather than half-populating it.
    const COctet tampered = withFlippedByte(
        COctet(container.toSpan()), container.size() * 2 / 3);
    CHECK(pfx->load(tampered.toSpan(), textSpan(FIXTURE_PASSWORD), merged) == ERET_KEY_ERROR);
    CHECK(merged.count() == 2);
}

TEST_CASE("CPfxFormat: an empty collection cannot be saved") {
    IChainFormatPtr pfx = fastPfx();
    CCertCollection empty;
    CBuffer out;

    CHECK(pfx->save(empty, textSpan(FIXTURE_PASSWORD), out) == ERET_BADREQ);
    CHECK(out.empty());
}

TEST_CASE("CPfxFormat: a non-ASCII password round-trips, and the two encodings stay distinct") {
    // The PFX password reaches two different KDFs in two different encodings: PBES2 takes the
    // bytes as given, and RFC 7292's Appendix B KDF takes them as a NUL-terminated UTF-16BE
    // BMPString. They agree for ASCII, which is why an ASCII-only test says nothing about
    // whether the conversion is there at all. This one does.
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    size_t index = 0;
    REQUIRE(col.add(h.leaf, h.leafKey.privateKey, index) == ERET_OK);

    IChainFormatPtr pfx = fastPfx();

    // "passwörd" in UTF-8: the o-umlaut is two bytes here and one UTF-16 unit there.
    const uint8_t utf8Password[] = {
        'p', 'a', 's', 's', 0xC3, 0xB6, 'r', 'd',
    };
    const SReadOnlyByteSpan password(utf8Password, sizeof(utf8Password));

    CBuffer container;
    REQUIRE(pfx->save(col, password, container) == ERET_OK);

    CCertCollection loaded;
    REQUIRE(pfx->load(container.toSpan(), password, loaded) == ERET_OK);
    CHECK(loaded.count() == 1);
    CHECK(loaded.checkKeyPairing(0) == ERET_OK);

    // The same characters written as Latin-1 are a different password -- and not even a valid
    // UTF-8 string, since a lone 0xF6 is a truncated four-byte lead. A password with no
    // BMPString form is ERET_BADREQ rather than ERET_KEY_ERROR, and that is not an oracle: the
    // refusal depends on the password alone and says nothing whatever about the container.
    const uint8_t latin1Password[] = { 'p', 'a', 's', 's', 0xF6, 'r', 'd' };
    CCertCollection wrong;
    CHECK(pfx->load(container.toSpan(),
                    SReadOnlyByteSpan(latin1Password, sizeof(latin1Password)),
                    wrong) == ERET_BADREQ);

    // A valid-UTF-8 password that differs only in that one character must come back as a plain
    // wrong password.
    const uint8_t otherUmlaut[] = { 'p', 'a', 's', 's', 0xC3, 0xBC, 'r', 'd' }; // "passwürd"
    CHECK(pfx->load(container.toSpan(),
                    SReadOnlyByteSpan(otherUmlaut, sizeof(otherUmlaut)),
                    wrong) == ERET_KEY_ERROR);
    CHECK(wrong.empty());

    // A password that is not valid UTF-8 has no BMPString form, so there is no key to derive.
    const uint8_t invalid[] = { 0xFF, 0xFE, 0x80 };
    CBuffer unused;
    CHECK(pfx->save(col, SReadOnlyByteSpan(invalid, sizeof(invalid)), unused) == ERET_BADREQ);
    CHECK(pfx->load(container.toSpan(), SReadOnlyByteSpan(invalid, sizeof(invalid)),
                    wrong) == ERET_BADREQ);
}

TEST_CASE("CPfxFormat: a friendlyName survives as a BMPString, non-ASCII included") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    size_t index = 0;
    REQUIRE(col.add(h.leaf, h.leafKey.privateKey, index) == ERET_OK);

    // "cert ünïcode" in UTF-8, which has to survive a trip through UTF-16BE and back.
    const char name[] = "cert \xC3\xBCn\xC3\xAF" "code";
    REQUIRE(col.setFriendlyName(index, CString(name)) == ERET_OK);

    IChainFormatPtr pfx = fastPfx();
    CBuffer container;
    REQUIRE(pfx->save(col, textSpan(FIXTURE_PASSWORD), container) == ERET_OK);

    CCertCollection loaded;
    REQUIRE(pfx->load(container.toSpan(), textSpan(FIXTURE_PASSWORD), loaded) == ERET_OK);
    REQUIRE(loaded.count() == 1);

    SCertEntry entry;
    REQUIRE(loaded.at(0, entry) == ERET_OK);
    CHECK(entry.friendlyName.compare(name) == 0);
    CHECK(loaded.findByFriendlyName(CString(name)) == 0);
}

// ------------------------------------------------------------- the PKCS#8 wrapping underneath

TEST_CASE("CCert: exportPkcs8PrivateKey and importPkcs8PrivateKey round-trip every algorithm") {
    // PFX stores keys as PKCS#8, so this pair is the layer the container sits on. Each algorithm
    // puts something different inside the privateKey OCTET STRING -- see
    // exportPkcs8PrivateKey()'s own doc comment -- and a round trip through this library alone
    // would not notice a wrong choice. The OpenSSL fixtures above are what catches that; this
    // case is here to pin the algorithms those fixtures do not cover.
    struct SCase { const char* name; EAsymmetrics which; SKeySize bits; };
    const SCase cases[] = {
        { "RSA-2048", EASYM_RSA,     SKeySize(2048) },
        { "P-256",    EASYM_P256,    SKeySize(256)  },
        { "P-384",    EASYM_P384,    SKeySize(384)  },
        { "Ed25519",  EASYM_ED25519, SKeySize(256)  },
        { "Ed448",    EASYM_ED448,   SKeySize(456)  },   // 57 bytes, not 56.
        { "X25519",   EASYM_X25519,  SKeySize(256)  },
    };

    for (const SCase& c : cases) {
        INFO("algorithm: " << c.name);

        SKeyPair kp = generate(c.which, c.bits);
        REQUIRE(kp.privateKey);

        COctet pkcs8;
        REQUIRE(CCert::exportPkcs8PrivateKey(kp.privateKey, pkcs8) == ERET_OK);
        REQUIRE_FALSE(pkcs8.empty());

        IPrivateKeyPtr back;
        REQUIRE(CCert::importPkcs8PrivateKey(pkcs8.toSpan(), back) == ERET_OK);
        REQUIRE(back);
        CHECK(back->algorithm() == c.which);

        // Compared by serialization rather than by pointer: the two are separate objects and the
        // question is whether the key material survived.
        COctet first, second;
        REQUIRE(kp.privateKey->serialize(first) == ERET_OK);
        REQUIRE(back->serialize(second) == ERET_OK);
        REQUIRE(first.size() == second.size());
        CHECK(std::memcmp(first.toPtr(), second.toPtr(), first.size()) == 0);
    }
}

TEST_CASE("CCert: PKCS#8 refusals") {
    IPrivateKeyPtr nothing;
    COctet out;
    CHECK(CCert::exportPkcs8PrivateKey(nothing, out) == ERET_INVAL);

    IPrivateKeyPtr key;
    CHECK(CCert::importPkcs8PrivateKey(SReadOnlyByteSpan(nullptr, 0), key) == ERET_BADREQ);
    CHECK_FALSE(key);

    const uint8_t garbage[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    CHECK(CCert::importPkcs8PrivateKey(
        SReadOnlyByteSpan(garbage, sizeof(garbage)), key) == ERET_BADREQ);
    CHECK_FALSE(key);

    // ML-DSA's PKCS#8 form is a CHOICE of seed and expanded key, and this library's own key blob
    // is neither -- so it is refused rather than wrapped in a guess.
    SKeyPair mldsa = generate(EASYM_MLDSA44, SKeySize(0));
    if (mldsa.privateKey) {
        CHECK(CCert::exportPkcs8PrivateKey(mldsa.privateKey, out) == ERET_NOTSUP);
    }
}
