#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <fstream>
#include <string>

using namespace certpp;
using namespace certpp::crypto;
using namespace certpp::x509;

// CPemChainFormat -- the PEM container format, and with it the whole of this library's PEM
// handling (CCert::importPem()/exportPem() are delegations to it, and tests/x509/cert.cpp
// exercises them from that side).
//
// Round-tripping this implementation against itself proves very little, so most of what follows
// reads files this library did not write: certs/openssl-*.pem were produced by OpenSSL 3.4.0 on
// the machine this was developed on -- the three real certificates from
// tests/x509/certs/implemented/ converted with `openssl x509 -inform DER`, a throwaway RSA and a
// throwaway P-256 key pair from `openssl req -x509 -newkey ...` (self-signed, CN=pem-interop-*,
// generated solely as fixtures -- the private keys in them are deliberately public and guard
// nothing), a PKCS#12 bag dumped back out with `openssl pkcs12 -nokeys`, and the same key
// encrypted both ways openssl can encrypt it. Nothing was fetched from the network.

namespace {

    constexpr const char* FIXTURE_DIR = CERTPP_TEST_DIR "/certs";
    constexpr const char* DER_DIR = CERTPP_TEST_DIR "/../certs/implemented";

    /* Reads a whole file as bytes. False if it can't be opened or is empty. */
    bool readFile(const std::string& path, std::string& out) {
        std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
        if (!file) {
            return false;
        }

        const std::streamsize size = file.tellg();
        if (size <= 0) {
            return false;
        }
        file.seekg(0, std::ios::beg);

        out.assign(static_cast<size_t>(size), '\0');
        return static_cast<bool>(file.read(&out[0], size));
    }

    std::string fixture(const char* name) {
        std::string text;
        REQUIRE(readFile(std::string(FIXTURE_DIR) + "/" + name, text));
        return text;
    }

    std::string derFile(const char* name) {
        std::string bytes;
        REQUIRE(readFile(std::string(DER_DIR) + "/" + name, bytes));
        return bytes;
    }

    SReadOnlyByteSpan bytesOf(const std::string& text) {
        return SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    }

    std::string textOf(const CBuffer& buffer) {
        return std::string(reinterpret_cast<const char*>(buffer.toPtr()), buffer.size());
    }

    /* No password at all, which is the point: every load()/save() in this file passes an empty
     * one, and the two tests that pass a real one check that it changes nothing. */
    SReadOnlyByteSpan noPassword() {
        return SReadOnlyByteSpan();
    }

    bool derEquals(const CCert& cert, const std::string& der) {
        return cert.rawData().size() == der.size()
            && std::memcmp(cert.rawData().toPtr(), der.data(), der.size()) == 0;
    }

    /* The certificate at index, or an empty one (which every check below fails on). */
    CCert certAt(const CCertCollection& col, size_t index) {
        SCertEntry entry;
        if (col.at(index, entry) != ERET_OK) {
            return CCert();
        }

        return entry.cert;
    }

    SCertEntry entryAt(const CCertCollection& col, size_t index) {
        SCertEntry entry;
        REQUIRE(col.at(index, entry) == ERET_OK);
        return entry;
    }

    /* Issues a certificate for subjectKey, signed by issuerKeyPair -- the same shape
     * tests/x509/chain.cpp and tests/x509/verify.cpp use, since only genuinely issued
     * certificates have the linkage a collection is about. */
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

    /* A root, an intermediate under it, and a leaf under that, plus the key pairs. */
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

        /* Leaf first, then intermediate, then root -- the order a chain is conventionally
         * written in a PEM bundle. */
        void fill(CCertCollection& out, bool withLeafKey = false) const {
            size_t index = 0;
            REQUIRE(out.add(leaf, withLeafKey ? leafKey.privateKey : IPrivateKeyPtr(), index)
                    == ERET_OK);
            REQUIRE(out.add(inter, index) == ERET_OK);
            REQUIRE(out.add(root, index) == ERET_OK);
        }
    };

    /* Replaces the base64 body of the index'th block with body, keeping the boundaries. */
    std::string replaceBody(const std::string& text, size_t index, const std::string& body) {
        size_t at = 0;
        for (size_t i = 0; i <= index; ++i) {
            at = text.find("-----BEGIN ", (i == 0) ? 0 : at + 1);
            REQUIRE(at != std::string::npos);
        }

        const size_t bodyStart = text.find('\n', at) + 1;
        const size_t bodyEnd = text.find("-----END ", bodyStart);
        REQUIRE(bodyEnd != std::string::npos);

        return text.substr(0, bodyStart) + body + text.substr(bodyEnd);
    }

    std::string bodyOf(const std::string& text, size_t index) {
        size_t at = 0;
        for (size_t i = 0; i <= index; ++i) {
            at = text.find("-----BEGIN ", (i == 0) ? 0 : at + 1);
            REQUIRE(at != std::string::npos);
        }

        const size_t bodyStart = text.find('\n', at) + 1;
        const size_t bodyEnd = text.find("-----END ", bodyStart);
        return text.substr(bodyStart, bodyEnd - bodyStart);
    }

} // namespace

TEST_CASE("CPemChainFormat: builtIn() hands back a PEM format that promises no secrecy") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    CHECK(format->format() == ECHAINFMT_PEM);

    // Not a convenience -- a warning. PEM has no password and no encryption, and nothing this
    // format writes is protected by one.
    CHECK_FALSE(format->needsPassword());

    // And builtIn() hands back the form that does not write private keys, so no caller gets a
    // key on disk in the clear without having asked for one in so many words.
    auto pem = std::dynamic_pointer_cast<CPemChainFormat>(format);
    REQUIRE(pem);
    CHECK_FALSE(pem->includesPrivateKeys());
    CHECK(CPemChainFormat(true).includesPrivateKeys());
}

TEST_CASE("CPemChainFormat: save()/load() round-trip every certificate byte for byte, in order") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection original;
    h.fill(original);

    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    CBuffer saved;
    REQUIRE(format->save(original, noPassword(), saved) == ERET_OK);

    const std::string text = textOf(saved);
    CHECK(IChainFormat::detect(bytesOf(text)) == ECHAINFMT_PEM);

    CCertCollection reloaded;
    REQUIRE(format->load(bytesOf(text), noPassword(), reloaded) == ERET_OK);
    REQUIRE(reloaded.count() == 3);

    for (size_t i = 0; i < 3; ++i) {
        const CCert before = certAt(original, i);
        const CCert after = certAt(reloaded, i);

        REQUIRE_FALSE(after.empty());
        CHECK(after.rawData().toSpan().sequencialEqual(before.rawData().toSpan()));
        CHECK(after.subject() == before.subject());
    }

    // The chain is still a chain on the far side, which is the point of keeping the order.
    TArray<size_t> chain;
    CHECK(reloaded.buildChain(0, chain) == ECHAINRES_OK);
    CHECK(chain.size() == 3);
    CHECK(reloaded.verifyLinks(chain) == ERET_OK);
}

TEST_CASE("CPemChainFormat: load() appends, so two containers merge rather than replace") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection original;
    h.fill(original);

    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    CBuffer saved;
    REQUIRE(format->save(original, noPassword(), saved) == ERET_OK);
    const std::string text = textOf(saved);

    // One certificate is already in the collection before either load, and has to survive both.
    CCertCollection merged;
    size_t index = 0;
    REQUIRE(merged.add(h.root, index) == ERET_OK);

    REQUIRE(format->load(bytesOf(text), noPassword(), merged) == ERET_OK);
    REQUIRE(format->load(bytesOf(text), noPassword(), merged) == ERET_OK);

    CHECK(merged.count() == 7);
    CHECK(certAt(merged, 0).subject() == h.root.subject());
    CHECK(certAt(merged, 1).subject() == h.leaf.subject());
    CHECK(certAt(merged, 4).subject() == h.leaf.subject());
    CHECK(certAt(merged, 6).subject() == h.root.subject());
}

TEST_CASE("CPemChainFormat: a container that breaks part way through leaves the collection alone") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection original;
    h.fill(original);

    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    CBuffer saved;
    REQUIRE(format->save(original, noPassword(), saved) == ERET_OK);
    const std::string text = textOf(saved);

    // The output collection is not empty to begin with, which is the only way to tell "nothing
    // was added" apart from "nothing happened".
    CCertCollection target;
    size_t index = 0;
    REQUIRE(target.add(h.root, index) == ERET_OK);

    SUBCASE("second block's payload decodes but isn't a certificate") {
        std::string body = bodyOf(text, 1);
        for (size_t i = 0; i + 1 < body.size(); ++i) {
            // Corrupt the first base64 character of the body, which lands inside the outer
            // SEQUENCE's own tag and length.
            if (body[i] != '\n') {
                body[i] = (body[i] == 'A') ? 'B' : 'A';
                break;
            }
        }

        const std::string broken = replaceBody(text, 1, body);
        CHECK(format->load(bytesOf(broken), noPassword(), target) == ERET_BADREQ);
    }

    SUBCASE("second block's payload is truncated mid-base64-group") {
        std::string body = bodyOf(text, 1);
        REQUIRE(body.size() > 40);
        body.erase(body.size() - 40);

        const std::string broken = replaceBody(text, 1, body);
        CHECK(format->load(bytesOf(broken), noPassword(), target) == ERET_BADREQ);
    }

    SUBCASE("second block's payload is short but a whole number of base64 groups") {
        // The previous subcase leaves a partial base64 group, which the decoder itself rejects.
        // This one decodes cleanly and hands up a truncated certificate, so it is the DER parse
        // that has to catch it -- two different layers, and a container is malformed either way.
        std::string body = bodyOf(text, 1);
        std::string packed;
        for (size_t i = 0; i < body.size(); ++i) {
            if (body[i] != '\n' && body[i] != '\r') {
                packed += body[i];
            }
        }

        REQUIRE(packed.size() > 16);
        REQUIRE(packed.size() % 4 == 0);
        packed.erase(packed.size() - 8);

        const std::string broken = replaceBody(text, 1, packed + "\n");
        CHECK(format->load(bytesOf(broken), noPassword(), target) == ERET_BADREQ);
    }

    SUBCASE("second block's payload isn't base64 at all") {
        const std::string broken = replaceBody(text, 1, "not base64 at all!!\n");
        CHECK(format->load(bytesOf(broken), noPassword(), target) == ERET_BADREQ);
    }

    SUBCASE("second block never ends") {
        const size_t secondBegin = text.find("-----BEGIN ", text.find("-----BEGIN ") + 1);
        REQUIRE(secondBegin != std::string::npos);
        const size_t cut = text.find("-----END ", secondBegin);
        REQUIRE(cut != std::string::npos);

        const std::string broken = text.substr(0, cut);
        CHECK(format->load(bytesOf(broken), noPassword(), target) == ERET_BADREQ);
    }

    // Whichever way it broke, the collection holds exactly what it held before.
    CHECK(target.count() == 1);
    CHECK(certAt(target, 0).subject() == h.root.subject());
}

TEST_CASE("CPemChainFormat: load() rejects what isn't a certificate container") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    CCertCollection out;

    CHECK(format->load(SReadOnlyByteSpan(), noPassword(), out) == ERET_BADREQ);

    const std::string empty;
    CHECK(format->load(bytesOf(empty), noPassword(), out) == ERET_BADREQ);

    const std::string blank = "\r\n   \t\n\n";
    CHECK(format->load(bytesOf(blank), noPassword(), out) == ERET_BADREQ);

    const std::string prose = "This file has no PEM in it whatsoever.\n";
    CHECK(format->load(bytesOf(prose), noPassword(), out) == ERET_BADREQ);

    // A file holding only a private key is well-formed PEM and still not a certificate
    // container: there is nothing for a collection to hold.
    std::string keyOnly = fixture("openssl-crossed-keys.pem");
    const size_t firstKey = keyOnly.find("-----BEGIN PRIVATE KEY-----");
    REQUIRE(firstKey != std::string::npos);
    const size_t firstKeyEnd = keyOnly.find("-----END PRIVATE KEY-----", firstKey);
    keyOnly = keyOnly.substr(
        firstKey, firstKeyEnd + std::strlen("-----END PRIVATE KEY-----\n") - firstKey);
    CHECK(format->load(bytesOf(keyOnly), noPassword(), out) == ERET_BADREQ);

    CHECK(out.empty());
}

TEST_CASE("CPemChainFormat: save() rejects an empty collection") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    CCertCollection empty;
    CBuffer out;
    CHECK(format->save(empty, noPassword(), out) == ERET_BADREQ);
}

TEST_CASE("CPemChainFormat: reads openssl's own multi-certificate bundle, byte for byte") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    const std::string bundle = fixture("openssl-bundle.pem");

    CCertCollection out;
    REQUIRE(format->load(bytesOf(bundle), noPassword(), out) == ERET_OK);
    REQUIRE(out.count() == 3);

    // The DER that comes back out of openssl's base64 is the DER that went into it -- these are
    // the same files tests/x509/realcerts.cpp reads directly.
    CHECK(derEquals(certAt(out, 0), derFile("github.com.der")));
    CHECK(derEquals(certAt(out, 1), derFile("amazon.com.der")));
    CHECK(derEquals(certAt(out, 2), derFile("sourceforge.net.der")));

    CName name;
    REQUIRE(certAt(out, 0).subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "github.com"));

    // And what this library writes out of what openssl wrote reads back identically.
    CBuffer resaved;
    REQUIRE(format->save(out, noPassword(), resaved) == ERET_OK);

    CCertCollection again;
    REQUIRE(format->load(bytesOf(textOf(resaved)), noPassword(), again) == ERET_OK);
    REQUIRE(again.count() == 3);
    CHECK(derEquals(certAt(again, 1), derFile("amazon.com.der")));
}

TEST_CASE("CPemChainFormat: CRLF line endings and trailing whitespace are PEM too") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    // Built here rather than kept as a fixture on purpose: a committed CRLF file is at the mercy
    // of whatever the checkout's line-ending normalization does to it, which would leave this
    // case silently testing LF again on another machine.
    std::string crlf;
    const std::string lf = fixture("openssl-bundle.pem");
    for (size_t i = 0; i < lf.size(); ++i) {
        if (lf[i] == '\n') {
            crlf += '\r';
        }
        crlf += lf[i];
    }
    crlf += "\r\n  \t\r\n";

    REQUIRE(crlf.find("\r\n") != std::string::npos);

    CCertCollection out;
    REQUIRE(format->load(bytesOf(crlf), noPassword(), out) == ERET_OK);
    REQUIRE(out.count() == 3);
    CHECK(derEquals(certAt(out, 0), derFile("github.com.der")));
    CHECK(derEquals(certAt(out, 2), derFile("sourceforge.net.der")));
}

TEST_CASE("CPemChainFormat: explanatory text outside the boundaries is skipped (RFC 7468 5.2)") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    const std::string annotated = fixture("openssl-annotated.pem");

    CCertCollection out;
    REQUIRE(format->load(bytesOf(annotated), noPassword(), out) == ERET_OK);
    REQUIRE(out.count() == 2);
    CHECK(derEquals(certAt(out, 0), derFile("github.com.der")));
    CHECK(derEquals(certAt(out, 1), derFile("amazon.com.der")));

    // The prose didn't leak into the PKCS#9 attributes either -- only the two keys this format
    // recognizes there are read, and neither appears in that file.
    CHECK(entryAt(out, 0).friendlyName.size() == 0);
    CHECK(entryAt(out, 1).localKeyId.empty());
}

TEST_CASE("CPemChainFormat: a single-certificate file is a container of one") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    const std::string single = fixture("openssl-single.pem");

    CCertCollection out;
    REQUIRE(format->load(bytesOf(single), noPassword(), out) == ERET_OK);
    REQUIRE(out.count() == 1);
    CHECK(derEquals(certAt(out, 0), derFile("github.com.der")));
    CHECK_FALSE(entryAt(out, 0).hasPrivateKey());
}

TEST_CASE("CPemChainFormat: keys are paired with the certificate they belong to, not the adjacent one") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    // openssl wrote both pairs; the file interleaves them crossed (RSA cert, EC key, EC cert,
    // RSA key), so anything pairing by position gets both wrong.
    const std::string crossed = fixture("openssl-crossed-keys.pem");

    CCertCollection out;
    REQUIRE(format->load(bytesOf(crossed), noPassword(), out) == ERET_OK);
    REQUIRE(out.count() == 2);

    CName name;
    REQUIRE(certAt(out, 0).subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "pem-interop-rsa"));
    CHECK(certAt(out, 0).keyAlgo() == CString("RSA"));

    REQUIRE(certAt(out, 1).subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "pem-interop-ec"));
    CHECK(certAt(out, 1).keyAlgo() == CString("EC"));

    REQUIRE(entryAt(out, 0).hasPrivateKey());
    REQUIRE(entryAt(out, 1).hasPrivateKey());

    // checkKeyPairing() signs and verifies, so this is a cryptographic statement about the
    // pairing rather than a comparison of two blobs.
    CHECK(out.checkKeyPairing(0) == ERET_OK);
    CHECK(out.checkKeyPairing(1) == ERET_OK);
}

TEST_CASE("CPemChainFormat: openssl's traditional SEC1 \"EC PRIVATE KEY\" block attaches too") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    const std::string text = fixture("openssl-ec-traditional.pem");
    REQUIRE(text.find("-----BEGIN EC PRIVATE KEY-----") != std::string::npos);

    CCertCollection out;
    REQUIRE(format->load(bytesOf(text), noPassword(), out) == ERET_OK);
    REQUIRE(out.count() == 1);
    REQUIRE(entryAt(out, 0).hasPrivateKey());
    CHECK(out.checkKeyPairing(0) == ERET_OK);
}

TEST_CASE("CPemChainFormat: a password-encrypted key block is unsupported, not malformed") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    CCertCollection out;

    // PKCS#8 EncryptedPrivateKeyInfo. The file is perfectly well-formed PEM; what it needs is a
    // password, which this format has no way to accept.
    const std::string pkcs8 = fixture("openssl-encrypted-pkcs8.pem");
    REQUIRE(pkcs8.find("-----BEGIN ENCRYPTED PRIVATE KEY-----") != std::string::npos);
    CHECK(format->load(bytesOf(pkcs8), noPassword(), out) == ERET_NOTSUP);

    // RFC 1421's legacy headers, which openssl still writes for a traditional key.
    const std::string legacy = fixture("openssl-encrypted-legacy.pem");
    REQUIRE(legacy.find("Proc-Type: 4,ENCRYPTED") != std::string::npos);
    CHECK(format->load(bytesOf(legacy), noPassword(), out) == ERET_NOTSUP);

    // Neither added the certificate that sits in front of the key, since a load that fails adds
    // nothing at all.
    CHECK(out.empty());

    // And passing the password openssl encrypted them with changes nothing: this format ignores
    // it outright rather than half-using it.
    const std::string password = "x";
    CHECK(format->load(bytesOf(pkcs8), bytesOf(password), out) == ERET_NOTSUP);
    CHECK(out.empty());
}

TEST_CASE("CPemChainFormat: a certificate whose algorithm this library can't resolve still loads") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    // A real certificate with one byte of its SubjectPublicKeyInfo algorithm OID changed, so the
    // OID is the same length (the DER stays well-formed) but names nothing this library knows:
    // rsaEncryption 1.2.840.113549.1.1.1 becomes 1.2.840.113549.1.1.99.
    std::string der = derFile("amazon.com.der");
    const char rsaOid[] = { 0x2A, '\x86', 0x48, '\x86', '\xF7', 0x0D, 0x01, 0x01, 0x01 };
    const size_t at = der.find(std::string(rsaOid, sizeof(rsaOid)));
    REQUIRE(at != std::string::npos);
    der[at + sizeof(rsaOid) - 1] = 0x63;

    CString body;
    REQUIRE(CBase64::encode(body, bytesOf(der), true));

    std::string text = "-----BEGIN CERTIFICATE-----\n";
    text.append(body.toPtr(), body.size());
    text += "-----END CERTIFICATE-----\n";

    CCertCollection out;
    REQUIRE(format->load(bytesOf(text), noPassword(), out) == ERET_OK);
    REQUIRE(out.count() == 1);

    // Loaded, not rejected: the file genuinely holds this certificate, and everything about it
    // but its key is still readable. What it cannot do is produce a key.
    const CCert cert = certAt(out, 0);
    CHECK(cert.keyAlgo() == CString("1.2.840.113549.1.1.99"));
    CHECK_FALSE(cert.publicKey());

    CName name;
    REQUIRE(cert.subject().tryGet(ENAME_CN, name));
    CHECK(name == CName(ENAME_CN, "*.peg.a2z.com"));
}

TEST_CASE("CPemChainFormat: private keys are written only when the caller asks, and then in the clear") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    h.fill(col, /*withLeafKey=*/true);
    REQUIRE(entryAt(col, 0).hasPrivateKey());

    // The default, and what builtIn() returns: certificates only. A key held by the collection
    // does not reach the file.
    CBuffer certsOnly;
    REQUIRE(CPemChainFormat().save(col, noPassword(), certsOnly) == ERET_OK);
    CHECK(textOf(certsOnly).find("PRIVATE KEY") == std::string::npos);

    CCertCollection reloaded;
    REQUIRE(CPemChainFormat().load(bytesOf(textOf(certsOnly)), noPassword(), reloaded) == ERET_OK);
    REQUIRE(reloaded.count() == 3);
    CHECK_FALSE(entryAt(reloaded, 0).hasPrivateKey());

    // Asked for explicitly, the key is there -- as plaintext DER in base64, which is all PEM has.
    CBuffer withKeys;
    REQUIRE(CPemChainFormat(true).save(col, noPassword(), withKeys) == ERET_OK);
    const std::string text = textOf(withKeys);
    CHECK(text.find("-----BEGIN EC PRIVATE KEY-----") != std::string::npos);

    CCertCollection roundTripped;
    REQUIRE(CPemChainFormat().load(bytesOf(text), noPassword(), roundTripped) == ERET_OK);
    REQUIRE(roundTripped.count() == 3);
    REQUIRE(entryAt(roundTripped, 0).hasPrivateKey());
    CHECK(roundTripped.checkKeyPairing(0) == ERET_OK);
    CHECK_FALSE(entryAt(roundTripped, 1).hasPrivateKey());

    // A password does not change any of that, in either direction.
    const std::string password = "this buys nothing";
    CBuffer withPassword;
    REQUIRE(CPemChainFormat(true).save(col, bytesOf(password), withPassword) == ERET_OK);
    CHECK(textOf(withPassword) == text);
}

TEST_CASE("CPemChainFormat: an entry's key that isn't its certificate's own is refused, not written") {
    SHierarchy h;
    REQUIRE(h.build());

    CCertCollection col;
    size_t index = 0;
    REQUIRE(col.add(h.leaf, h.rootKey.privateKey, index) == ERET_OK);

    CBuffer out;
    CHECK(CPemChainFormat(true).save(col, noPassword(), out) == ERET_KEY_ERROR);

    // Certificates only, and the mismatch is simply never consulted.
    CHECK(CPemChainFormat().save(col, noPassword(), out) == ERET_OK);
    CHECK(textOf(out).find("PRIVATE KEY") == std::string::npos);
}

TEST_CASE("CPemChainFormat: PKCS#9 attributes survive, in openssl's own Bag Attributes shape") {
    IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
    REQUIRE(format);

    SUBCASE("openssl's own pkcs12 -nokeys dump is read back") {
        const std::string text = fixture("openssl-bagattrs.pem");

        CCertCollection out;
        REQUIRE(format->load(bytesOf(text), noPassword(), out) == ERET_OK);
        REQUIRE(out.count() == 1);

        const SCertEntry entry = entryAt(out, 0);
        CHECK(entry.friendlyName == CString("libcertpp pem interop"));
        REQUIRE(entry.localKeyId.size() == 20);
        CHECK(out.findByFriendlyName(CString("libcertpp pem interop")) == 0);
        CHECK(out.findByLocalKeyId(entry.localKeyId.toSpan()) == 0);
    }

    SUBCASE("and what this library writes is read back the same way") {
        SHierarchy h;
        REQUIRE(h.build());

        CCertCollection col;
        h.fill(col);

        const uint8_t keyId[] = { 0x01, 0x23, 0xAB, 0xFF, 0x00 };
        REQUIRE(col.setFriendlyName(0, CString("my leaf")) == ERET_OK);
        REQUIRE(col.setLocalKeyId(0, SReadOnlyByteSpan(keyId, sizeof(keyId))) == ERET_OK);
        REQUIRE(col.setFriendlyName(2, CString("the root")) == ERET_OK);

        CBuffer saved;
        REQUIRE(format->save(col, noPassword(), saved) == ERET_OK);

        const std::string text = textOf(saved);
        CHECK(text.find("Bag Attributes") != std::string::npos);
        CHECK(text.find("    friendlyName: my leaf\n") != std::string::npos);
        CHECK(text.find("    localKeyID: 01 23 AB FF 00\n") != std::string::npos);

        CCertCollection out;
        REQUIRE(format->load(bytesOf(text), noPassword(), out) == ERET_OK);
        REQUIRE(out.count() == 3);
        CHECK(entryAt(out, 0).friendlyName == CString("my leaf"));
        CHECK(entryAt(out, 0).localKeyId.toSpan().sequencialEqual(
            SReadOnlyByteSpan(keyId, sizeof(keyId))));
        CHECK(entryAt(out, 1).friendlyName.size() == 0);
        CHECK(entryAt(out, 1).localKeyId.empty());
        CHECK(entryAt(out, 2).friendlyName == CString("the root"));
    }

    SUBCASE("a friendlyName that can't be written on one line is refused rather than mangled") {
        SHierarchy h;
        REQUIRE(h.build());

        CCertCollection col;
        h.fill(col);
        REQUIRE(col.setFriendlyName(1, CString("two\nlines")) == ERET_OK);

        CBuffer out;
        CHECK(format->save(col, noPassword(), out) == ERET_BADREQ);
    }
}

TEST_CASE("CPemChainFormat: CCert's own PEM methods agree with the format they delegate to") {
    const std::string der = derFile("github.com.der");

    CCert cert;
    REQUIRE(cert.importDer(COctet(bytesOf(der))) == ERET_OK);

    COctet pem;
    REQUIRE(cert.exportPem(pem) == ERET_OK);

    CCertCollection one;
    size_t index = 0;
    REQUIRE(one.add(cert, index) == ERET_OK);

    CBuffer saved;
    REQUIRE(CPemChainFormat().save(one, noPassword(), saved) == ERET_OK);

    // Byte-identical: exportPem() is this format saving a one-entry collection, not a second
    // implementation that happens to agree.
    REQUIRE(pem.size() == saved.size());
    CHECK(std::memcmp(pem.toPtr(), saved.toPtr(), saved.size()) == 0);

    // And the file openssl wrote for the same certificate imports through CCert as well.
    CCert fromOpenssl;
    const std::string single = fixture("openssl-single.pem");
    REQUIRE(fromOpenssl.importPem(COctet(bytesOf(single))) == ERET_OK);
    CHECK(fromOpenssl.equals(cert));
}
