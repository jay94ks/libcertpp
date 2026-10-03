#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/asyms/gost3410.hpp>
#include <certpp/crypto/hasher.hpp>
#include <string>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {

    std::vector<uint8_t> fromHex(const std::string& hex) {
        std::vector<uint8_t> out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            auto nibble = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return uint8_t(c - '0');
                if (c >= 'a' && c <= 'f') return uint8_t(c - 'a' + 10);
                return uint8_t(c - 'A' + 10);
            };
            out.push_back(uint8_t((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
        }
        return out;
    }

    SReadOnlyByteSpan spanOf(const std::vector<uint8_t>& v) {
        return SReadOnlyByteSpan(v.data(), v.size());
    }

    /* RFC 7091 section 7's known-answer values, over ECURVE_GOST256TEST. The
     * "digest" is e serialized little-endian, which is exactly what the
     * hash-to-integer step reads out of a real Streebog-256 digest yielding this e. */
    const char* RFC7091_D_LE =
        "283bec9198ce191dee7e39491f96601b"
        "c1729ad39d35ed10beb99b78de9a927a";
    const char* RFC7091_PUB =
        "0bd86fe5d8db89668f789b4e1dba8585"
        "c5508b45ec5b59d8906ddb70e2492b7f"
        "da77ff871a10fbdf2766d293c5d164af"
        "bb3c7b973a41c885d11d70d689b4f126";
    const char* RFC7091_E_LE =
        "e53e042b67e6ec678e2e02b12a0352ce"
        "1fc6eee0529cc088119ad872b3c1fb2d";
    const char* RFC7091_SIG_SR =
        "01456c64ba4642a1653c235a98a60249"
        "bcd6d3f746b631df928014f6c5bf9c40"
        "41aa28d2f1ab148280cd9ed56feda419"
        "74053554a42767b83ad043fd39dc0493";

    /* RFC 9215 appendix D.1: the private key, the certified public key, the signed
     * tbsCertificate, and its signature. */
    const char* D1_D_LE =
        "283bec9198ce191dee7e39491f96601b"
        "c1729ad39d35ed10beb99b78de9a927a";
    const char* D1_PUB =
        "0bd86fe5d8db89668f789b4e1dba8585"
        "c5508b45ec5b59d8906ddb70e2492b7f"
        "da77ff871a10fbdf2766d293c5d164af"
        "bb3c7b973a41c885d11d70d689b4f126";
    const char* D1_SIG =
        "4d53f012fe081776507d4d9bb81f00ef"
        "db4eefd4ab83bac4bacf735173cfa81c"
        "41aa28d2f1ab148280cd9ed56feda419"
        "74053554a42767b83ad043fd39dc0493";
    const char* D1_TBS =
        "3081dba00302010202010a300a06082a"
        "8503070101030230123110300e060355"
        "040313074578616d706c653020170d30"
        "31303130313030303030305a180f3230"
        "3530313233313030303030305a301231"
        "10300e060355040313074578616d706c"
        "653066301f06082a8503070101010130"
        "1306072a85030202230006082a850307"
        "0101020203430004400bd86fe5d8db89"
        "668f789b4e1dba8585c5508b45ec5b59"
        "d8906ddb70e2492b7fda77ff871a10fb"
        "df2766d293c5d164afbb3c7b973a41c8"
        "85d11d70d689b4f126a3133011300f06"
        "03551d130101ff040530030101ff";

    /* RFC 9215 appendix D.2: the private key, the certified public key, the signed
     * tbsCertificate, and its signature. */
    const char* D2_D_LE =
        "c12eb625431f045cb818be803fc8870b"
        "c1729ad39d35ed10beb99b78de9a923a";
    const char* D2_PUB =
        "742795d4bee884ddf2850fec03ea3faf"
        "1844e01d9da60b645093a55e26dfc399"
        "78f596cf4d4d0c6cf1d18943d94493d1"
        "6b9ec0a16d512d2e127cc4691a6318e2";
    const char* D2_SIG =
        "140b4da9124b09cb0d5ce928ee874273"
        "a310129492ec0e29369e3b791248578c"
        "1d0e1da5be347c6f1b5256c7aeac200a"
        "d64ac77a6f5b3a0e097318e7ae6ee769";
    const char* D2_TBS =
        "3081d3a00302010202010a300a06082a"
        "8503070101030230123110300e060355"
        "040313074578616d706c653020170d30"
        "31303130313030303030305a180f3230"
        "3530313233313030303030305a301231"
        "10300e060355040313074578616d706c"
        "65305e301706082a8503070101010130"
        "0b06092a850307010201010103430004"
        "40742795d4bee884ddf2850fec03ea3f"
        "af1844e01d9da60b645093a55e26dfc3"
        "9978f596cf4d4d0c6cf1d18943d94493"
        "d16b9ec0a16d512d2e127cc4691a6318"
        "e2a3133011300f0603551d130101ff04"
        "0530030101ff";

    /* RFC 9215 appendix D.3: the private key, the certified public key, the signed
     * tbsCertificate, and its signature. */
    const char* D3_D_LE =
        "d48da11f826729c6dfaa18fd7b6b63a2"
        "14277e82d2da223356a000223b12e872"
        "20108b508e50e70e70694651e8a09130"
        "c9d75677d43609a41b24aead8a04a60b";
    const char* D3_PUB =
        "e1ef30d52c6133ddd99d1d5c41455cf7"
        "df4d8b4c925bbc69af1433d15658515a"
        "dd2146850c325c5b81c133be655aa8c4"
        "d440e7b98a8d59487b0c7696bcc55d11"
        "ecbe7736a9ec357ff2fd39931f4e114c"
        "b8cda359270ac7f0e7ff43d9419419ea"
        "61fd2ab77f5d9f63523d3b50a04f63e2"
        "a0cf51b7c13adc21560f0bd40cc9c737";
    const char* D3_SIG =
        "415703d892f1a5f3f68c4353189a7ee2"
        "07b80b5631ef9d49529a4d6b542c2cfa"
        "15aa2eacf11f470fde7d954856903c35"
        "fd8f955ef300d95c77534a724a0eee70"
        "2f86fa60a081091a23dd795e1e3c689e"
        "e512a3c82ee0dcc2643c78eea8fcacd3"
        "5492558486b20f1c9ec197c906998502"
        "60c93bcbcd9c5c3317e19344e173ae36";
    const char* D3_TBS =
        "30820116a00302010202010b300a0608"
        "2a8503070101030330123110300e0603"
        "55040313074578616d706c653020170d"
        "3031303130313030303030305a180f32"
        "303530313233313030303030305a3012"
        "3110300e060355040313074578616d70"
        "6c653081a0301706082a850307010101"
        "02300b06092a85030701020102000381"
        "8400048180e1ef30d52c6133ddd99d1d"
        "5c41455cf7df4d8b4c925bbc69af1433"
        "d15658515add2146850c325c5b81c133"
        "be655aa8c4d440e7b98a8d59487b0c76"
        "96bcc55d11ecbe7736a9ec357ff2fd39"
        "931f4e114cb8cda359270ac7f0e7ff43"
        "d9419419ea61fd2ab77f5d9f63523d3b"
        "50a04f63e2a0cf51b7c13adc21560f0b"
        "d40cc9c737a3133011300f0603551d13"
        "0101ff040530030101ff";

    /* Every parameter set, with the digest length RFC 7091 section 5.2 pairs with it. */
    struct SParamSet {
        EEcKnownCurves curve;
        EAsymmetrics algorithm;
        EHashers hash;
        size_t halfLen;
        const char* name;
    };

    const SParamSet PARAM_SETS[] = {
        { ECURVE_GOST256TEST, EASYM_GOST256TEST, EHASH_STREEBOG256, 32, "GOST256TEST" },
        { ECURVE_GOST256A,    EASYM_GOST256A,    EHASH_STREEBOG256, 32, "GOST256A" },
        { ECURVE_GOST256B,    EASYM_GOST256B,    EHASH_STREEBOG256, 32, "GOST256B" },
        { ECURVE_GOST256C,    EASYM_GOST256C,    EHASH_STREEBOG256, 32, "GOST256C" },
        { ECURVE_GOST256D,    EASYM_GOST256D,    EHASH_STREEBOG256, 32, "GOST256D" },
        { ECURVE_GOST512TEST, EASYM_GOST512TEST, EHASH_STREEBOG512, 64, "GOST512TEST" },
        { ECURVE_GOST512A,    EASYM_GOST512A,    EHASH_STREEBOG512, 64, "GOST512A" },
        { ECURVE_GOST512B,    EASYM_GOST512B,    EHASH_STREEBOG512, 64, "GOST512B" },
        { ECURVE_GOST512C,    EASYM_GOST512C,    EHASH_STREEBOG512, 64, "GOST512C" },
    };

    /* Hashes message with the parameter set's paired Streebog length. */
    std::vector<uint8_t> digestOf(EHashers which, const std::vector<uint8_t>& message) {
        IHasherPtr hasher;
        REQUIRE(IHasher::create(which, hasher) == ERET_OK);

        hasher->push(spanOf(message));

        std::vector<uint8_t> out(hasher->byteWidth());
        REQUIRE(hasher->finish(SByteSpan(out.data(), out.size())));
        return out;
    }

    /* Verifies signature over message's digest with the public key blob, on one curve. */
    ERetCode verifyBlob(
        EEcKnownCurves curve, EHashers hash, const char* pubHex, const char* msgHex,
        const char* sigHex
    ) {
        CGost3410 algorithm(curve);

        const std::vector<uint8_t> pubBytes = fromHex(pubHex);
        IPublicKeyPtr pub = algorithm.createPublicKey(spanOf(pubBytes));
        REQUIRE(pub);

        IAsymmetricContextPtr ctx = algorithm.createContext();
        REQUIRE(ctx);
        ctx->keyPair(pub, nullptr);

        const std::vector<uint8_t> digest = digestOf(hash, fromHex(msgHex));
        const std::vector<uint8_t> sig = fromHex(sigHex);

        return ctx->verify(spanOf(digest), spanOf(sig));
    }

} // namespace

/* RFC 7091 section 7's worked example. The RFC gives e directly rather than a message, so the
 * digest fed in here is e itself serialized little-endian -- the one and only thing a real
 * Streebog-256 digest yielding that e could look like, given GOST's hash-to-integer rule.
 *
 * This is the only published (r, s) pair available for the scheme, and it is what rules out an
 * implementation that is merely self-consistent: the nonce k is random, so a round trip can
 * never catch a wrong verification equation or a swapped signature half. */
TEST_CASE("GOST R 34.10-2012 verifies RFC 7091 section 7's example signature") {
    CGost3410 algorithm(ECURVE_GOST256TEST);

    const std::vector<uint8_t> pubBytes = fromHex(RFC7091_PUB);
    IPublicKeyPtr pub = algorithm.createPublicKey(spanOf(pubBytes));
    REQUIRE(pub);

    // --> The private key's own public point must come out as the RFC's verification key.
    const std::vector<uint8_t> privBytes = fromHex(RFC7091_D_LE);
    IPrivateKeyPtr priv = algorithm.createPrivateKey(spanOf(privBytes));
    REQUIRE(priv);
    CHECK(algorithm.checkPrivateKey(priv) == ERET_OK);
    CHECK(priv->publicKey()->compare(pub) == 0);

    // --> And the public key round-trips through the RFC 9215 section 2.4 encoding.
    COctet reEncoded;
    REQUIRE(pub->serialize(reEncoded) == ERET_OK);
    CHECK(std::vector<uint8_t>(reEncoded.toPtr(), reEncoded.toPtr() + reEncoded.size()) == pubBytes);

    IAsymmetricContextPtr ctx = algorithm.createContext();
    ctx->keyPair(pub, priv);
    CHECK(ctx->sizeOfSign() == 64);
    CHECK(ctx->sizeOfDigest() == 32);

    const std::vector<uint8_t> digest = fromHex(RFC7091_E_LE);
    const std::vector<uint8_t> sig = fromHex(RFC7091_SIG_SR);

    CHECK(ctx->verify(spanOf(digest), spanOf(sig)) == ERET_OK);

    SUBCASE("a tampered signature byte is rejected") {
        for (size_t i : { size_t(0), size_t(31), size_t(32), size_t(63) }) {
            CAPTURE(i);
            std::vector<uint8_t> bad = sig;
            bad[i] ^= 0x01;
            CHECK(ctx->verify(spanOf(digest), spanOf(bad)) != ERET_OK);
        }
    }

    SUBCASE("swapping the two halves is rejected, pinning the s||r order") {
        std::vector<uint8_t> swapped(sig.begin() + 32, sig.end());
        swapped.insert(swapped.end(), sig.begin(), sig.begin() + 32);
        CHECK(ctx->verify(spanOf(digest), spanOf(swapped)) != ERET_OK);
    }

    SUBCASE("reading the digest big-endian is rejected, pinning GOST's hash-to-integer rule") {
        std::vector<uint8_t> reversed(digest.rbegin(), digest.rend());
        CHECK(ctx->verify(spanOf(reversed), spanOf(sig)) != ERET_OK);
    }

    SUBCASE("a signature of the wrong length is rejected") {
        CHECK(ctx->verify(spanOf(digest), SReadOnlyByteSpan(sig.data(), 63)) != ERET_OK);
    }
}

/* RFC 9215 appendix D's three test certificates, verified end to end: Streebog over the real
 * tbsCertificate bytes, then GOST R 34.10-2012 against the certificate's own public key. These
 * cover both digest lengths, three parameter sets, and -- because every byte comes off the
 * wire -- the public-key and signature byte orders at once. */
TEST_CASE("GOST R 34.10-2012 verifies RFC 9215 appendix D's test certificates") {
    SUBCASE("D.1, the 256-bit test parameter set") {
        CHECK(verifyBlob(ECURVE_GOST256TEST, EHASH_STREEBOG256, D1_PUB, D1_TBS, D1_SIG) == ERET_OK);
    }

    SUBCASE("D.2, id-tc26-gost-3410-2012-256-paramSetA") {
        CHECK(verifyBlob(ECURVE_GOST256A, EHASH_STREEBOG256, D2_PUB, D2_TBS, D2_SIG) == ERET_OK);
    }

    SUBCASE("D.3, id-tc26-gost-3410-2012-512-paramSetTest") {
        CHECK(verifyBlob(ECURVE_GOST512TEST, EHASH_STREEBOG512, D3_PUB, D3_TBS, D3_SIG) == ERET_OK);
    }
}

/* One flipped message bit must break each certificate's signature -- the control that proves
 * the test above is actually hashing the tbsCertificate rather than accepting anything. */
TEST_CASE("GOST R 34.10-2012 rejects a tampered message") {
    struct SCase {
        EEcKnownCurves curve;
        EHashers hash;
        const char* pub;
        const char* tbs;
        const char* sig;
        const char* name;
    };

    const SCase cases[] = {
        { ECURVE_GOST256TEST, EHASH_STREEBOG256, D1_PUB, D1_TBS, D1_SIG, "D.1" },
        { ECURVE_GOST256A,    EHASH_STREEBOG256, D2_PUB, D2_TBS, D2_SIG, "D.2" },
        { ECURVE_GOST512TEST, EHASH_STREEBOG512, D3_PUB, D3_TBS, D3_SIG, "D.3" },
    };

    for (const SCase& c : cases) {
        CAPTURE(c.name);

        CGost3410 algorithm(c.curve);

        const std::vector<uint8_t> pubBytes = fromHex(c.pub);
        IPublicKeyPtr pub = algorithm.createPublicKey(spanOf(pubBytes));
        REQUIRE(pub);

        IAsymmetricContextPtr ctx = algorithm.createContext();
        ctx->keyPair(pub, nullptr);

        std::vector<uint8_t> message = fromHex(c.tbs);
        message[message.size() / 2] ^= 0x01;

        const std::vector<uint8_t> digest = digestOf(c.hash, message);
        const std::vector<uint8_t> sig = fromHex(c.sig);

        CHECK(ctx->verify(spanOf(digest), spanOf(sig)) != ERET_OK);
    }
}

/* The wrong public key, on the right curve, must fail. RFC 9215 appendix D.1 happens to use the
 * same key as RFC 7091 section 7, so the second key here is built from the scalar d = 2 on the
 * same curve rather than taken from a vector. */
TEST_CASE("GOST R 34.10-2012 rejects a signature verified with the wrong public key") {
    CGost3410 algorithm(ECURVE_GOST256TEST);

    std::vector<uint8_t> scalar(32, 0x00);
    scalar[0] = 0x02; // d = 2, little-endian

    IPrivateKeyPtr other = algorithm.createPrivateKey(spanOf(scalar));
    REQUIRE(other);
    REQUIRE(algorithm.checkPrivateKey(other) == ERET_OK);

    COctet otherPub;
    REQUIRE(other->publicKey()->serialize(otherPub) == ERET_OK);

    IAsymmetricContextPtr ctx = algorithm.createContext();
    ctx->keyPair(other->publicKey(), nullptr);

    const std::vector<uint8_t> digest = digestOf(EHASH_STREEBOG256, fromHex(D1_TBS));
    const std::vector<uint8_t> sig = fromHex(D1_SIG);

    // --> The same signature verifies under the certificate's own key and fails under this one.
    CHECK(verifyBlob(ECURVE_GOST256TEST, EHASH_STREEBOG256, D1_PUB, D1_TBS, D1_SIG) == ERET_OK);
    CHECK(ctx->verify(spanOf(digest), spanOf(sig)) != ERET_OK);
}

TEST_CASE("GOST R 34.10-2012 signs and verifies on a freshly generated key, on every parameter set") {
    for (const SParamSet& set : PARAM_SETS) {
        CAPTURE(set.name);

        CGost3410 algorithm(set.curve);
        REQUIRE(algorithm.keySizes().size() == 1);
        CHECK(algorithm.keySizes()[0].includes(set.halfLen * 8));

        SKeyPair pair;
        ERetCode rc = ERET_AGAIN;
        for (int attempt = 0; attempt < 4 && rc == ERET_AGAIN; ++attempt) {
            rc = algorithm.generateKeyPair(set.halfLen * 8, pair);
        }
        REQUIRE(rc == ERET_OK);
        REQUIRE(!pair.empty());
        CHECK(pair.publicKey->algorithm() == set.algorithm);
        CHECK(pair.privateKey->algorithm() == set.algorithm);
        CHECK(algorithm.checkPrivateKey(pair.privateKey) == ERET_OK);

        // --> Both halves survive a serialize/parse round trip, and the private half's
        // re-derived public point still matches.
        COctet pubBlob, privBlob;
        REQUIRE(pair.publicKey->serialize(pubBlob) == ERET_OK);
        REQUIRE(pair.privateKey->serialize(privBlob) == ERET_OK);
        CHECK(pubBlob.size() == set.halfLen * 2);
        CHECK(privBlob.size() == set.halfLen);

        // --> toSpan() rather than the COctet overload: the derived class's own
        // createPublicKey()/createPrivateKey() hide IAsymmetric's COctet convenience overloads,
        // same as CEcdsa's do.
        IPublicKeyPtr reloadedPub = algorithm.createPublicKey(pubBlob.toSpan());
        IPrivateKeyPtr reloadedPriv = algorithm.createPrivateKey(privBlob.toSpan());
        REQUIRE(reloadedPub);
        REQUIRE(reloadedPriv);
        CHECK(reloadedPub->compare(pair.publicKey) == 0);
        CHECK(reloadedPriv->compare(pair.privateKey) == 0);
        CHECK(reloadedPriv->publicKey()->compare(pair.publicKey) == 0);

        const std::vector<uint8_t> message = fromHex(
            "4745524d414e204752454554494e47532046524f4d2074686520746573742073756974652e");
        const std::vector<uint8_t> digest = digestOf(set.hash, message);

        IAsymmetricContextPtr ctx = algorithm.createContext();
        ctx->keyPair(pair);
        REQUIRE(ctx->sizeOfSign() == set.halfLen * 2);
        REQUIRE(ctx->sizeOfDigest() == set.halfLen);

        std::vector<uint8_t> sig(ctx->sizeOfSign());
        SByteSpan sigSpan(sig.data(), sig.size());
        REQUIRE(ctx->sign(spanOf(digest), sigSpan) == ERET_OK);
        REQUIRE(sigSpan.size == set.halfLen * 2);

        CHECK(ctx->verify(spanOf(digest), SReadOnlyByteSpan(sigSpan.data, sigSpan.size)) == ERET_OK);

        // --> Signing twice must give different signatures: the nonce is fresh each time.
        std::vector<uint8_t> sig2(ctx->sizeOfSign());
        SByteSpan sig2Span(sig2.data(), sig2.size());
        REQUIRE(ctx->sign(spanOf(digest), sig2Span) == ERET_OK);
        CHECK(sig != sig2);
        CHECK(ctx->verify(spanOf(digest), SReadOnlyByteSpan(sig2Span.data, sig2Span.size)) == ERET_OK);

        // --> A tampered signature, and a tampered message, both fail.
        std::vector<uint8_t> badSig = sig;
        badSig[0] ^= 0x80;
        CHECK(ctx->verify(spanOf(digest), spanOf(badSig)) != ERET_OK);

        std::vector<uint8_t> badMessage = message;
        badMessage[0] ^= 0x01;
        const std::vector<uint8_t> badDigest = digestOf(set.hash, badMessage);
        CHECK(ctx->verify(spanOf(badDigest), spanOf(sig)) != ERET_OK);

        // --> And a signature from an independently generated key on the same curve fails.
        SKeyPair other;
        rc = ERET_AGAIN;
        for (int attempt = 0; attempt < 4 && rc == ERET_AGAIN; ++attempt) {
            rc = algorithm.generateKeyPair(set.halfLen * 8, other);
        }
        REQUIRE(rc == ERET_OK);

        IAsymmetricContextPtr otherCtx = algorithm.createContext();
        otherCtx->keyPair(other.publicKey, nullptr);
        CHECK(otherCtx->verify(spanOf(digest), spanOf(sig)) != ERET_OK);
    }
}

TEST_CASE("GOST R 34.10-2012 is reachable through IAsymmetric::builtIn()") {
    for (const SParamSet& set : PARAM_SETS) {
        CAPTURE(set.name);

        IAsymmetricPtr algorithm = IAsymmetric::builtIn(set.algorithm);
        REQUIRE(algorithm);
        REQUIRE(algorithm->keySizes().size() == 1);
        CHECK(algorithm->keySizes()[0].includes(set.halfLen * 8));
    }
}

TEST_CASE("GOST R 34.10-2012 rejects malformed key material") {
    CGost3410 algorithm(ECURVE_GOST256A);

    // --> Wrong-length blobs.
    const std::vector<uint8_t> shortBlob(63, 0x11);
    CHECK(!algorithm.createPublicKey(spanOf(shortBlob)));
    CHECK(!algorithm.createPrivateKey(spanOf(shortBlob)));

    // --> An all-zero private scalar is out of the required 0 < d < q range.
    const std::vector<uint8_t> zeroScalar(32, 0x00);
    CHECK(!algorithm.createPrivateKey(spanOf(zeroScalar)));

    // --> An all-0xFF "point" is not on the curve.
    const std::vector<uint8_t> offCurve(64, 0xFF);
    CHECK(!algorithm.createPublicKey(spanOf(offCurve)));

    // --> Nothing can be signed or verified without a bound key.
    IAsymmetricContextPtr ctx = algorithm.createContext();
    const std::vector<uint8_t> digest(32, 0x42);
    std::vector<uint8_t> sig(64);
    SByteSpan sigSpan(sig.data(), sig.size());
    CHECK(ctx->sign(spanOf(digest), sigSpan) == ERET_KEY_EMPTY);
    CHECK(ctx->verify(spanOf(digest), spanOf(sig)) == ERET_KEY_EMPTY);

    // --> GOST R 34.10 has no encryption operation and no key agreement here.
    IAsymmetricTransformerPtr transformer;
    CHECK(ctx->createEncrypter(transformer) == ERET_NOTSUP);
    CHECK(ctx->createDecrypter(transformer) == ERET_NOTSUP);
}
