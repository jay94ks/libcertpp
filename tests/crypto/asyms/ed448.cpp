#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    constexpr SKeySize TEST_KEY_SIZE = 456;

    const SKeyPair& sharedTestKeyPair() {
        static SKeyPair pair = [] {
            IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
            SKeyPair result;
            ed->generateKeyPair(TEST_KEY_SIZE, result);
            return result;
        }();

        return pair;
    }

    int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    std::vector<uint8_t> hexToBytes(const char* hex) {
        std::vector<uint8_t> out;
        size_t len = std::char_traits<char>::length(hex);
        for (size_t i = 0; i + 1 < len; i += 2) {
            out.push_back(uint8_t((hexVal(hex[i]) << 4) | hexVal(hex[i + 1])));
        }
        return out;
    }
}

// RFC 8032 Section 7.4, TEST 1: an empty message. EdDSA signing is fully deterministic (no
// per-signature randomness, unlike DSA/ECDSA), so reproducing this exact signature validates
// the whole pipeline at once -- field/point arithmetic, the derived curve/group constants
// (including the base point, itself derived from this same vector rather than transcribed --
// see ed448.cpp's basePoint() comment), key clamping, the dom4 prefix, and SHAKE256 itself.
TEST_CASE("Ed448: RFC 8032 TEST 1 vector (empty message)") {
    auto secretKey = hexToBytes(
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    auto publicKey = hexToBytes(
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
    auto signature = hexToBytes(
        "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"
        "ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");

    REQUIRE(secretKey.size() == 57);
    REQUIRE(publicKey.size() == 57);
    REQUIRE(signature.size() == 114);

    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    REQUIRE(ed);

    IPrivateKeyPtr priv = ed->createPrivateKey(SReadOnlyByteSpan(secretKey.data(), secretKey.size()));
    REQUIRE(priv);

    COctet derivedPub;
    REQUIRE(priv->publicKey()->serialize(derivedPub) == ERET_OK);
    REQUIRE(derivedPub.size() == 57);
    CHECK(derivedPub.toSpan().sequencialEqual(SReadOnlyByteSpan(publicKey.data(), publicKey.size())));

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(priv->publicKey(), priv);

    TArray<uint8_t> producedSignature;
    producedSignature.resize(ctx->sizeOfSign());
    SByteSpan producedSignatureSpan(producedSignature.begin(), producedSignature.size());
    REQUIRE(ctx->sign(SReadOnlyByteSpan(nullptr, 0), producedSignatureSpan) == ERET_OK);
    producedSignature.resize(producedSignatureSpan.size);
    REQUIRE(producedSignature.size() == 114);

    for (size_t i = 0; i < 114; ++i) {
        CHECK(producedSignature[i] == signature[i]);
    }

    CHECK(ctx->verify(SReadOnlyByteSpan(nullptr, 0),
        SReadOnlyByteSpan(signature.data(), signature.size())) == ERET_OK);
}

TEST_CASE("Ed448: builtIn(EASYM_ED448) returns a usable algorithm instance") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    REQUIRE(ed);

    bool acceptsTestSize = false;
    for (size_t i = 0; i < ed->keySizes().size(); ++i) {
        if (ed->keySizes()[i].includes(TEST_KEY_SIZE)) {
            acceptsTestSize = true;
        }
    }
    CHECK(acceptsTestSize);
}

TEST_CASE("Ed448: generateKeyPair produces a matched, usable key pair") {
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);
    REQUIRE(pair.publicKey->keySize() == TEST_KEY_SIZE);
    REQUIRE(pair.privateKey->keySize() == TEST_KEY_SIZE);
    CHECK(pair.privateKey->publicKey()->compare(pair.publicKey) == 0);
}

TEST_CASE("Ed448: generateKeyPair rejects a key size other than 456") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    SKeyPair pair;
    ed->generateKeyPair(256, pair);
    CHECK(pair.empty());
}

TEST_CASE("Ed448: public/private key round-trips through serialize()/create*Key()") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    COctet pubBytes, privBytes;
    REQUIRE(pair.publicKey->serialize(pubBytes) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privBytes) == ERET_OK);

    CHECK(pubBytes.size() == 57);
    CHECK(privBytes.size() == 57);

    IPublicKeyPtr parsedPub = ed->createPublicKey(pubBytes);
    IPrivateKeyPtr parsedPriv = ed->createPrivateKey(privBytes);

    REQUIRE(parsedPub);
    REQUIRE(parsedPriv);
    CHECK(parsedPub->compare(pair.publicKey) == 0);
    CHECK(parsedPriv->compare(pair.privateKey) == 0);
}

TEST_CASE("Ed448: createPublicKey rejects a point not on the curve") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);

    // y = 2 has no valid x on edwards448 for either sign bit (verified offline: (y^2-1)/(d*y^2-1)
    // is not a quadratic residue mod p) -- deterministically invalid, unlike flipping a random bit
    // of a real encoded point, which has roughly even odds of still landing on a valid point
    // (about half of field elements are quadratic residues).
    uint8_t invalid[57] = { 2 };

    IPublicKeyPtr parsed = ed->createPublicKey(SReadOnlyByteSpan(invalid, sizeof(invalid)));
    CHECK_FALSE(parsed);
}

TEST_CASE("Ed448: sign/verify round-trips for a non-empty message") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    const uint8_t message[] = "certpp Ed448 test message";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(ctx->sign(messageSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);
    REQUIRE(signature.size() == 114);
    CHECK(ctx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

    uint8_t tamperedMessage[sizeof(message) - 1];
    for (size_t i = 0; i < sizeof(tamperedMessage); ++i) {
        tamperedMessage[i] = message[i];
    }
    tamperedMessage[0] ^= 0xFF;

    CHECK(ctx->verify(SReadOnlyByteSpan(tamperedMessage, sizeof(tamperedMessage)),
        SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("Ed448: signing is deterministic (same seed and message produce the same signature)") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    const uint8_t message[] = "deterministic";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> sig1, sig2;
    sig1.resize(ctx->sizeOfSign());
    sig2.resize(ctx->sizeOfSign());
    SByteSpan sig1Span(sig1.begin(), sig1.size());
    SByteSpan sig2Span(sig2.begin(), sig2.size());
    REQUIRE(ctx->sign(messageSpan, sig1Span) == ERET_OK);
    REQUIRE(ctx->sign(messageSpan, sig2Span) == ERET_OK);
    sig1.resize(sig1Span.size);
    sig2.resize(sig2Span.size);

    REQUIRE(sig1.size() == sig2.size());
    for (size_t i = 0; i < sig1.size(); ++i) {
        CHECK(sig1[i] == sig2[i]);
    }
}

TEST_CASE("Ed448: verify rejects a tampered signature") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    const uint8_t message[] = "tamper test";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(ctx->sign(messageSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);
    REQUIRE(ctx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

    signature[signature.size() - 1] ^= 0xFF;
    CHECK(ctx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("Ed448: createPublicKey rejects the identity point (universal-forgery guard)") {
    // See ed25519.cpp's identical test for the full reasoning -- the identity point encodes as
    // y=1, x=0 (little-endian: 0x01 followed by zero bytes, 57 bytes total for Ed448).
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);

    uint8_t identityEncoded[57] = { 0 };
    identityEncoded[0] = 0x01;

    IPublicKeyPtr identityKey = ed->createPublicKey(SReadOnlyByteSpan(identityEncoded, sizeof(identityEncoded)));
    CHECK_FALSE(identityKey);
}

TEST_CASE("Ed448: verify rejects a signature whose R is the identity point, even against a real key") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair.publicKey, nullptr);

    uint8_t forgedSignature[114] = { 0 };
    forgedSignature[0] = 0x01; // R == identity point; S == 0 (the rest stays zero)

    const uint8_t anyMessage[] = "this message was never signed";
    CHECK(ctx->verify(
        SReadOnlyByteSpan(anyMessage, sizeof(anyMessage) - 1),
        SReadOnlyByteSpan(forgedSignature, sizeof(forgedSignature))
    ) != ERET_OK);
}

TEST_CASE("Ed448: verify rejects a signature produced by a different key pair") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    SKeyPair otherPair;

    ed->generateKeyPair(TEST_KEY_SIZE, otherPair);
    REQUIRE(otherPair);

    IAsymmetricContextPtr signCtx = ed->createContext();
    signCtx->keyPair(otherPair);

    const uint8_t message[] = "different key";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> signature;
    signature.resize(signCtx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(signCtx->sign(messageSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);

    IAsymmetricContextPtr verifyCtx = ed->createContext();
    verifyCtx->keyPair(pair);
    CHECK(verifyCtx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("Ed448: createEncrypter()/createDecrypter() are unsupported") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED448);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    IAsymmetricTransformerPtr transformer;
    CHECK(ctx->createEncrypter(transformer) == ERET_NOTSUP);
    CHECK(ctx->createDecrypter(transformer) == ERET_NOTSUP);
}
