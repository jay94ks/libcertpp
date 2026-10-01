#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    constexpr SKeySize TEST_KEY_SIZE = 256;

    const SKeyPair& sharedTestKeyPair() {
        static SKeyPair pair = [] {
            IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
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

// RFC 8032 Section 7.1, TEST 1: an empty message. EdDSA signing is fully deterministic (no
// per-signature randomness, unlike DSA/ECDSA), so reproducing this exact signature validates
// the whole pipeline at once -- field arithmetic, the derived curve/group constants, key
// clamping, and the signing algorithm itself -- far more strongly than a self-consistency
// round-trip alone could.
TEST_CASE("Ed25519: RFC 8032 TEST 1 vector (empty message)") {
    auto secretKey = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    auto publicKey = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    auto signature = hexToBytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    REQUIRE(secretKey.size() == 32);
    REQUIRE(publicKey.size() == 32);
    REQUIRE(signature.size() == 64);

    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    REQUIRE(ed);

    IPrivateKeyPtr priv = ed->createPrivateKey(SReadOnlyByteSpan(secretKey.data(), secretKey.size()));
    REQUIRE(priv);

    COctet derivedPub;
    REQUIRE(priv->publicKey()->serialize(derivedPub) == ERET_OK);
    REQUIRE(derivedPub.size() == 32);
    CHECK(derivedPub.toSpan().sequencialEqual(SReadOnlyByteSpan(publicKey.data(), publicKey.size())));

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(priv->publicKey(), priv);

    TArray<uint8_t> producedSignature;
    producedSignature.resize(ctx->sizeOfSign());
    SByteSpan producedSignatureSpan(producedSignature.begin(), producedSignature.size());
    REQUIRE(ctx->sign(SReadOnlyByteSpan(nullptr, 0), producedSignatureSpan) == ERET_OK);
    producedSignature.resize(producedSignatureSpan.size);
    REQUIRE(producedSignature.size() == 64);

    for (size_t i = 0; i < 64; ++i) {
        CHECK(producedSignature[i] == signature[i]);
    }

    CHECK(ctx->verify(SReadOnlyByteSpan(nullptr, 0),
        SReadOnlyByteSpan(signature.data(), signature.size())) == ERET_OK);
}

TEST_CASE("Ed25519: builtIn(EASYM_ED25519) returns a usable algorithm instance") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    REQUIRE(ed);

    bool acceptsTestSize = false;
    for (size_t i = 0; i < ed->keySizes().size(); ++i) {
        if (ed->keySizes()[i].includes(TEST_KEY_SIZE)) {
            acceptsTestSize = true;
        }
    }
    CHECK(acceptsTestSize);
}

TEST_CASE("Ed25519: generateKeyPair produces a matched, usable key pair") {
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);
    REQUIRE(pair.publicKey->keySize() == TEST_KEY_SIZE);
    REQUIRE(pair.privateKey->keySize() == TEST_KEY_SIZE);
    CHECK(pair.privateKey->publicKey()->compare(pair.publicKey) == 0);
}

TEST_CASE("Ed25519: generateKeyPair rejects a key size other than 256") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    SKeyPair pair;
    ed->generateKeyPair(384, pair);
    CHECK(pair.empty());
}

TEST_CASE("Ed25519: public/private key round-trips through serialize()/create*Key()") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    COctet pubBytes, privBytes;
    REQUIRE(pair.publicKey->serialize(pubBytes) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privBytes) == ERET_OK);

    CHECK(pubBytes.size() == 32);
    CHECK(privBytes.size() == 32);

    IPublicKeyPtr parsedPub = ed->createPublicKey(pubBytes);
    IPrivateKeyPtr parsedPriv = ed->createPrivateKey(privBytes);

    REQUIRE(parsedPub);
    REQUIRE(parsedPriv);
    CHECK(parsedPub->compare(pair.publicKey) == 0);
    CHECK(parsedPriv->compare(pair.privateKey) == 0);
}

TEST_CASE("Ed25519: createPublicKey rejects a point not on the curve") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);

    // y = 2 has no valid x on edwards25519 for either sign bit (verified offline: (y^2-1)/(d*y^2+1)
    // is not a quadratic residue mod p) -- deterministically invalid, unlike flipping a random bit
    // of a real encoded point, which has roughly even odds of still landing on a valid point
    // (about half of field elements are quadratic residues).
    uint8_t invalid[32] = { 2 };

    IPublicKeyPtr parsed = ed->createPublicKey(SReadOnlyByteSpan(invalid, sizeof(invalid)));
    CHECK_FALSE(parsed);
}

TEST_CASE("Ed25519: sign/verify round-trips for a non-empty message") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    const uint8_t message[] = "certpp Ed25519 test message";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(ctx->sign(messageSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);
    REQUIRE(signature.size() == 64);
    CHECK(ctx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

    // Tampering with the message must invalidate the signature.
    uint8_t tamperedMessage[sizeof(message) - 1];
    for (size_t i = 0; i < sizeof(tamperedMessage); ++i) {
        tamperedMessage[i] = message[i];
    }
    tamperedMessage[0] ^= 0xFF;

    CHECK(ctx->verify(SReadOnlyByteSpan(tamperedMessage, sizeof(tamperedMessage)),
        SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("Ed25519: signing is deterministic (same seed and message produce the same signature)") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
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

TEST_CASE("Ed25519: verify rejects a tampered signature") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
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

TEST_CASE("Ed25519: createPublicKey rejects the identity point (universal-forgery guard)") {
    // The identity point encodes as y=1, x=0 (little-endian: 0x01 followed by 31 zero bytes).
    // If accepted as a public key, the all-zero signature (R == identity, S == 0) would verify
    // against *any* message under it, since scalarMul(0)*B == identity and
    // pointAdd(identity, scalarMul(identity, k)) == identity for every k -- a universal
    // signature forgery in the same spirit as CVE-2022-21449's missing ECDSA r/s == 0 checks.
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);

    uint8_t identityEncoded[32] = { 0 };
    identityEncoded[0] = 0x01;

    IPublicKeyPtr identityKey = ed->createPublicKey(SReadOnlyByteSpan(identityEncoded, sizeof(identityEncoded)));
    CHECK_FALSE(identityKey);
}

TEST_CASE("Ed25519: verify rejects a signature whose R is the identity point, even against a real key") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair.publicKey, nullptr);

    uint8_t forgedSignature[64] = { 0 };
    forgedSignature[0] = 0x01; // R == identity point; S == 0 (the rest stays zero)

    const uint8_t anyMessage[] = "this message was never signed";
    CHECK(ctx->verify(
        SReadOnlyByteSpan(anyMessage, sizeof(anyMessage) - 1),
        SReadOnlyByteSpan(forgedSignature, sizeof(forgedSignature))
    ) != ERET_OK);
}

TEST_CASE("Ed25519: verify rejects a signature produced by a different key pair") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
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

TEST_CASE("Ed25519: createEncrypter()/createDecrypter() are unsupported") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    IAsymmetricTransformerPtr transformer;
    CHECK(ctx->createEncrypter(transformer) == ERET_NOTSUP);
    CHECK(ctx->createDecrypter(transformer) == ERET_NOTSUP);
}
