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
            IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
            SKeyPair result;
            x25519->generateKeyPair(TEST_KEY_SIZE, result);
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

// RFC 7748 5.2's Diffie-Hellman example. Verified independently (not just transcribed): computed
// with a standalone Python re-implementation of the same ladder before hardcoding these bytes,
// following this codebase's established practice of cross-checking constants/vectors against a
// second source rather than trusting a single fetch.
TEST_CASE("X25519: RFC 7748 5.2 Diffie-Hellman known-answer vector") {
    auto alicePriv = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto alicePub  = hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    auto bobPriv   = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    auto bobPub    = hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    auto shared    = hexToBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    REQUIRE(alicePriv.size() == 32);
    REQUIRE(alicePub.size() == 32);
    REQUIRE(bobPriv.size() == 32);
    REQUIRE(bobPub.size() == 32);
    REQUIRE(shared.size() == 32);

    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    REQUIRE(x25519);

    IPrivateKeyPtr alice = x25519->createPrivateKey(SReadOnlyByteSpan(alicePriv.data(), alicePriv.size()));
    IPrivateKeyPtr bob = x25519->createPrivateKey(SReadOnlyByteSpan(bobPriv.data(), bobPriv.size()));
    REQUIRE(alice);
    REQUIRE(bob);

    COctet derivedAlicePub, derivedBobPub;
    REQUIRE(alice->publicKey()->serialize(derivedAlicePub) == ERET_OK);
    REQUIRE(bob->publicKey()->serialize(derivedBobPub) == ERET_OK);
    CHECK(derivedAlicePub.toSpan().sequencialEqual(SReadOnlyByteSpan(alicePub.data(), alicePub.size())));
    CHECK(derivedBobPub.toSpan().sequencialEqual(SReadOnlyByteSpan(bobPub.data(), bobPub.size())));

    IAsymmetricContextPtr aliceCtx = x25519->createContext();
    aliceCtx->keyPair(alice->publicKey(), alice);

    IAsymmetricContextPtr bobCtx = x25519->createContext();
    bobCtx->keyPair(bob->publicKey(), bob);

    TArray<uint8_t> aliceShared, bobShared;
    aliceShared.resize(32);
    bobShared.resize(32);
    SByteSpan aliceSharedSpan(aliceShared.begin(), aliceShared.size());
    SByteSpan bobSharedSpan(bobShared.begin(), bobShared.size());
    REQUIRE(aliceCtx->deriveSharedSecret(bob->publicKey(), aliceSharedSpan) == ERET_OK);
    REQUIRE(bobCtx->deriveSharedSecret(alice->publicKey(), bobSharedSpan) == ERET_OK);
    aliceShared.resize(aliceSharedSpan.size);
    bobShared.resize(bobSharedSpan.size);

    REQUIRE(aliceShared.size() == 32);
    REQUIRE(bobShared.size() == 32);

    for (size_t i = 0; i < 32; ++i) {
        CHECK(aliceShared[i] == shared[i]);
        CHECK(bobShared[i] == shared[i]);
    }
}

// RFC 7748 5.2's iterated self-test, at the k=1 and k=1,000 checkpoints only -- the
// 1,000,000-iteration vector is skipped as impractically slow for this library's schoolbook,
// non-constant-time CBigNum arithmetic in a CTest run.
TEST_CASE("X25519: RFC 7748 5.2 iterated scalar multiplication (1 and 1,000 iterations)") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    REQUIRE(x25519);

    auto nine = hexToBytes("0900000000000000000000000000000000000000000000000000000000000000");
    REQUIRE(nine.size() == 32);

    auto after1 = hexToBytes("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    auto after1000 = hexToBytes("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    REQUIRE(after1.size() == 32);
    REQUIRE(after1000.size() == 32);

    std::vector<uint8_t> k = nine, u = nine;

    for (int i = 0; i < 1000; ++i) {
        IPrivateKeyPtr priv = x25519->createPrivateKey(SReadOnlyByteSpan(k.data(), k.size()));
        REQUIRE(priv);

        // The RFC's iterated test treats the running "k" as both scalar and (via its own
        // decoded-and-re-encoded form) the next u-coordinate; deriveSharedSecret() computes
        // X25519(k, u), which needs u encoded as a peer public key.
        IPublicKeyPtr peer = x25519->createPublicKey(SReadOnlyByteSpan(u.data(), u.size()));
        REQUIRE(peer);

        IAsymmetricContextPtr ctx = x25519->createContext();
        ctx->keyPair(IPublicKeyPtr(), priv);

        TArray<uint8_t> next;
        next.resize(32);
        SByteSpan nextSpan(next.begin(), next.size());
        REQUIRE(ctx->deriveSharedSecret(peer, nextSpan) == ERET_OK);
        next.resize(nextSpan.size);
        REQUIRE(next.size() == 32);

        u = k;
        k.assign(next.begin(), next.begin() + next.size());

        if (i == 0) {
            for (size_t j = 0; j < 32; ++j) {
                CHECK(k[j] == after1[j]);
            }
        }
    }

    for (size_t j = 0; j < 32; ++j) {
        CHECK(k[j] == after1000[j]);
    }
}

TEST_CASE("X25519: builtIn(EASYM_X25519) returns a usable algorithm instance") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    REQUIRE(x25519);

    bool acceptsTestSize = false;
    for (size_t i = 0; i < x25519->keySizes().size(); ++i) {
        if (x25519->keySizes()[i].includes(TEST_KEY_SIZE)) {
            acceptsTestSize = true;
        }
    }
    CHECK(acceptsTestSize);
}

TEST_CASE("X25519: generateKeyPair produces a matched, usable key pair") {
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);
    REQUIRE(pair.publicKey->keySize() == TEST_KEY_SIZE);
    REQUIRE(pair.privateKey->keySize() == TEST_KEY_SIZE);
    CHECK(pair.privateKey->publicKey()->compare(pair.publicKey) == 0);
}

TEST_CASE("X25519: generateKeyPair rejects a key size other than 256") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    SKeyPair pair;
    x25519->generateKeyPair(384, pair);
    CHECK(pair.empty());
}

TEST_CASE("X25519: public/private key round-trips through serialize()/create*Key()") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    COctet pubBytes, privBytes;
    REQUIRE(pair.publicKey->serialize(pubBytes) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privBytes) == ERET_OK);

    CHECK(pubBytes.size() == 32);
    CHECK(privBytes.size() == 32);

    IPublicKeyPtr parsedPub = x25519->createPublicKey(pubBytes);
    IPrivateKeyPtr parsedPriv = x25519->createPrivateKey(privBytes);

    REQUIRE(parsedPub);
    REQUIRE(parsedPriv);
    CHECK(parsedPub->compare(pair.publicKey) == 0);
    CHECK(parsedPriv->compare(pair.privateKey) == 0);
}

TEST_CASE("X25519: create*Key reject input that isn't 32 bytes") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);

    uint8_t tooShort[31] = { 0 };
    uint8_t tooLong[33] = { 0 };

    CHECK_FALSE(x25519->createPublicKey(SReadOnlyByteSpan(tooShort, sizeof(tooShort))));
    CHECK_FALSE(x25519->createPublicKey(SReadOnlyByteSpan(tooLong, sizeof(tooLong))));
    CHECK_FALSE(x25519->createPrivateKey(SReadOnlyByteSpan(tooShort, sizeof(tooShort))));
    CHECK_FALSE(x25519->createPrivateKey(SReadOnlyByteSpan(tooLong, sizeof(tooLong))));
}

TEST_CASE("X25519: deriveSharedSecret produces a symmetric result between two independent key pairs") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);

    SKeyPair a;

    x25519->generateKeyPair(TEST_KEY_SIZE, a);
    SKeyPair b;
    x25519->generateKeyPair(TEST_KEY_SIZE, b);
    REQUIRE(a);
    REQUIRE(b);

    IAsymmetricContextPtr aCtx = x25519->createContext();
    aCtx->keyPair(a);

    IAsymmetricContextPtr bCtx = x25519->createContext();
    bCtx->keyPair(b);

    TArray<uint8_t> secretA, secretB;
    secretA.resize(32);
    secretB.resize(32);
    SByteSpan secretASpan(secretA.begin(), secretA.size());
    SByteSpan secretBSpan(secretB.begin(), secretB.size());
    REQUIRE(aCtx->deriveSharedSecret(b.publicKey, secretASpan) == ERET_OK);
    REQUIRE(bCtx->deriveSharedSecret(a.publicKey, secretBSpan) == ERET_OK);
    secretA.resize(secretASpan.size);
    secretB.resize(secretBSpan.size);

    REQUIRE(secretA.size() == secretB.size());
    for (size_t i = 0; i < secretA.size(); ++i) {
        CHECK(secretA[i] == secretB[i]);
    }
}

TEST_CASE("X25519: deriveSharedSecret rejects an all-zero-result (low-order) peer point") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    uint8_t zeroU[32] = { 0 };
    IPublicKeyPtr lowOrderPeer = x25519->createPublicKey(SReadOnlyByteSpan(zeroU, sizeof(zeroU)));
    REQUIRE(lowOrderPeer);

    IAsymmetricContextPtr ctx = x25519->createContext();
    ctx->keyPair(pair);

    TArray<uint8_t> secret;
    secret.resize(32);
    SByteSpan secretSpan(secret.begin(), secret.size());
    CHECK(ctx->deriveSharedSecret(lowOrderPeer, secretSpan) != ERET_OK);
}

TEST_CASE("X25519: deriveSharedSecret rejects a peer key of a different algorithm") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricPtr ed25519 = IAsymmetric::builtIn(EASYM_ED25519);
    SKeyPair otherAlgPair;
    ed25519->generateKeyPair(256, otherAlgPair);
    REQUIRE(otherAlgPair);

    IAsymmetricContextPtr ctx = x25519->createContext();
    ctx->keyPair(pair);

    TArray<uint8_t> secret;
    secret.resize(32);
    SByteSpan secretSpan(secret.begin(), secret.size());
    CHECK(ctx->deriveSharedSecret(otherAlgPair.publicKey, secretSpan) != ERET_OK);
}

TEST_CASE("X25519: sign()/verify() are unsupported") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = x25519->createContext();
    ctx->keyPair(pair);

    uint8_t message[] = "test";
    SByteSpan signature;
    CHECK(ctx->sign(SReadOnlyByteSpan(message, sizeof(message)), signature) == ERET_NOTSUP);
    CHECK(ctx->verify(SReadOnlyByteSpan(message, sizeof(message)),
        SReadOnlyByteSpan(message, sizeof(message))) == ERET_NOTSUP);
}

TEST_CASE("X25519: createEncrypter()/createDecrypter() are unsupported") {
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = x25519->createContext();
    ctx->keyPair(pair);

    IAsymmetricTransformerPtr transformer;
    CHECK(ctx->createEncrypter(transformer) == ERET_NOTSUP);
    CHECK(ctx->createDecrypter(transformer) == ERET_NOTSUP);
}
