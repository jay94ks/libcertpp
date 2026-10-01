#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    constexpr SKeySize TEST_KEY_SIZE = 409;

    const SKeyPair& sharedTestKeyPair() {
        static SKeyPair pair = [] {
            IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);
            SKeyPair result;
            b409->generateKeyPair(TEST_KEY_SIZE, result);
            return result;
        }();

        return pair;
    }
}

TEST_CASE("B409: builtIn(EASYM_B409) returns a usable algorithm instance") {
    IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);
    REQUIRE(b409);

    bool acceptsTestSize = false;
    for (size_t i = 0; i < b409->keySizes().size(); ++i) {
        if (b409->keySizes()[i].includes(TEST_KEY_SIZE)) {
            acceptsTestSize = true;
        }
    }
    CHECK(acceptsTestSize);
}

TEST_CASE("B409: generateKeyPair produces a matched, usable key pair") {
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);
    REQUIRE(pair.publicKey->keySize() == TEST_KEY_SIZE);
    REQUIRE(pair.privateKey->keySize() == TEST_KEY_SIZE);
    CHECK(pair.privateKey->publicKey()->compare(pair.publicKey) == 0);
}

TEST_CASE("B409: generateKeyPair rejects a key size other than 409") {
    IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);
    SKeyPair pair;
    b409->generateKeyPair(999, pair);
    CHECK(pair.empty());
}

TEST_CASE("B409: public/private key DER round-trips through serialize()/create*Key()") {
    IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    COctet pubDer, privDer;
    REQUIRE(pair.publicKey->serialize(pubDer) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privDer) == ERET_OK);

    // SEC1 uncompressed point: 0x04 || X(52) || Y(52) = 105 bytes.
    CHECK(pubDer.size() == 105);

    IPublicKeyPtr parsedPub = b409->createPublicKey(pubDer);
    IPrivateKeyPtr parsedPriv = b409->createPrivateKey(privDer);

    REQUIRE(parsedPub);
    REQUIRE(parsedPriv);
    CHECK(parsedPub->compare(pair.publicKey) == 0);
    CHECK(parsedPriv->compare(pair.privateKey) == 0);
}

TEST_CASE("B409: createPublicKey rejects a point not on the curve") {
    IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);

    COctet pubDer;
    REQUIRE(sharedTestKeyPair().publicKey->serialize(pubDer) == ERET_OK);

    TArray<uint8_t> tampered;
    tampered.resize(pubDer.size());
    for (size_t i = 0; i < pubDer.size(); ++i) {
        tampered[i] = pubDer.toSpan().data[i];
    }
    tampered[tampered.size() - 1] ^= 0xFF; // flip a bit in Y

    IPublicKeyPtr parsed = b409->createPublicKey(SReadOnlyByteSpan(tampered.begin(), tampered.size()));
    CHECK_FALSE(parsed);
}

TEST_CASE("B409: sign/verify round-trips for digests both wider and narrower than the field") {
    IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = b409->createContext();
    ctx->keyPair(pair);

    const size_t digestLens[] = { 20, 48 }; // SHA-1 (narrower than most fields), SHA-384 (wider)

    for (size_t len : digestLens) {
        TArray<uint8_t> digest;
        digest.resize(len);
        for (size_t i = 0; i < len; ++i) {
            digest[i] = uint8_t(i * 13 + 5);
        }

        SReadOnlyByteSpan digestSpan(digest.begin(), digest.size());

        TArray<uint8_t> signature;
        signature.resize(ctx->sizeOfSign());
        SByteSpan sigSpan(signature.begin(), signature.size());
        REQUIRE(ctx->sign(digestSpan, sigSpan) == ERET_OK);
        signature.resize(sigSpan.size);
        CHECK(ctx->verify(digestSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

        digest[0] ^= 0xFF;
        CHECK(ctx->verify(SReadOnlyByteSpan(digest.begin(), digest.size()),
            SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
    }
}

TEST_CASE("B409: verify rejects a tampered signature") {
    IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = b409->createContext();
    ctx->keyPair(pair);

    uint8_t digest[32] = { 0 };
    for (size_t i = 0; i < sizeof(digest); ++i) {
        digest[i] = uint8_t(i * 5 + 1);
    }
    SReadOnlyByteSpan digestSpan(digest, sizeof(digest));

    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(ctx->sign(digestSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);
    REQUIRE(ctx->verify(digestSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

    signature[signature.size() - 1] ^= 0xFF;
    CHECK(ctx->verify(digestSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("B409: verify rejects a signature produced by a different key pair") {
    IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    SKeyPair otherPair;

    b409->generateKeyPair(TEST_KEY_SIZE, otherPair);
    REQUIRE(otherPair);

    IAsymmetricContextPtr signCtx = b409->createContext();
    signCtx->keyPair(otherPair);

    uint8_t digest[32] = { 0 };
    for (size_t i = 0; i < sizeof(digest); ++i) {
        digest[i] = uint8_t(i * 3 + 7);
    }
    SReadOnlyByteSpan digestSpan(digest, sizeof(digest));

    TArray<uint8_t> signature;
    signature.resize(signCtx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(signCtx->sign(digestSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);

    IAsymmetricContextPtr verifyCtx = b409->createContext();
    verifyCtx->keyPair(pair);
    CHECK(verifyCtx->verify(digestSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("B409: createEncrypter()/createDecrypter() are unsupported") {
    IAsymmetricPtr b409 = IAsymmetric::builtIn(EASYM_B409);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = b409->createContext();
    ctx->keyPair(pair);

    IAsymmetricTransformerPtr transformer;
    CHECK(ctx->createEncrypter(transformer) == ERET_NOTSUP);
    CHECK(ctx->createDecrypter(transformer) == ERET_NOTSUP);
}
