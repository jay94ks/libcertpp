#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    // The smallest FIPS 186-4 approved size DSA::keySizes() accepts; domain parameter
    // generation (a full L-bit prime p, not two L/2-bit factors like RSA) is the expensive
    // part, so every test case below shares one lazily-generated pair instead of regenerating.
    constexpr SKeySize TEST_KEY_SIZE = 1024;

    const SKeyPair& sharedTestKeyPair() {
        static SKeyPair pair = [] {
            IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
            SKeyPair result;
            dsa->generateKeyPair(TEST_KEY_SIZE, result);
            return result;
        }();

        return pair;
    }
}

TEST_CASE("DSA: builtIn(EASYM_DSA) returns a usable algorithm instance") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    REQUIRE(dsa);

    bool acceptsTestSize = false;
    for (size_t i = 0; i < dsa->keySizes().size(); ++i) {
        if (dsa->keySizes()[i].includes(TEST_KEY_SIZE)) {
            acceptsTestSize = true;
        }
    }
    CHECK(acceptsTestSize);
}

TEST_CASE("DSA: generateKeyPair produces a matched, usable key pair") {
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);
    REQUIRE(pair.publicKey->keySize() == TEST_KEY_SIZE);
    REQUIRE(pair.privateKey->keySize() == TEST_KEY_SIZE);
    CHECK(pair.privateKey->publicKey()->compare(pair.publicKey) == 0);
}

TEST_CASE("DSA: generateKeyPair rejects a key size outside the FIPS 186-4 set") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    SKeyPair pair;
    dsa->generateKeyPair(1536, pair); // not one of 1024/2048/3072
    CHECK(pair.empty());
}

TEST_CASE("DSA: public/private key DER round-trips through serialize()/create*Key()") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    COctet pubDer, privDer;
    REQUIRE(pair.publicKey->serialize(pubDer) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privDer) == ERET_OK);

    IPublicKeyPtr parsedPub = dsa->createPublicKey(pubDer);
    IPrivateKeyPtr parsedPriv = dsa->createPrivateKey(privDer);

    REQUIRE(parsedPub);
    REQUIRE(parsedPriv);
    CHECK(parsedPub->compare(pair.publicKey) == 0);
    CHECK(parsedPriv->compare(pair.privateKey) == 0);
}

TEST_CASE("DSA: sign/verify round-trips for digests both wider and narrower than the subgroup order") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = dsa->createContext();
    ctx->keyPair(pair);

    // subgroup order N = 160 bits (20 bytes) for a 1024-bit key; exercise a digest shorter
    // than that (MD5, 16 bytes) and one longer (SHA-256, 32 bytes).
    const size_t digestLens[] = { 16, 32 };

    for (size_t len : digestLens) {
        TArray<uint8_t> digest;
        digest.resize(len);
        for (size_t i = 0; i < len; ++i) {
            digest[i] = uint8_t(i * 11 + 3);
        }

        SReadOnlyByteSpan digestSpan(digest.begin(), digest.size());

        TArray<uint8_t> signature;
        signature.resize(ctx->sizeOfSign());
        SByteSpan sigSpan(signature.begin(), signature.size());
        REQUIRE(ctx->sign(digestSpan, sigSpan) == ERET_OK);
        signature.resize(sigSpan.size);
        CHECK(ctx->verify(digestSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

        // Tampering with the digest must invalidate the signature.
        digest[0] ^= 0xFF;
        CHECK(ctx->verify(SReadOnlyByteSpan(digest.begin(), digest.size()),
            SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
    }
}

TEST_CASE("DSA: verify rejects a tampered signature") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = dsa->createContext();
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

TEST_CASE("DSA: verify rejects a signature produced by a different key pair") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    SKeyPair otherPair;

    dsa->generateKeyPair(TEST_KEY_SIZE, otherPair);
    REQUIRE(otherPair);

    IAsymmetricContextPtr signCtx = dsa->createContext();
    signCtx->keyPair(otherPair);

    uint8_t digest[20] = { 0 };
    for (size_t i = 0; i < sizeof(digest); ++i) {
        digest[i] = uint8_t(i * 3 + 7);
    }
    SReadOnlyByteSpan digestSpan(digest, sizeof(digest));

    TArray<uint8_t> signature;
    signature.resize(signCtx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(signCtx->sign(digestSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);

    IAsymmetricContextPtr verifyCtx = dsa->createContext();
    verifyCtx->keyPair(pair);
    CHECK(verifyCtx->verify(digestSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("DSA: createEncrypter()/createDecrypter() are unsupported") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = dsa->createContext();
    ctx->keyPair(pair);

    IAsymmetricTransformerPtr transformer;
    CHECK(ctx->createEncrypter(transformer) == ERET_NOTSUP);
    CHECK(ctx->createDecrypter(transformer) == ERET_NOTSUP);
}
