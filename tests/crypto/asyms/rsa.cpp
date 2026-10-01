#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    // 1024 bits is the smallest size that leaves room for a SHA-512 DigestInfo under PKCS#1
    // v1.5 padding (64 + 19-byte prefix + 11 bytes overhead = 94 bytes = 752 bits, rounded up
    // to the next 8-bit step); still fast enough for a test suite with this schoolbook bignum
    // (no CRT/Montgomery speedups). Production use should request a much larger size.
    constexpr SKeySize TEST_KEY_SIZE = 1024;

    SKeyPair generateTestKeyPair() {
        IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
        SKeyPair result;
        rsa->generateKeyPair(TEST_KEY_SIZE, result);
        return result;
    }
}

TEST_CASE("RSA: builtIn(EASYM_RSA) returns a usable algorithm instance") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    REQUIRE(rsa);

    bool acceptsTestSize = false;
    for (size_t i = 0; i < rsa->keySizes().size(); ++i) {
        if (rsa->keySizes()[i].includes(TEST_KEY_SIZE)) {
            acceptsTestSize = true;
        }
    }
    CHECK(acceptsTestSize);
}

TEST_CASE("RSA: generateKeyPair produces a matched, usable key pair") {
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);
    REQUIRE(pair.publicKey->keySize() == TEST_KEY_SIZE);
    REQUIRE(pair.privateKey->keySize() == TEST_KEY_SIZE);
    CHECK(pair.privateKey->publicKey()->compare(pair.publicKey) == 0);
}

TEST_CASE("RSA: generateKeyPair rejects a key size outside keySizes()") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair;
    rsa->generateKeyPair(13, pair); // not in the 512-8192/8 spec
    CHECK(pair.empty());
}

TEST_CASE("RSA: public/private key DER round-trips through serialize()/create*Key()") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    COctet pubDer, privDer;
    REQUIRE(pair.publicKey->serialize(pubDer) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privDer) == ERET_OK);

    IPublicKeyPtr parsedPub = rsa->createPublicKey(pubDer);
    IPrivateKeyPtr parsedPriv = rsa->createPrivateKey(privDer);

    REQUIRE(parsedPub);
    REQUIRE(parsedPriv);
    CHECK(parsedPub->compare(pair.publicKey) == 0);
    CHECK(parsedPriv->compare(pair.privateKey) == 0);
}

TEST_CASE("RSA: sign/verify round-trips for every supported digest length") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    const size_t digestLens[] = { 16, 20, 32, 48, 64 }; // MD5, SHA-1, SHA-256, SHA-384, SHA-512

    for (size_t len : digestLens) {
        TArray<uint8_t> digest;
        digest.resize(len);
        for (size_t i = 0; i < len; ++i) {
            digest[i] = uint8_t(i * 7 + 1);
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

TEST_CASE("RSA: sign/verify rejects an unrecognized digest length") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    uint8_t oddDigest[17] = { 0 };
    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    CHECK(ctx->sign(SReadOnlyByteSpan(oddDigest, sizeof(oddDigest)), sigSpan) == ERET_NOTSUP);
}

TEST_CASE("RSA: encrypt/decrypt round-trips via createEncrypter()/createDecrypter()") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    const uint8_t plaintext[] = "certpp RSA test message";
    COctet message(plaintext, sizeof(plaintext));

    IAsymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    SByteSpan unused;
    TArray<uint8_t> ciphertext;
    ciphertext.resize(encrypter->blockSize());
    SByteSpan ciphertextSpan(ciphertext.begin(), ciphertext.size());
    REQUIRE(encrypter->transform(message.toSpan(), unused) == ERET_OK);
    REQUIRE(encrypter->transformFinal(ciphertextSpan) == ERET_OK);
    ciphertext.resize(ciphertextSpan.size);
    CHECK(ciphertext.size() == TEST_KEY_SIZE / 8);

    IAsymmetricTransformerPtr decrypter;
    REQUIRE(ctx->createDecrypter(decrypter) == ERET_OK);

    SByteSpan unused2;
    TArray<uint8_t> recovered;
    recovered.resize(decrypter->blockSize());
    SByteSpan recoveredSpan(recovered.begin(), recovered.size());
    REQUIRE(decrypter->transform(SReadOnlyByteSpan(ciphertext.begin(), ciphertext.size()), unused2) == ERET_OK);
    REQUIRE(decrypter->transformFinal(recoveredSpan) == ERET_OK);
    recovered.resize(recoveredSpan.size);

    REQUIRE(recovered.size() == message.size());
    CHECK(SReadOnlyByteSpan(recovered.begin(), recovered.size()).sequencialEqual(message.toSpan()));
}

TEST_CASE("RSA: transform() processes complete blocks eagerly, block by block") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    // TEST_KEY_SIZE/8 - 11 = 117 bytes of plaintext per block; 300 bytes spans 3 blocks
    // (117 + 117 + 66), so a single transform() call must process more than one block itself
    // rather than only ever deferring to transformFinal().
    TArray<uint8_t> plaintext;
    plaintext.resize(300);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(i);
    }

    IAsymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    TArray<uint8_t> ciphertext;
    ciphertext.resize(encrypter->blockSize() * 3);
    SByteSpan ciphertextSpan(ciphertext.begin(), ciphertext.size());

    REQUIRE(encrypter->transform(SReadOnlyByteSpan(plaintext.begin(), plaintext.size()), ciphertextSpan) == ERET_OK);
    // Two complete 117-byte blocks were available immediately, so transform() must have
    // already produced their ciphertext instead of buffering it for transformFinal().
    CHECK(ciphertextSpan.size == encrypter->blockSize() * 2);

    SByteSpan finalSpan(ciphertext.begin() + ciphertextSpan.size, ciphertext.size() - ciphertextSpan.size);
    REQUIRE(encrypter->transformFinal(finalSpan) == ERET_OK);
    CHECK(finalSpan.size == encrypter->blockSize());

    size_t totalCiphertext = ciphertextSpan.size + finalSpan.size;
    CHECK(totalCiphertext == encrypter->blockSize() * 3);

    IAsymmetricTransformerPtr decrypter;
    REQUIRE(ctx->createDecrypter(decrypter) == ERET_OK);

    TArray<uint8_t> recovered;
    recovered.resize(plaintext.size());
    SByteSpan recoveredSpan(recovered.begin(), recovered.size());

    // totalCiphertext is an exact multiple of the 128-byte decrypt block size (3 * 128), and
    // recoveredSpan has room for the full 300-byte plaintext, so transform() can eagerly
    // decrypt all 3 blocks itself, leaving nothing for transformFinal() to do.
    REQUIRE(decrypter->transform(SReadOnlyByteSpan(ciphertext.begin(), totalCiphertext), recoveredSpan) == ERET_OK);
    CHECK(recoveredSpan.size == 300);

    SByteSpan recoveredFinalSpan(recovered.begin() + recoveredSpan.size, recovered.size() - recoveredSpan.size);
    REQUIRE(decrypter->transformFinal(recoveredFinalSpan) == ERET_OK);
    CHECK(recoveredFinalSpan.size == 0);

    size_t totalRecovered = recoveredSpan.size + recoveredFinalSpan.size;
    REQUIRE(totalRecovered == plaintext.size());
    CHECK(SReadOnlyByteSpan(recovered.begin(), totalRecovered).sequencialEqual(
        SReadOnlyByteSpan(plaintext.begin(), plaintext.size())));
}

TEST_CASE("RSA: decrypt rejects a tampered ciphertext") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    const uint8_t plaintext[] = "tamper test";
    COctet message(plaintext, sizeof(plaintext));

    IAsymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    SByteSpan unused;
    TArray<uint8_t> ciphertext;
    ciphertext.resize(encrypter->blockSize());
    SByteSpan ciphertextSpan(ciphertext.begin(), ciphertext.size());
    REQUIRE(encrypter->transform(message.toSpan(), unused) == ERET_OK);
    REQUIRE(encrypter->transformFinal(ciphertextSpan) == ERET_OK);
    ciphertext.resize(ciphertextSpan.size);

    TArray<uint8_t> tampered;
    tampered.resize(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        tampered[i] = ciphertext[i];
    }
    tampered[0] ^= 0xFF;

    IAsymmetricTransformerPtr decrypter;
    REQUIRE(ctx->createDecrypter(decrypter) == ERET_OK);

    SByteSpan unused2;
    TArray<uint8_t> recovered;
    recovered.resize(decrypter->blockSize());
    SByteSpan recoveredSpan(recovered.begin(), recovered.size());

    // Processing is block-by-block now, so the tampered block's padding may be rejected as
    // soon as transform() sees the complete block, rather than only at transformFinal().
    ERetCode rc = decrypter->transform(SReadOnlyByteSpan(tampered.begin(), tampered.size()), unused2);
    if (rc == ERET_OK) {
        rc = decrypter->transformFinal(recoveredSpan);
    }
    CHECK(rc != ERET_OK);
}
