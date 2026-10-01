#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;

TEST_CASE("ChaCha20: builtIn(ESYM_CHACHA20) returns a usable algorithm instance accepting a 256-bit key") {
    ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);
    REQUIRE(cc);

    bool accepts256 = false;
    for (size_t i = 0; i < cc->keySizes().size(); ++i) {
        if (cc->keySizes()[i].includes(256)) {
            accepts256 = true;
        }
    }
    CHECK(accepts256);
}

TEST_CASE("ChaCha20: generateKey produces a 32-byte key; generateIV produces a 12-byte nonce") {
    ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);
    ISymmetricKeyPtr key;
    REQUIRE(cc->generateKey(key, SKeySizeSpec(256)) == ERET_OK);
    REQUIRE(key);
    CHECK(key->keySize() == 32);
    CHECK(key->algorithm() == ESYM_CHACHA20);

    CBuffer iv;
    REQUIRE(cc->generateIV(key, iv) == ERET_OK);
    CHECK(iv.size() == 12);
}

TEST_CASE("ChaCha20: generateKey rejects a key size outside keySizes()") {
    ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);
    ISymmetricKeyPtr key;
    CHECK(cc->generateKey(key, SKeySizeSpec(128)) != ERET_OK);
    CHECK_FALSE(key);
}

TEST_CASE("ChaCha20: matches RFC 8439 Appendix A.1 Test Vector #1 (all-zero key/nonce, counter 0)") {
    const uint8_t KEY[32] = { 0 };
    const uint8_t NONCE[12] = { 0 };
    const uint8_t EXPECTED_KEYSTREAM[64] = {
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
        0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
    };

    ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);
    ISymmetricKeyPtr key = cc->createKey(SReadOnlyByteSpan(KEY, sizeof(KEY)));
    REQUIRE(key);

    ISymmetricContextPtr ctx = cc->createContext(key);
    ctx->key(key, CBuffer(NONCE, sizeof(NONCE)));

    ISymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    uint8_t zeroPlaintext[64] = { 0 };
    uint8_t out[64];
    SByteSpan outSpan(out, sizeof(out));
    // XORing an all-zero plaintext with the keystream yields the keystream itself.
    REQUIRE(encrypter->transform(SReadOnlyByteSpan(zeroPlaintext, sizeof(zeroPlaintext)), outSpan) == ERET_OK);
    REQUIRE(outSpan.size == 64);

    CHECK(std::memcmp(out, EXPECTED_KEYSTREAM, 64) == 0);
}

TEST_CASE("ChaCha20: createDecrypter undoes createEncrypter (same XOR operation)") {
    ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);
    ISymmetricKeyPtr key;
    REQUIRE(cc->generateKey(key, SKeySizeSpec(256)) == ERET_OK);

    CBuffer iv;
    REQUIRE(cc->generateIV(key, iv) == ERET_OK);

    const uint8_t plaintext[] = "certpp ChaCha20 round trip test message, spanning more than one 64-byte block of keystream.";

    ISymmetricContextPtr ctx = cc->createContext(key);
    ctx->key(key, iv);

    ISymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    TArray<uint8_t> ciphertext;
    ciphertext.resize(sizeof(plaintext));
    SByteSpan cspan(ciphertext.begin(), ciphertext.size());
    REQUIRE(encrypter->transform(SReadOnlyByteSpan(plaintext, sizeof(plaintext)), cspan) == ERET_OK);
    REQUIRE(cspan.size == sizeof(plaintext));

    SByteSpan cfinal(ciphertext.begin(), 0);
    REQUIRE(encrypter->transformFinal(cfinal) == ERET_OK);
    CHECK(cfinal.size == 0);

    ISymmetricContextPtr dctx = cc->createContext(key);
    dctx->key(key, iv);

    ISymmetricTransformerPtr decrypter;
    REQUIRE(dctx->createDecrypter(decrypter) == ERET_OK);

    TArray<uint8_t> recovered;
    recovered.resize(sizeof(plaintext));
    SByteSpan rspan(recovered.begin(), recovered.size());
    REQUIRE(decrypter->transform(SReadOnlyByteSpan(ciphertext.begin(), ciphertext.size()), rspan) == ERET_OK);
    REQUIRE(rspan.size == sizeof(plaintext));

    CHECK(std::memcmp(recovered.begin(), plaintext, sizeof(plaintext)) == 0);
}

TEST_CASE("ChaCha20: is insensitive to how input is chunked across transform() calls") {
    ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);
    ISymmetricKeyPtr key;
    REQUIRE(cc->generateKey(key, SKeySizeSpec(256)) == ERET_OK);

    CBuffer iv;
    REQUIRE(cc->generateIV(key, iv) == ERET_OK);

    TArray<uint8_t> plaintext;
    plaintext.resize(200);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(i * 13 + 5);
    }

    ISymmetricContextPtr wholeCtx = cc->createContext(key);
    wholeCtx->key(key, iv);
    ISymmetricTransformerPtr wholeEnc;
    REQUIRE(wholeCtx->createEncrypter(wholeEnc) == ERET_OK);

    TArray<uint8_t> wholeCipher;
    wholeCipher.resize(plaintext.size());
    SByteSpan wholeSpan(wholeCipher.begin(), wholeCipher.size());
    REQUIRE(wholeEnc->transform(SReadOnlyByteSpan(plaintext.begin(), plaintext.size()), wholeSpan) == ERET_OK);
    REQUIRE(wholeSpan.size == plaintext.size());

    ISymmetricContextPtr chunkedCtx = cc->createContext(key);
    chunkedCtx->key(key, iv);
    ISymmetricTransformerPtr chunkedEnc;
    REQUIRE(chunkedCtx->createEncrypter(chunkedEnc) == ERET_OK);

    TArray<uint8_t> chunkedCipher;
    chunkedCipher.resize(plaintext.size());
    size_t pos = 0;
    while (pos < plaintext.size()) {
        size_t n = (plaintext.size() - pos < 7) ? (plaintext.size() - pos) : 7;
        SByteSpan outSpan(chunkedCipher.begin() + pos, n);
        REQUIRE(chunkedEnc->transform(SReadOnlyByteSpan(plaintext.begin() + pos, n), outSpan) == ERET_OK);
        REQUIRE(outSpan.size == n);
        pos += n;
    }

    CHECK(std::memcmp(wholeCipher.begin(), chunkedCipher.begin(), plaintext.size()) == 0);
}

TEST_CASE("ChaCha20: createEncrypter fails without a key or a correctly-sized nonce") {
    ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);
    ISymmetricKeyPtr key;
    REQUIRE(cc->generateKey(key, SKeySizeSpec(256)) == ERET_OK);

    ISymmetricContextPtr ctxNoKey = cc->createContext(nullptr);
    ISymmetricTransformerPtr t1;
    CHECK(ctxNoKey->createEncrypter(t1) == ERET_KEY_EMPTY);

    ISymmetricContextPtr ctxNoNonce = cc->createContext(key);
    ISymmetricTransformerPtr t2;
    CHECK(ctxNoNonce->createEncrypter(t2) == ERET_KEY_PARAM);
}
