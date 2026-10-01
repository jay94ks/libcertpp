#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    const uint8_t ZERO_IV8[8] = { 0 };

    // Single-block CBC-with-zero-IV ECB equivalent, built on the already independently-validated
    // DES algorithm (see des.cpp's FIPS 46 known-answer test) -- used both directly (DES) and as
    // the reference implementation TripleDES's EDE3 composition is cross-checked against below.
    bool desEncryptBlock(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]) {
        ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
        ISymmetricKeyPtr k = des->createKey(SReadOnlyByteSpan(key, 8));
        if (!k) return false;

        ISymmetricContextPtr ctx = des->createContext(k);
        ctx->key(k, CBuffer(ZERO_IV8, sizeof(ZERO_IV8)));

        ISymmetricTransformerPtr encrypter;
        if (ctx->createEncrypter(encrypter) != ERET_OK) return false;

        uint8_t buf[8];
        SByteSpan outSpan(buf, sizeof(buf));
        if (encrypter->transform(SReadOnlyByteSpan(in, 8), outSpan) != ERET_OK) return false;
        if (outSpan.size != 8) return false;

        std::memcpy(out, buf, 8);
        return true;
    }

    bool desDecryptBlock(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]) {
        ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
        ISymmetricKeyPtr k = des->createKey(SReadOnlyByteSpan(key, 8));
        if (!k) return false;

        ISymmetricContextPtr ctx = des->createContext(k);
        ctx->key(k, CBuffer(ZERO_IV8, sizeof(ZERO_IV8)));

        // CbcTransformer's decrypt path always holds back the most recently completed block
        // rather than emitting it immediately (in case it turns out to be the final, padded
        // one -- see cbctransformer.cpp). Feeding two blocks via transform() (never calling
        // transformFinal()) therefore emits only the first block, decrypted and dechained but
        // with no padding ever inspected or stripped -- exactly a raw single-block CBC decrypt.
        // The second block is filler; its content is irrelevant since it's never processed here.
        ISymmetricTransformerPtr decrypter;
        if (ctx->createDecrypter(decrypter) != ERET_OK) return false;

        uint8_t twoBlocks[16] = { 0 };
        std::memcpy(twoBlocks, in, 8);

        uint8_t buf[16];
        SByteSpan outSpan(buf, sizeof(buf));
        if (decrypter->transform(SReadOnlyByteSpan(twoBlocks, 16), outSpan) != ERET_OK) return false;
        if (outSpan.size != 8) return false;

        std::memcpy(out, buf, 8);
        return true;
    }
}

TEST_CASE("TripleDES: builtIn(ESYM_3DES) returns a usable algorithm instance accepting 128/192-bit keys") {
    ISymmetricPtr des3 = ISymmetric::builtIn(ESYM_3DES);
    REQUIRE(des3);

    bool acc128 = false, acc192 = false;
    for (size_t i = 0; i < des3->keySizes().size(); ++i) {
        if (des3->keySizes()[i].includes(128)) acc128 = true;
        if (des3->keySizes()[i].includes(192)) acc192 = true;
    }
    CHECK(acc128);
    CHECK(acc192);
}

TEST_CASE("TripleDES: generateKey produces a key of the requested size") {
    ISymmetricPtr des3 = ISymmetric::builtIn(ESYM_3DES);

    for (SKeySize bits : { 128, 192 }) {
        ISymmetricKeyPtr key;
        REQUIRE(des3->generateKey(key, SKeySizeSpec(bits)) == ERET_OK);
        REQUIRE(key);
        CHECK(key->keySize() == bits / 8);
    }
}

TEST_CASE("TripleDES: generateKey rejects a key size outside keySizes()") {
    ISymmetricPtr des3 = ISymmetric::builtIn(ESYM_3DES);
    ISymmetricKeyPtr key;
    CHECK(des3->generateKey(key, SKeySizeSpec(64)) != ERET_OK);
    CHECK_FALSE(key);
}

TEST_CASE("TripleDES: three-key EDE3 matches Encrypt(K3,Decrypt(K2,Encrypt(K1,P))) composed from DES") {
    const uint8_t K1[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const uint8_t K2[8] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const uint8_t K3[8] = { 0x3B, 0x38, 0x98, 0x37, 0x15, 0x20, 0xF7, 0x5E };
    const uint8_t PLAINTEXT[8] = { 0x4E, 0x6F, 0x77, 0x69, 0x73, 0x74, 0x68, 0x65 };

    uint8_t stage1[8], stage2[8], expected[8];
    REQUIRE(desEncryptBlock(K1, PLAINTEXT, stage1));
    REQUIRE(desDecryptBlock(K2, stage1, stage2));
    REQUIRE(desEncryptBlock(K3, stage2, expected));

    uint8_t key24[24];
    std::memcpy(key24, K1, 8);
    std::memcpy(key24 + 8, K2, 8);
    std::memcpy(key24 + 16, K3, 8);

    ISymmetricPtr des3 = ISymmetric::builtIn(ESYM_3DES);
    ISymmetricKeyPtr key = des3->createKey(SReadOnlyByteSpan(key24, sizeof(key24)));
    REQUIRE(key);

    const uint8_t ZERO_IV[8] = { 0 };
    ISymmetricContextPtr ctx = des3->createContext(key);
    ctx->key(key, CBuffer(ZERO_IV, sizeof(ZERO_IV)));

    ISymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    uint8_t out[8];
    SByteSpan outSpan(out, sizeof(out));
    REQUIRE(encrypter->transform(SReadOnlyByteSpan(PLAINTEXT, 8), outSpan) == ERET_OK);
    REQUIRE(outSpan.size == 8);

    CHECK(std::memcmp(out, expected, 8) == 0);
}

TEST_CASE("TripleDES: two-key EDE (K3 == K1) round-trips via createEncrypter()/createDecrypter()") {
    const uint8_t K1[8] = { 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    const uint8_t K2[8] = { 0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F };

    uint8_t key16[16];
    std::memcpy(key16, K1, 8);
    std::memcpy(key16 + 8, K2, 8);

    ISymmetricPtr des3 = ISymmetric::builtIn(ESYM_3DES);
    ISymmetricKeyPtr key = des3->createKey(SReadOnlyByteSpan(key16, sizeof(key16)));
    REQUIRE(key);

    CBuffer iv;
    REQUIRE(des3->generateIV(key, iv) == ERET_OK);

    ISymmetricContextPtr ctx = des3->createContext(key);
    ctx->key(key, iv);

    const uint8_t plaintext[] = "certpp 3DES two-key round trip test message";

    ISymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    TArray<uint8_t> ciphertext;
    ciphertext.resize(sizeof(plaintext) + 16);
    SByteSpan cstep(ciphertext.begin(), ciphertext.size());
    REQUIRE(encrypter->transform(SReadOnlyByteSpan(plaintext, sizeof(plaintext)), cstep) == ERET_OK);
    size_t written = cstep.size;
    SByteSpan cfinal(ciphertext.begin() + written, ciphertext.size() - written);
    REQUIRE(encrypter->transformFinal(cfinal) == ERET_OK);
    written += cfinal.size;

    ISymmetricContextPtr dctx = des3->createContext(key);
    dctx->key(key, iv);

    ISymmetricTransformerPtr decrypter;
    REQUIRE(dctx->createDecrypter(decrypter) == ERET_OK);

    TArray<uint8_t> recovered;
    recovered.resize(written);
    SByteSpan rstep(recovered.begin(), recovered.size());
    REQUIRE(decrypter->transform(SReadOnlyByteSpan(ciphertext.begin(), written), rstep) == ERET_OK);
    size_t rwritten = rstep.size;
    SByteSpan rfinal(recovered.begin() + rwritten, recovered.size() - rwritten);
    REQUIRE(decrypter->transformFinal(rfinal) == ERET_OK);
    rwritten += rfinal.size;

    REQUIRE(rwritten == sizeof(plaintext));
    CHECK(std::memcmp(recovered.begin(), plaintext, sizeof(plaintext)) == 0);
}
