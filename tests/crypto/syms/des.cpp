#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    const uint8_t ZERO_IV[8] = { 0 };

    // See aes.cpp's identical helper: CBC with an all-zero IV makes the first (and here, only)
    // ciphertext block equal plain single-block ECB encryption.
    bool encryptOneBlockEcbEquivalent(
        const ISymmetricKeyPtr& key, const uint8_t plaintext[8], uint8_t out[8]
    ) {
        ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
        ISymmetricContextPtr ctx = des->createContext(key);
        ctx->key(key, CBuffer(ZERO_IV, sizeof(ZERO_IV)));

        ISymmetricTransformerPtr encrypter;
        if (ctx->createEncrypter(encrypter) != ERET_OK) {
            return false;
        }

        uint8_t buf[8];
        SByteSpan outSpan(buf, sizeof(buf));
        if (encrypter->transform(SReadOnlyByteSpan(plaintext, 8), outSpan) != ERET_OK) {
            return false;
        }
        if (outSpan.size != 8) {
            return false;
        }

        std::memcpy(out, buf, 8);
        return true;
    }
}

TEST_CASE("DES: builtIn(ESYM_DES) returns a usable algorithm instance accepting a 64-bit key") {
    ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
    REQUIRE(des);

    bool accepts64 = false;
    for (size_t i = 0; i < des->keySizes().size(); ++i) {
        if (des->keySizes()[i].includes(64)) {
            accepts64 = true;
        }
    }
    CHECK(accepts64);
}

TEST_CASE("DES: generateKey produces an 8-byte key") {
    ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
    ISymmetricKeyPtr key;
    REQUIRE(des->generateKey(key, SKeySizeSpec(64)) == ERET_OK);
    REQUIRE(key);
    CHECK(key->keySize() == 8);
    CHECK(key->algorithm() == ESYM_DES);
}

TEST_CASE("DES: generateKey rejects a key size outside keySizes()") {
    ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
    ISymmetricKeyPtr key;
    CHECK(des->generateKey(key, SKeySizeSpec(128)) != ERET_OK);
    CHECK_FALSE(key);
}

TEST_CASE("DES: matches the classic FIPS 46 worked example") {
    // Key = 13 34 57 79 9B BC DF F1, Plaintext = 01 23 45 67 89 AB CD EF,
    // Ciphertext = 85 E8 13 54 0F 0A B4 05 -- the canonical textbook DES example.
    const uint8_t KEY[8] = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    const uint8_t PLAINTEXT[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const uint8_t EXPECTED[8] = { 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };

    ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
    ISymmetricKeyPtr key = des->createKey(SReadOnlyByteSpan(KEY, sizeof(KEY)));
    REQUIRE(key);

    uint8_t out[8];
    REQUIRE(encryptOneBlockEcbEquivalent(key, PLAINTEXT, out));
    CHECK(std::memcmp(out, EXPECTED, 8) == 0);
}

TEST_CASE("DES-CBC: encrypt/decrypt round-trips for messages of various lengths") {
    ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
    ISymmetricKeyPtr key;
    REQUIRE(des->generateKey(key, SKeySizeSpec(64)) == ERET_OK);

    CBuffer iv;
    REQUIRE(des->generateIV(key, iv) == ERET_OK);
    REQUIRE(iv.size() == 8);

    for (size_t len : { size_t(0), size_t(1), size_t(7), size_t(8), size_t(9), size_t(31), size_t(50) }) {
        TArray<uint8_t> plaintext;
        plaintext.resize(len);
        for (size_t i = 0; i < len; ++i) {
            plaintext[i] = static_cast<uint8_t>(i * 17 + 3);
        }

        ISymmetricContextPtr ctx = des->createContext(key);
        ctx->key(key, iv);

        ISymmetricTransformerPtr encrypter;
        REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

        TArray<uint8_t> ciphertext;
        ciphertext.resize(len + 16);
        SByteSpan cstep(ciphertext.begin(), ciphertext.size());
        REQUIRE(encrypter->transform(SReadOnlyByteSpan(plaintext.begin(), plaintext.size()), cstep) == ERET_OK);

        size_t written = cstep.size;
        SByteSpan cfinal(ciphertext.begin() + written, ciphertext.size() - written);
        REQUIRE(encrypter->transformFinal(cfinal) == ERET_OK);
        written += cfinal.size;

        CHECK(written % 8 == 0);
        CHECK(written >= len + 1);

        ISymmetricContextPtr dctx = des->createContext(key);
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

        REQUIRE(rwritten == len);
        CHECK(SReadOnlyByteSpan(recovered.begin(), rwritten)
            .sequencialEqual(SReadOnlyByteSpan(plaintext.begin(), plaintext.size())));
    }
}

TEST_CASE("DES-CBC: decrypt rejects a tampered ciphertext") {
    ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);
    ISymmetricKeyPtr key;
    REQUIRE(des->generateKey(key, SKeySizeSpec(64)) == ERET_OK);

    CBuffer iv;
    REQUIRE(des->generateIV(key, iv) == ERET_OK);

    ISymmetricContextPtr ctx = des->createContext(key);
    ctx->key(key, iv);

    const uint8_t plaintext[] = "certpp DES tamper test, more than one block long";

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

    ciphertext[written - 1] ^= 0xFF;

    ISymmetricContextPtr dctx = des->createContext(key);
    dctx->key(key, iv);

    ISymmetricTransformerPtr decrypter;
    REQUIRE(dctx->createDecrypter(decrypter) == ERET_OK);

    TArray<uint8_t> recovered;
    recovered.resize(written);
    SByteSpan rstep(recovered.begin(), recovered.size());
    REQUIRE(decrypter->transform(SReadOnlyByteSpan(ciphertext.begin(), written), rstep) == ERET_OK);

    SByteSpan rfinal(recovered.begin() + rstep.size, recovered.size() - rstep.size);
    CHECK(decrypter->transformFinal(rfinal) != ERET_OK);
}
