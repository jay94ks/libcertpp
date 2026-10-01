#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    // NIST SP 800-38A's shared example plaintext block, reused across the AES-128/192/256
    // vectors below (only the key and resulting ciphertext differ per key size).
    const uint8_t PLAINTEXT_BLOCK[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };

    const uint8_t ZERO_IV[16] = { 0 };

    // Encrypts a single 16-byte plaintext block under key via CBC with an all-zero IV: since
    // plaintext XOR 0 == plaintext, the first (and here, only) ciphertext block equals plain
    // single-block ECB encryption -- letting a textbook single-block AES known-answer vector
    // validate createEncrypter()/createContext() end-to-end, without this library needing to
    // expose a separate raw-ECB API of its own.
    bool encryptOneBlockEcbEquivalent(
        const ISymmetricKeyPtr& key, const uint8_t plaintext[16], uint8_t out[16]
    ) {
        ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
        ISymmetricContextPtr ctx = aes->createContext(key);
        ctx->key(key, CBuffer(ZERO_IV, sizeof(ZERO_IV)));

        ISymmetricTransformerPtr encrypter;
        if (ctx->createEncrypter(encrypter) != ERET_OK) {
            return false;
        }

        uint8_t buf[16];
        SByteSpan outSpan(buf, sizeof(buf));
        if (encrypter->transform(SReadOnlyByteSpan(plaintext, 16), outSpan) != ERET_OK) {
            return false;
        }
        if (outSpan.size != 16) {
            return false;
        }

        std::memcpy(out, buf, 16);
        return true;
    }
}

TEST_CASE("AES: builtIn(ESYM_AES) returns a usable algorithm instance accepting 128/192/256") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    REQUIRE(aes);

    bool acc128 = false, acc192 = false, acc256 = false;
    for (size_t i = 0; i < aes->keySizes().size(); ++i) {
        if (aes->keySizes()[i].includes(128)) acc128 = true;
        if (aes->keySizes()[i].includes(192)) acc192 = true;
        if (aes->keySizes()[i].includes(256)) acc256 = true;
    }
    CHECK(acc128);
    CHECK(acc192);
    CHECK(acc256);
}

TEST_CASE("AES: generateKey produces a key of the requested size") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);

    for (SKeySize bits : { 128, 192, 256 }) {
        ISymmetricKeyPtr key;
        REQUIRE(aes->generateKey(key, SKeySizeSpec(bits)) == ERET_OK);
        REQUIRE(key);
        CHECK(key->keySize() == bits / 8);
        CHECK(key->algorithm() == ESYM_AES);
    }
}

TEST_CASE("AES: generateKey rejects a key size outside keySizes()") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key;
    CHECK(aes->generateKey(key, SKeySizeSpec(123)) != ERET_OK);
    CHECK_FALSE(key);
}

TEST_CASE("AES: createKey rejects raw key material of the wrong length") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    uint8_t raw[15] = { 0 };
    CHECK_FALSE(aes->createKey(SReadOnlyByteSpan(raw, sizeof(raw))));
}

TEST_CASE("AES-128: matches the NIST SP 800-38A known-answer vector") {
    const uint8_t KEY[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const uint8_t EXPECTED[16] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    };

    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key = aes->createKey(SReadOnlyByteSpan(KEY, sizeof(KEY)));
    REQUIRE(key);

    uint8_t out[16];
    REQUIRE(encryptOneBlockEcbEquivalent(key, PLAINTEXT_BLOCK, out));
    CHECK(std::memcmp(out, EXPECTED, 16) == 0);
}

TEST_CASE("AES-192: matches the NIST SP 800-38A known-answer vector") {
    const uint8_t KEY[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    };
    const uint8_t EXPECTED[16] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
    };

    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key = aes->createKey(SReadOnlyByteSpan(KEY, sizeof(KEY)));
    REQUIRE(key);

    uint8_t out[16];
    REQUIRE(encryptOneBlockEcbEquivalent(key, PLAINTEXT_BLOCK, out));
    CHECK(std::memcmp(out, EXPECTED, 16) == 0);
}

TEST_CASE("AES-256: matches the NIST SP 800-38A known-answer vector") {
    const uint8_t KEY[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    const uint8_t EXPECTED[16] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    };

    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key = aes->createKey(SReadOnlyByteSpan(KEY, sizeof(KEY)));
    REQUIRE(key);

    uint8_t out[16];
    REQUIRE(encryptOneBlockEcbEquivalent(key, PLAINTEXT_BLOCK, out));
    CHECK(std::memcmp(out, EXPECTED, 16) == 0);
}

TEST_CASE("AES-CBC: encrypt/decrypt round-trips for messages of various lengths") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key;
    REQUIRE(aes->generateKey(key, SKeySizeSpec(256)) == ERET_OK);

    CBuffer iv;
    REQUIRE(aes->generateIV(key, iv) == ERET_OK);
    REQUIRE(iv.size() == 16);

    for (size_t len : { size_t(0), size_t(1), size_t(15), size_t(16), size_t(17), size_t(63), size_t(64), size_t(100) }) {
        TArray<uint8_t> plaintext;
        plaintext.resize(len);
        for (size_t i = 0; i < len; ++i) {
            plaintext[i] = static_cast<uint8_t>(i * 31 + 7);
        }

        ISymmetricContextPtr ctx = aes->createContext(key);
        ctx->key(key, iv);

        ISymmetricTransformerPtr encrypter;
        REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

        TArray<uint8_t> ciphertext;
        ciphertext.resize(len + 32); // room for up to two pad blocks worth of slack
        SByteSpan cstep(ciphertext.begin(), ciphertext.size());
        REQUIRE(encrypter->transform(SReadOnlyByteSpan(plaintext.begin(), plaintext.size()), cstep) == ERET_OK);

        size_t written = cstep.size;
        SByteSpan cfinal(ciphertext.begin() + written, ciphertext.size() - written);
        REQUIRE(encrypter->transformFinal(cfinal) == ERET_OK);
        written += cfinal.size;

        CHECK(written % 16 == 0);
        CHECK(written >= len + 1);

        ISymmetricContextPtr dctx = aes->createContext(key);
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

TEST_CASE("AES-CBC: decrypt rejects a tampered ciphertext") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key;
    REQUIRE(aes->generateKey(key, SKeySizeSpec(128)) == ERET_OK);

    CBuffer iv;
    REQUIRE(aes->generateIV(key, iv) == ERET_OK);

    ISymmetricContextPtr ctx = aes->createContext(key);
    ctx->key(key, iv);

    const uint8_t plaintext[] = "certpp AES-CBC tamper test message, over one block";

    ISymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    TArray<uint8_t> ciphertext;
    ciphertext.resize(sizeof(plaintext) + 32);
    SByteSpan cstep(ciphertext.begin(), ciphertext.size());
    REQUIRE(encrypter->transform(SReadOnlyByteSpan(plaintext, sizeof(plaintext)), cstep) == ERET_OK);
    size_t written = cstep.size;
    SByteSpan cfinal(ciphertext.begin() + written, ciphertext.size() - written);
    REQUIRE(encrypter->transformFinal(cfinal) == ERET_OK);
    written += cfinal.size;

    ciphertext[written - 1] ^= 0xFF; // --> corrupt the final (padding) block.

    ISymmetricContextPtr dctx = aes->createContext(key);
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

TEST_CASE("AES: createEncrypter fails without a key or a correctly-sized IV") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key;
    REQUIRE(aes->generateKey(key, SKeySizeSpec(128)) == ERET_OK);

    ISymmetricContextPtr ctxNoKey = aes->createContext(nullptr);
    ISymmetricTransformerPtr t1;
    CHECK(ctxNoKey->createEncrypter(t1) == ERET_KEY_EMPTY);

    ISymmetricContextPtr ctxNoIv = aes->createContext(key);
    ISymmetricTransformerPtr t2;
    CHECK(ctxNoIv->createEncrypter(t2) == ERET_KEY_PARAM);
}
