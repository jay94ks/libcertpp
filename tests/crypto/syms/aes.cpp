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

// --- Unpadded CBC (ESYMPAD_NONE) ------------------------------------------------------------
//
// The default stays PKCS#7, which every test above depends on; these exercise the opt-in a
// protocol that pads for itself needs (IKEv2, RFC 7296 3.14, builds its own padding into the
// payload and would otherwise get a second, unexpected pad block underneath it).

namespace {
    // SP 800-38A F.2.1/F.2.2's CBC-AES128 example: four blocks, with the IV the standard prints
    // rather than the all-zero one the single-block vectors above use. Padded CBC cannot be held
    // against it directly -- it appends a fifth, all-16s block -- so this is also the first time
    // this library's CBC chaining is checked against a published multi-block vector.
    const uint8_t CBC_KEY[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const uint8_t CBC_IV[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t CBC_PLAINTEXT[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const uint8_t CBC_CIPHERTEXT[64] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
    };

    // Runs one whole transform through a freshly built transformer, so each case starts from the
    // IV rather than wherever a previous one left the chaining value.
    ERetCode runUnpadded(
        bool encrypting, const ISymmetricKeyPtr& key, const CBuffer& iv,
        const SReadOnlyByteSpan& input, TArray<uint8_t>& output, size_t& written
    ) {
        written = 0;

        ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
        ISymmetricContextPtr ctx = aes->createContext(key);
        ctx->padding(ESYMPAD_NONE);
        ctx->key(key, iv);

        // padding() must survive key(), or an opt-in made before the key was bound would be
        // silently discarded -- which is how a caller ends up emitting PKCS#7 by accident.
        if (ctx->padding() != ESYMPAD_NONE) {
            return ERET_BADREQ;
        }

        ISymmetricTransformerPtr transformer;
        ERetCode rc = encrypting ? ctx->createEncrypter(transformer)
                                 : ctx->createDecrypter(transformer);
        if (rc != ERET_OK) {
            return rc;
        }

        output.resize(input.size + 32);

        SByteSpan step(output.begin(), output.size());
        rc = transformer->transform(input, step);
        if (rc != ERET_OK) {
            return rc;
        }
        written = step.size;

        SByteSpan last(output.begin() + written, output.size() - written);
        rc = transformer->transformFinal(last);
        if (rc != ERET_OK) {
            return rc;
        }
        written += last.size;

        return ERET_OK;
    }
}

TEST_CASE("AES-CBC unpadded: matches the NIST SP 800-38A F.2 four-block vector") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key = aes->createKey(SReadOnlyByteSpan(CBC_KEY, sizeof(CBC_KEY)));
    REQUIRE(key);

    const CBuffer iv(CBC_IV, sizeof(CBC_IV));

    TArray<uint8_t> ciphertext;
    size_t written = 0;
    REQUIRE(runUnpadded(true, key, iv,
                        SReadOnlyByteSpan(CBC_PLAINTEXT, sizeof(CBC_PLAINTEXT)),
                        ciphertext, written) == ERET_OK);

    // Exactly as long as the plaintext: no pad block, which is the whole point.
    REQUIRE(written == sizeof(CBC_PLAINTEXT));
    CHECK(std::memcmp(ciphertext.begin(), CBC_CIPHERTEXT, sizeof(CBC_CIPHERTEXT)) == 0);

    TArray<uint8_t> recovered;
    REQUIRE(runUnpadded(false, key, iv,
                        SReadOnlyByteSpan(CBC_CIPHERTEXT, sizeof(CBC_CIPHERTEXT)),
                        recovered, written) == ERET_OK);
    REQUIRE(written == sizeof(CBC_PLAINTEXT));
    CHECK(std::memcmp(recovered.begin(), CBC_PLAINTEXT, sizeof(CBC_PLAINTEXT)) == 0);
}

TEST_CASE("AES-CBC: the default is still PKCS#7, and it still pads a block-aligned plaintext") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key = aes->createKey(SReadOnlyByteSpan(CBC_KEY, sizeof(CBC_KEY)));
    REQUIRE(key);

    const CBuffer iv(CBC_IV, sizeof(CBC_IV));

    ISymmetricContextPtr ctx = aes->createContext(key);
    CHECK(ctx->padding() == ESYMPAD_PKCS7);
    ctx->key(key, iv);

    ISymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    TArray<uint8_t> padded;
    padded.resize(sizeof(CBC_PLAINTEXT) + 32);
    SByteSpan step(padded.begin(), padded.size());
    REQUIRE(encrypter->transform(
        SReadOnlyByteSpan(CBC_PLAINTEXT, sizeof(CBC_PLAINTEXT)), step) == ERET_OK);
    size_t written = step.size;
    SByteSpan last(padded.begin() + written, padded.size() - written);
    REQUIRE(encrypter->transformFinal(last) == ERET_OK);
    written += last.size;

    // A block-aligned plaintext still gets a whole extra block of padding under PKCS#7 -- exactly
    // what a protocol that pads for itself must not have added -- and the blocks before it are
    // identical to the unpadded case's, so nothing about the chaining changed.
    CHECK(written == sizeof(CBC_PLAINTEXT) + 16);
    CHECK(std::memcmp(padded.begin(), CBC_CIPHERTEXT, sizeof(CBC_CIPHERTEXT)) == 0);
}

TEST_CASE("AES-CBC unpadded: a length that isn't a whole number of blocks is refused") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key = aes->createKey(SReadOnlyByteSpan(CBC_KEY, sizeof(CBC_KEY)));
    REQUIRE(key);

    const CBuffer iv(CBC_IV, sizeof(CBC_IV));

    for (size_t len : { size_t(1), size_t(15), size_t(17), size_t(31), size_t(63) }) {
        CAPTURE(len);

        TArray<uint8_t> out;
        size_t written = 0;

        // Refused rather than rounded up: silently padding here would produce a ciphertext longer
        // than the caller asked for, and silently truncating would lose data.
        CHECK(runUnpadded(true, key, iv, SReadOnlyByteSpan(CBC_PLAINTEXT, len), out, written)
            == ERET_BADREQ);
        CHECK(runUnpadded(false, key, iv, SReadOnlyByteSpan(CBC_CIPHERTEXT, len), out, written)
            == ERET_BADREQ);
    }
}

TEST_CASE("AES-CBC unpadded: round-trips at every block-aligned length, including empty") {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr key;
    REQUIRE(aes->generateKey(key, SKeySizeSpec(256)) == ERET_OK);

    CBuffer iv;
    REQUIRE(aes->generateIV(key, iv) == ERET_OK);

    for (size_t len : { size_t(0), size_t(16), size_t(32), size_t(48), size_t(160) }) {
        CAPTURE(len);

        TArray<uint8_t> plaintext;
        plaintext.resize(len);
        for (size_t i = 0; i < len; ++i) {
            plaintext[i] = static_cast<uint8_t>(i * 31 + 7);
        }

        TArray<uint8_t> ciphertext;
        size_t written = 0;
        REQUIRE(runUnpadded(true, key, iv,
                            SReadOnlyByteSpan(plaintext.begin(), len), ciphertext, written)
            == ERET_OK);
        REQUIRE(written == len);

        TArray<uint8_t> recovered;
        size_t rwritten = 0;
        REQUIRE(runUnpadded(false, key, iv,
                            SReadOnlyByteSpan(ciphertext.begin(), written), recovered, rwritten)
            == ERET_OK);
        REQUIRE(rwritten == len);

        if (len > 0) {
            CHECK(SReadOnlyByteSpan(recovered.begin(), rwritten)
                .sequencialEqual(SReadOnlyByteSpan(plaintext.begin(), len)));
        }
    }
}
