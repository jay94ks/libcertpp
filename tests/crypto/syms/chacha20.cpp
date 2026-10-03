#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <vector>

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

// ---------------------------------------------------------------------------------------------
// The four-block SSE2 path, against an independent scalar reference.
//
// RFC 8439's own vectors do not reach it: the AEAD vector in 2.8.2 is 114 bytes and the cipher
// vectors are smaller still, so every one of them is served entirely by the scalar loop. A
// vectorized path that is wrong past the first four blocks would pass all of them.
//
// So the reference below is ChaCha20's block function written out again from RFC 8439 2.3,
// sharing no code with the library's, and the comparison sweeps every length across the
// scalar/vector boundary at 256 bytes -- including the partial blocks on either side of it,
// where the two paths hand over to each other.

namespace {
    /* RFC 8439 2.3, implemented independently of ChaCha20Core. */
    struct ReferenceChaCha20 {
        static uint32_t rotl(uint32_t x, int n) {
            return (x << n) | (x >> (32 - n));
        }

        static void quarter(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
            a += b; d ^= a; d = rotl(d, 16);
            c += d; b ^= c; b = rotl(b, 12);
            a += b; d ^= a; d = rotl(d, 8);
            c += d; b ^= c; b = rotl(b, 7);
        }

        static void block(
            const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]
        ) {
            uint32_t s[16];
            s[0] = 0x61707865u; s[1] = 0x3320646eu;
            s[2] = 0x79622d32u; s[3] = 0x6b206574u;

            for (int i = 0; i < 8; ++i) {
                s[4 + i] = uint32_t(key[4 * i]) | (uint32_t(key[4 * i + 1]) << 8)
                         | (uint32_t(key[4 * i + 2]) << 16) | (uint32_t(key[4 * i + 3]) << 24);
            }

            s[12] = counter;
            for (int i = 0; i < 3; ++i) {
                s[13 + i] = uint32_t(nonce[4 * i]) | (uint32_t(nonce[4 * i + 1]) << 8)
                          | (uint32_t(nonce[4 * i + 2]) << 16) | (uint32_t(nonce[4 * i + 3]) << 24);
            }

            uint32_t w[16];
            for (int i = 0; i < 16; ++i) {
                w[i] = s[i];
            }

            for (int r = 0; r < 10; ++r) {
                quarter(w[0], w[4], w[8], w[12]);
                quarter(w[1], w[5], w[9], w[13]);
                quarter(w[2], w[6], w[10], w[14]);
                quarter(w[3], w[7], w[11], w[15]);
                quarter(w[0], w[5], w[10], w[15]);
                quarter(w[1], w[6], w[11], w[12]);
                quarter(w[2], w[7], w[8], w[13]);
                quarter(w[3], w[4], w[9], w[14]);
            }

            for (int i = 0; i < 16; ++i) {
                const uint32_t v = w[i] + s[i];
                out[4 * i + 0] = uint8_t(v);
                out[4 * i + 1] = uint8_t(v >> 8);
                out[4 * i + 2] = uint8_t(v >> 16);
                out[4 * i + 3] = uint8_t(v >> 24);
            }
        }

        /* The keystream from counter 1, which is what the AEAD's payload uses. */
        static std::vector<uint8_t> keystreamFromOne(
            const uint8_t key[32], const uint8_t nonce[12], size_t length
        ) {
            std::vector<uint8_t> out;
            uint32_t counter = 1;

            while (out.size() < length) {
                uint8_t blk[64];
                block(key, nonce, counter, blk);
                ++counter;

                for (size_t i = 0; i < 64 && out.size() < length; ++i) {
                    out.push_back(blk[i]);
                }
            }

            return out;
        }
    };
}

TEST_CASE("ChaCha20: the vectorized path matches an independent reference at every length") {
    uint8_t key[32];
    uint8_t nonce[12];
    for (size_t i = 0; i < 32; ++i) {
        key[i] = uint8_t(i * 7 + 1);
    }
    for (size_t i = 0; i < 12; ++i) {
        nonce[i] = uint8_t(i * 5 + 3);
    }

    CChaCha20Poly1305 aead;
    REQUIRE(aead.reset(SReadOnlyByteSpan(key, sizeof(key))));

    // Every length from 0 to 600 covers: the scalar-only region below 256, the handover at
    // exactly 256, the vector region, and every partial-block remainder after a vector group.
    // Then a few larger sizes, where several vector groups run back to back.
    std::vector<size_t> lengths;
    for (size_t n = 0; n <= 600; ++n) {
        lengths.push_back(n);
    }
    for (size_t n : { size_t(1024), size_t(4096), size_t(16384), size_t(65536) }) {
        lengths.push_back(n);
    }

    for (size_t n : lengths) {
        // Sealing a zero buffer yields the keystream itself, which is what makes this a direct
        // comparison of the two implementations rather than of ciphertexts.
        std::vector<uint8_t> buffer(n, 0x00);
        uint8_t tag[16];

        REQUIRE(aead.seal(SReadOnlyByteSpan(nonce, sizeof(nonce)),
                          SReadOnlyByteSpan(nullptr, 0),
                          SReadOnlyByteSpan(buffer.data(), n),
                          SByteSpan(buffer.data(), n),
                          SByteSpan(tag, sizeof(tag))));

        const std::vector<uint8_t> expected =
            ReferenceChaCha20::keystreamFromOne(key, nonce, n);

        REQUIRE(buffer.size() == expected.size());
        for (size_t i = 0; i < n; ++i) {
            // Reported per byte so a failure names the exact offset, which immediately says
            // whether the fault is in a vector group, a transpose lane, or the remainder.
            REQUIRE(buffer[i] == expected[i]);
        }
    }
}

TEST_CASE("ChaCha20: the stream cipher agrees with the reference across chunk boundaries") {
    uint8_t key[32];
    uint8_t nonce[12];
    for (size_t i = 0; i < 32; ++i) {
        key[i] = uint8_t(0xA0 + i);
    }
    for (size_t i = 0; i < 12; ++i) {
        nonce[i] = uint8_t(0x10 + i);
    }

    // The transformer keeps a cursor across calls, so feeding it in awkward pieces exercises the
    // handover between its byte-wise edges and the block-aligned vector bulk. The chunk sizes
    // straddle both boundaries that matter: 64 (one block) and 256 (one vector group).
    const size_t total = 1000;

    // The stream cipher starts at counter 0, unlike the AEAD payload, which starts at 1.
    std::vector<uint8_t> expected;
    uint32_t refCounter = 0;
    while (expected.size() < total) {
        uint8_t blk[64];
        ReferenceChaCha20::block(key, nonce, refCounter, blk);
        ++refCounter;
        for (size_t i = 0; i < 64 && expected.size() < total; ++i) {
            expected.push_back(blk[i]);
        }
    }

    for (size_t chunk : { size_t(1), size_t(7), size_t(63), size_t(64), size_t(65),
                          size_t(255), size_t(256), size_t(257) }) {
        ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);
        ISymmetricKeyPtr skey = cc->createKey(SReadOnlyByteSpan(key, sizeof(key)));
        REQUIRE(skey);

        ISymmetricContextPtr ctx = cc->createContext(skey);
        ctx->key(skey, CBuffer(nonce, sizeof(nonce)));

        ISymmetricTransformerPtr enc;
        REQUIRE(ctx->createEncrypter(enc) == ERET_OK);

        std::vector<uint8_t> input(total, 0x00);
        std::vector<uint8_t> output(total, 0xFF);

        size_t offset = 0;
        while (offset < total) {
            const size_t take = (total - offset < chunk) ? (total - offset) : chunk;

            SByteSpan piece(output.data() + offset, take);
            REQUIRE(enc->transform(SReadOnlyByteSpan(input.data() + offset, take), piece)
                    == ERET_OK);
            REQUIRE(piece.size == take);
            offset += take;
        }

        for (size_t i = 0; i < total; ++i) {
            REQUIRE(output[i] == expected[i]);
        }
    }
}
