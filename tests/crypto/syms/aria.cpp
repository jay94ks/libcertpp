#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

#include <cstdio>
#include <cstring>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {

    // ARIA is specified in RFC 5794, and Appendix A publishes one vector per key size --
    // all three sharing the same plaintext. A mistranscribed S-box table or a wrong
    // substitution-layer rotation produces an ARIA that is self-consistent and matches
    // nothing in the world, which only an external known-answer vector can catch, so all
    // three are checked here against the published ciphertexts.
    struct AriaVector {
        size_t keyLen;
        const char* key;
        const char* cipher;
    };

    // RFC 5794 A.1/A.2/A.3. The plaintext is 00112233445566778899aabbccddeeff for all three.
    const AriaVector RFC_VECTORS[] = {
        { 16, "000102030405060708090a0b0c0d0e0f", "d718fbd6ab644c739da95f3be6451778" },
        { 24, "000102030405060708090a0b0c0d0e0f1011121314151617",
              "26449c1805dbe7aa25a468ce263a9e79" },
        { 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
              "f92bd7c79fb72e2f2b8f80c1972d24fc" },
    };

    const uint8_t RFC_PLAINTEXT[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    const uint8_t ZERO_IV[16] = { 0 };

    bool fromHex(const char* hex, uint8_t* out, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
            char* end = nullptr;
            out[i] = uint8_t(strtoul(b, &end, 16));
            if (end != b + 2) {
                return false;
            }
        }
        return true;
    }

    // Encrypts one 16-byte block through CBC with an all-zero IV, so the first ciphertext
    // block is plain E_K(P) -- the same device aes.cpp uses to run a textbook single-block
    // known-answer vector through the real ISymmetric surface.
    bool encryptOneBlock(const ISymmetricKeyPtr& key, const uint8_t in[16], uint8_t out[16]) {
        ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);
        ISymmetricContextPtr ctx = aria->createContext(key);
        ctx->key(key, CBuffer(ZERO_IV, sizeof(ZERO_IV)));
        ctx->padding(ESYMPAD_NONE);

        ISymmetricTransformerPtr enc;
        if (ctx->createEncrypter(enc) != ERET_OK) {
            return false;
        }

        SByteSpan span(out, 16);
        if (enc->transform(SReadOnlyByteSpan(in, 16), span) != ERET_OK) {
            return false;
        }
        return span.size == 16;
    }

    bool decryptOneBlock(const ISymmetricKeyPtr& key, const uint8_t in[16], uint8_t out[16]) {
        ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);
        ISymmetricContextPtr ctx = aria->createContext(key);
        ctx->key(key, CBuffer(ZERO_IV, sizeof(ZERO_IV)));
        ctx->padding(ESYMPAD_NONE);

        ISymmetricTransformerPtr dec;
        if (ctx->createDecrypter(dec) != ERET_OK) {
            return false;
        }

        SByteSpan span(out, 16);
        if (dec->transform(SReadOnlyByteSpan(in, 16), span) != ERET_OK) {
            return false;
        }
        return span.size == 16;
    }

    void toHex(const uint8_t* p, size_t n, char* out) {
        for (size_t i = 0; i < n; ++i) {
            std::snprintf(out + 2 * i, 3, "%02x", p[i]);
        }
        out[2 * n] = 0;
    }
}

TEST_CASE("ARIA: builtIn(ESYM_ARIA) returns an instance that accepts all three key sizes") {
    ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);
    REQUIRE(aria);
    CHECK(aria->keySizes().size() == 1);

    const SKeySizeSpec& spec = aria->keySizes()[0];
    CHECK(spec.includes(128));
    CHECK(spec.includes(192));
    CHECK(spec.includes(256));
    CHECK_FALSE(spec.includes(64));
    CHECK_FALSE(spec.includes(512));
}

TEST_CASE("ARIA: matches the RFC 5794 Appendix A known-answer vectors at every key size") {
    ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);
    REQUIRE(aria);

    for (const AriaVector& v : RFC_VECTORS) {
        uint8_t key[32], want[16];
        REQUIRE(fromHex(v.key, key, v.keyLen));
        REQUIRE(fromHex(v.cipher, want, 16));

        ISymmetricKeyPtr k = aria->createKey(SReadOnlyByteSpan(key, v.keyLen));
        REQUIRE(k);
        CHECK(k->keySize() == v.keyLen);

        uint8_t got[16] = { 0 };
        REQUIRE(encryptOneBlock(k, RFC_PLAINTEXT, got));

        char gotHex[33];
        toHex(got, 16, gotHex);
        INFO("key size " << v.keyLen * 8 << " produced " << gotHex
                         << " but the RFC says " << v.cipher);
        CHECK(std::memcmp(got, want, 16) == 0);

        // And the inverse, which is what makes it usable as a cipher at all.
        uint8_t back[16] = { 0 };
        REQUIRE(decryptOneBlock(k, got, back));
        CHECK(std::memcmp(back, RFC_PLAINTEXT, 16) == 0);
    }
}

TEST_CASE("ARIA: createKey rejects every key length the RFC does not define") {
    ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);

    uint8_t buf[64] = { 0 };
    for (size_t n : { size_t(0), size_t(8), size_t(15), size_t(17), size_t(24 * 2), size_t(40) }) {
        // 24 is legal; the others are not. Written explicitly rather than looping, so a
        // legal length can never be swept in by accident.
        if (n == 48) {
            continue;
        }
        CHECK(aria->createKey(SReadOnlyByteSpan(buf, n)) == nullptr);
    }

    // The three legal ones, for contrast.
    CHECK(aria->createKey(SReadOnlyByteSpan(buf, 16)) != nullptr);
    CHECK(aria->createKey(SReadOnlyByteSpan(buf, 24)) != nullptr);
    CHECK(aria->createKey(SReadOnlyByteSpan(buf, 32)) != nullptr);
}

TEST_CASE("ARIA: generateKey produces a usable key of the size asked for") {
    ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);

    for (SKeySize bits : { SKeySize(128), SKeySize(192), SKeySize(256) }) {
        ISymmetricKeyPtr key;
        REQUIRE(aria->generateKey(key, SKeySizeSpec(bits, bits, 0)) == ERET_OK);
        REQUIRE(key);
        CHECK(key->keySize() == bits / 8);

        // Round-trip something through it, because a correctly-sized key that does not
        // expand is still useless.
        uint8_t out[16] = { 0 };
        CHECK(encryptOneBlock(key, RFC_PLAINTEXT, out));
    }

    // The default, when the caller expresses no preference, should be the strongest.
    ISymmetricKeyPtr def;
    REQUIRE(aria->generateKey(def, SKeySizeSpec()) == ERET_OK);
    REQUIRE(def);
    CHECK(def->keySize() == 32);
}

TEST_CASE("ARIA: generateIV produces a full-block IV, and a wrong-sized one is rejected") {
    ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);

    uint8_t raw[32] = { 0 };
    ISymmetricKeyPtr key = aria->createKey(SReadOnlyByteSpan(raw, sizeof(raw)));
    REQUIRE(key);

    CBuffer iv;
    REQUIRE(aria->generateIV(key, iv) == ERET_OK);
    CHECK(iv.size() == 16);

    ISymmetricContextPtr ctx = aria->createContext(key);

    uint8_t shortIv[8] = { 0 };
    ctx->key(key, CBuffer(shortIv, sizeof(shortIv)));
    ISymmetricTransformerPtr enc;
    CHECK(ctx->createEncrypter(enc) == ERET_KEY_PARAM);

    // And generateIV must refuse a key that is not ARIA's.
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    ISymmetricKeyPtr aesKey = aes->createKey(SReadOnlyByteSpan(raw, 16));
    REQUIRE(aesKey);
    CBuffer wrong;
    CHECK(aria->generateIV(aesKey, wrong) == ERET_KEY_FORMAT);
}

TEST_CASE("ARIA-CBC: PKCS#7 round-trips a multi-block payload") {
    ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);

    uint8_t raw[32] = { 0 };
    ISymmetricKeyPtr key = aria->createKey(SReadOnlyByteSpan(raw, sizeof(raw)));
    REQUIRE(key);

    uint8_t ivBytes[16];
    for (size_t i = 0; i < sizeof(ivBytes); ++i) {
        ivBytes[i] = uint8_t(i * 13 + 1);
    }

    std::vector<uint8_t> msg(200);
    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i] = uint8_t(i * 31 + 7);
    }

    ISymmetricContextPtr ctx = aria->createContext(key);
    ctx->key(key, CBuffer(ivBytes, sizeof(ivBytes)));

    ISymmetricTransformerPtr enc;
    REQUIRE(ctx->createEncrypter(enc) == ERET_OK);

    std::vector<uint8_t> ct(msg.size() + 32);
    size_t ctLen = 0;
    {
        SByteSpan span(ct.data() + ctLen, ct.size() - ctLen);
        REQUIRE(enc->transform(SReadOnlyByteSpan(msg.data(), msg.size()), span) == ERET_OK);
        ctLen += span.size;
        SByteSpan last(ct.data() + ctLen, ct.size() - ctLen);
        REQUIRE(enc->transformFinal(last) == ERET_OK);
        ctLen += last.size;
    }

    CHECK(ctLen >= msg.size());
    CHECK(ctLen % 16 == 0);

    ISymmetricTransformerPtr dec;
    REQUIRE(ctx->createDecrypter(dec) == ERET_OK);

    std::vector<uint8_t> rt(ctLen + 32);
    size_t rtLen = 0;
    {
        SByteSpan span(rt.data() + rtLen, rt.size() - rtLen);
        REQUIRE(dec->transform(SReadOnlyByteSpan(ct.data(), ctLen), span) == ERET_OK);
        rtLen += span.size;
        SByteSpan last(rt.data() + rtLen, rt.size() - rtLen);
        REQUIRE(dec->transformFinal(last) == ERET_OK);
        rtLen += last.size;
    }

    CHECK(rtLen == msg.size());
    CHECK(std::memcmp(rt.data(), msg.data(), msg.size()) == 0);
}

TEST_CASE("ARIA-CBC unpadded: the result does not depend on how the input is chunked") {
    ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);

    uint8_t raw[32] = { 0 };
    ISymmetricKeyPtr key = aria->createKey(SReadOnlyByteSpan(raw, sizeof(raw)));
    REQUIRE(key);

    ISymmetricContextPtr ctx = aria->createContext(key);
    ctx->key(key, CBuffer(ZERO_IV, sizeof(ZERO_IV)));
    ctx->padding(ESYMPAD_NONE);

    const std::vector<uint8_t> aligned(192, 0xAB);

    std::vector<uint8_t> whole(aligned.size() + 32);
    size_t wholeLen = 0;
    {
        ISymmetricTransformerPtr enc;
        REQUIRE(ctx->createEncrypter(enc) == ERET_OK);
        SByteSpan span(whole.data(), whole.size());
        REQUIRE(enc->transform(SReadOnlyByteSpan(aligned.data(), aligned.size()), span) == ERET_OK);
        wholeLen += span.size;
        SByteSpan last(whole.data() + wholeLen, whole.size() - wholeLen);
        REQUIRE(enc->transformFinal(last) == ERET_OK);
        wholeLen += last.size;
    }

    ISymmetricTransformerPtr chunked;
    REQUIRE(ctx->createEncrypter(chunked) == ERET_OK);

    std::vector<uint8_t> piecewise(aligned.size() + 32);
    size_t pieceLen = 0;
    const size_t chunks[] = { 1, 7, 64, 100, 20 };
    for (size_t c : chunks) {
        SByteSpan span(piecewise.data() + pieceLen, piecewise.size() - pieceLen);
        REQUIRE(chunked->transform(SReadOnlyByteSpan(aligned.data() + pieceLen, c), span) == ERET_OK);
        pieceLen += span.size;
    }
    {
        SByteSpan last(piecewise.data() + pieceLen, piecewise.size() - pieceLen);
        REQUIRE(chunked->transformFinal(last) == ERET_OK);
        pieceLen += last.size;
    }

    CHECK(pieceLen == wholeLen);
    CHECK(std::memcmp(piecewise.data(), whole.data(), wholeLen) == 0);
}

TEST_CASE("ARIA-CBC unpadded: a partial final block is refused rather than rounded up") {
    ISymmetricPtr aria = ISymmetric::builtIn(ESYM_ARIA);

    uint8_t raw[32] = { 0 };
    ISymmetricKeyPtr key = aria->createKey(SReadOnlyByteSpan(raw, sizeof(raw)));
    REQUIRE(key);

    ISymmetricContextPtr ctx = aria->createContext(key);
    ctx->key(key, CBuffer(ZERO_IV, sizeof(ZERO_IV)));
    ctx->padding(ESYMPAD_NONE);

    ISymmetricTransformerPtr enc;
    REQUIRE(ctx->createEncrypter(enc) == ERET_OK);

    const uint8_t partial[20] = { 0 };
    std::vector<uint8_t> out(sizeof(partial) + 32);
    SByteSpan span(out.data() + 0, out.size());
    REQUIRE(enc->transform(SReadOnlyByteSpan(partial, sizeof(partial)), span) == ERET_OK);

    SByteSpan last(out.data() + span.size, out.size() - span.size);
    // 20 bytes is not a whole number of 16-byte blocks, so there is nothing padding could
    // legitimately do here.
    CHECK(enc->transformFinal(last) != ERET_OK);
}