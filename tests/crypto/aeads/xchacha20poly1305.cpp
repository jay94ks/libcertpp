// XChaCha20-Poly1305, against draft-irtf-cfrg-xchacha's published vectors: 2.2.1 (HChaCha20) and
// A.3.1 (the AEAD).
//
// A round trip proves nothing here. Both of this construction's own pitfalls -- restoring the
// feed-forward that HChaCha20 omits, and building the inner nonce as nonce[16:24] || 00000000
// instead of 00000000 || nonce[16:24] -- produce an AEAD that seals and opens perfectly against
// itself and interoperates with nothing, as does taking the wrong 32 bytes of HChaCha20's output.
// So does every pitfall the inner RFC 8439 AEAD already has. Only the draft's bytes catch any of
// it, which is why the subkey is checked separately from the ciphertext rather than only end to
// end.
//
// The vectors marked "derived" below are not published: they come from an independent
// implementation that reproduces the published ones exactly, and they exist to cover the shapes
// the draft does not (an empty plaintext, an AAD whose length is not a multiple of 16).

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    std::vector<uint8_t> fromHex(const char* hex) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') { return c - '0'; }
            if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
            if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
            return -1;
        };

        std::vector<uint8_t> out;
        for (const char* p = hex; *p; ++p) {
            if (nibble(*p) < 0) {
                continue;   // skip whitespace, so vectors can be laid out as the draft prints them
            }
            const int hi = nibble(*p);
            ++p;
            while (*p && nibble(*p) < 0) { ++p; }
            if (!*p) { break; }
            out.push_back(uint8_t((hi << 4) | nibble(*p)));
        }
        return out;
    }

    std::vector<uint8_t> ascii(const char* text) {
        std::vector<uint8_t> out;
        for (const char* p = text; *p; ++p) {
            out.push_back(uint8_t(*p));
        }
        return out;
    }

    SReadOnlyByteSpan readOf(const std::vector<uint8_t>& v) {
        return v.empty() ? SReadOnlyByteSpan(nullptr, 0) : SReadOnlyByteSpan(v.data(), v.size());
    }

    SByteSpan writeOf(std::vector<uint8_t>& v) {
        return v.empty() ? SByteSpan(nullptr, 0) : SByteSpan(v.data(), v.size());
    }

    // The draft's HChaCha20 vectors carry a 16-byte nonce; deriveSubkey() takes the AEAD's 24-byte
    // one and reads the first 16. The eight bytes appended here are deliberately non-zero junk:
    // if they were ever read, a vector would fail rather than quietly agree.
    std::vector<uint8_t> padNonce(const std::vector<uint8_t>& nonce16) {
        std::vector<uint8_t> out = nonce16;
        for (size_t i = 0; i < 8; ++i) {
            out.push_back(uint8_t(0xa5 + i));
        }
        return out;
    }

    std::vector<uint8_t> subkeyOf(const char* keyHex, const char* nonce16Hex) {
        const std::vector<uint8_t> key = fromHex(keyHex);
        const std::vector<uint8_t> nonce = padNonce(fromHex(nonce16Hex));

        CXChaCha20Poly1305 aead;
        REQUIRE(aead.reset(readOf(key)));

        std::vector<uint8_t> subkey(CXChaCha20Poly1305::SUBKEY_BYTES);
        REQUIRE(aead.deriveSubkey(readOf(nonce), writeOf(subkey)));
        return subkey;
    }
}

// draft-irtf-cfrg-xchacha 2.2.1. The one vector that pins HChaCha20 itself: a feed-forward added
// back, or the wrong eight output words taken, fails here and nowhere a round trip would look.
TEST_CASE("CXChaCha20Poly1305: HChaCha20, draft 2.2.1") {
    const std::vector<uint8_t> expected = fromHex(
        "82413b42 27b27bfe d30e4250 8a877d73"
        "a0f9e4d5 8a74a853 c12ec413 26d3ecdc");

    const std::vector<uint8_t> subkey = subkeyOf(
        "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f"
        "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f",
        "00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27");

    CHECK(subkey == expected);
}

// Derived, not published: an all-zero input, where a missing round or a mis-set constant would
// otherwise still look structured, and a second key/nonce pair so no single vector carries the
// whole function.
TEST_CASE("CXChaCha20Poly1305: HChaCha20, derived vectors") {
    CHECK(subkeyOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000") == fromHex(
        "1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586"));

    CHECK(subkeyOf(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "101112131415161718191a1b1c1d1e1f") == fromHex(
        "0bde6e74ec830a779b754eec40483c2c3dda34a9267b79b25ac58f5b2e114251"));
}

// draft-irtf-cfrg-xchacha A.3.1, checked at both steps the construction has: the subkey, then the
// ciphertext and tag. The inner nonce's byte order is pinned by the ciphertext -- the subkey is
// the same either way, so only this half of the test sees that mistake.
TEST_CASE("CXChaCha20Poly1305: AEAD, draft A.3.1") {
    const std::vector<uint8_t> key = fromHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<uint8_t> nonce = fromHex(
        "404142434445464748494a4b4c4d4e4f5051525354555657");
    const std::vector<uint8_t> aad = fromHex("50515253c0c1c2c3c4c5c6c7");

    const std::vector<uint8_t> plaintext = ascii(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it.");

    // The draft prints the plaintext as hex; confirm the ASCII above is those bytes rather than
    // trusting a transcription of a sentence.
    CHECK(plaintext == fromHex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e"));

    const std::vector<uint8_t> expectedCipher = fromHex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e");
    const std::vector<uint8_t> expectedTag = fromHex("c0875924c1c7987947deafd8780acf49");

    CXChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    // Derived from the above by an independent implementation; it isolates a wrong HChaCha20 from
    // a wrong inner nonce when the end-to-end check below fails.
    std::vector<uint8_t> subkey(CXChaCha20Poly1305::SUBKEY_BYTES);
    REQUIRE(aead.deriveSubkey(readOf(nonce), writeOf(subkey)));
    CHECK(subkey == fromHex(
        "4a8ac0c0296222bafe959faabe06a45b89a3cee444fef6e3d77659a53f49ee32"));

    std::vector<uint8_t> cipher(plaintext.size());
    std::vector<uint8_t> tag(CXChaCha20Poly1305::TAG_BYTES);

    REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                      writeOf(cipher), writeOf(tag)));

    CHECK(cipher == expectedCipher);
    CHECK(tag == expectedTag);

    // And the other direction, from the draft's own bytes rather than the ones just produced.
    std::vector<uint8_t> recovered(expectedCipher.size());
    REQUIRE(aead.open(readOf(nonce), readOf(aad), readOf(expectedCipher),
                      readOf(expectedTag), writeOf(recovered)));
    CHECK(recovered == plaintext);
}

// Derived vectors for the shapes A.3.1 does not reach: an empty plaintext, an AAD of length 0, and
// an AAD whose length is neither zero nor a multiple of 16 -- the case where pad16 of the AAD
// actually has to insert something.
TEST_CASE("CXChaCha20Poly1305: derived AEAD vectors, edge shapes") {
    const std::vector<uint8_t> key = fromHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<uint8_t> nonce = fromHex(
        "404142434445464748494a4b4c4d4e4f5051525354555657");

    CXChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    SUBCASE("empty plaintext, empty aad") {
        std::vector<uint8_t> tag(CXChaCha20Poly1305::TAG_BYTES);
        REQUIRE(aead.seal(readOf(nonce), SReadOnlyByteSpan(nullptr, 0),
                          SReadOnlyByteSpan(nullptr, 0), SByteSpan(nullptr, 0), writeOf(tag)));
        CHECK(tag == fromHex("1dac8f73146d1e9da796cb7f7221a5df"));

        REQUIRE(aead.open(readOf(nonce), SReadOnlyByteSpan(nullptr, 0),
                          SReadOnlyByteSpan(nullptr, 0), readOf(tag), SByteSpan(nullptr, 0)));
    }

    SUBCASE("aad of 17 bytes, plaintext of 70") {
        // 17 and 70: both leave a partial block, so both halves of the MAC's padding are exercised.
        std::vector<uint8_t> aad;
        for (size_t i = 0; i < 17; ++i) {
            aad.push_back(uint8_t(i));
        }
        std::vector<uint8_t> plaintext;
        for (size_t i = 0; i < 70; ++i) {
            plaintext.push_back(uint8_t((i * 7 + 1) & 0xff));
        }

        std::vector<uint8_t> cipher(plaintext.size());
        std::vector<uint8_t> tag(CXChaCha20Poly1305::TAG_BYTES);
        REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                          writeOf(cipher), writeOf(tag)));

        CHECK(cipher == fromHex(
            "f0047ce246d4df68c252309da3f2fe3f433f0de888d0074e630a42b28799de12"
            "e1d4ff8bd669946f28f3c6675baf1d109049f572c14fdff2277400c9d8ca2787"
            "80282d52bf3f"));
        CHECK(tag == fromHex("4cca79526e864858b3bd83389e05d3a9"));
    }

    SUBCASE("aad of 3 bytes, plaintext of exactly one block") {
        std::vector<uint8_t> aad = fromHex("000102");
        std::vector<uint8_t> plaintext;
        for (size_t i = 0; i < 16; ++i) {
            plaintext.push_back(uint8_t((i * 7 + 1) & 0xff));
        }

        std::vector<uint8_t> cipher(plaintext.size());
        std::vector<uint8_t> tag(CXChaCha20Poly1305::TAG_BYTES);
        REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                          writeOf(cipher), writeOf(tag)));

        CHECK(cipher == fromHex("f0047ce246d4df68c252309da3f2fe3f"));
        CHECK(tag == fromHex("f92f6cf34749642a93b14834ee0fa5b7"));
    }
}

// The aliasing contract: a receiver decrypts where the record already sits, so both directions
// have to tolerate out == in exactly, and a rejected open() must leave that buffer as it found it
// -- there is nowhere else the ciphertext survives.
TEST_CASE("CXChaCha20Poly1305: in-place sealing and opening") {
    const std::vector<uint8_t> key = fromHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<uint8_t> nonce = fromHex(
        "404142434445464748494a4b4c4d4e4f5051525354555657");
    const std::vector<uint8_t> aad = fromHex("50515253c0c1c2c3c4c5c6c7");
    const std::vector<uint8_t> plaintext = ascii(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it.");

    CXChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    std::vector<uint8_t> buffer = plaintext;
    std::vector<uint8_t> tag(CXChaCha20Poly1305::TAG_BYTES);

    REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(buffer), writeOf(buffer), writeOf(tag)));
    CHECK(buffer != plaintext);
    CHECK(buffer == fromHex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e"));

    const std::vector<uint8_t> sealed = buffer;

    REQUIRE(aead.open(readOf(nonce), readOf(aad), readOf(buffer), readOf(tag), writeOf(buffer)));
    CHECK(buffer == plaintext);

    SUBCASE("a rejected in-place open leaves the ciphertext intact") {
        buffer = sealed;

        std::vector<uint8_t> forged = tag;
        forged[0] ^= 0x01;

        CHECK_FALSE(aead.open(readOf(nonce), readOf(aad), readOf(buffer),
                              readOf(forged), writeOf(buffer)));
        CHECK(buffer == sealed);
    }
}

// Every input the tag covers, one bit at a time: a changed tag, a changed AAD, a changed
// ciphertext byte and a changed nonce must each be rejected, and rejected without writing.
TEST_CASE("CXChaCha20Poly1305: forgeries are rejected") {
    const std::vector<uint8_t> key = fromHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<uint8_t> nonce = fromHex(
        "404142434445464748494a4b4c4d4e4f5051525354555657");
    const std::vector<uint8_t> aad = fromHex("50515253c0c1c2c3c4c5c6c7");
    const std::vector<uint8_t> plaintext = ascii("sixteen bytes...plus a little more");

    CXChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    std::vector<uint8_t> cipher(plaintext.size());
    std::vector<uint8_t> tag(CXChaCha20Poly1305::TAG_BYTES);
    REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                      writeOf(cipher), writeOf(tag)));

    std::vector<uint8_t> out(plaintext.size(), 0xcc);
    const std::vector<uint8_t> untouched = out;

    SUBCASE("a tampered tag") {
        std::vector<uint8_t> bad = tag;
        bad[15] ^= 0x80;
        CHECK_FALSE(aead.open(readOf(nonce), readOf(aad), readOf(cipher),
                              readOf(bad), writeOf(out)));
        CHECK(out == untouched);
    }

    SUBCASE("a tampered aad byte") {
        std::vector<uint8_t> bad = aad;
        bad[4] ^= 0x01;
        CHECK_FALSE(aead.open(readOf(nonce), readOf(bad), readOf(cipher),
                              readOf(tag), writeOf(out)));
        CHECK(out == untouched);
    }

    SUBCASE("a truncated aad") {
        CHECK_FALSE(aead.open(readOf(nonce), SReadOnlyByteSpan(aad.data(), aad.size() - 1),
                              readOf(cipher), readOf(tag), writeOf(out)));
        CHECK(out == untouched);
    }

    SUBCASE("a tampered ciphertext byte") {
        std::vector<uint8_t> bad = cipher;
        bad[0] ^= 0x01;
        CHECK_FALSE(aead.open(readOf(nonce), readOf(aad), readOf(bad),
                              readOf(tag), writeOf(out)));
        CHECK(out == untouched);
    }

    SUBCASE("a nonce byte from the half HChaCha20 consumes") {
        std::vector<uint8_t> bad = nonce;
        bad[0] ^= 0x01;
        CHECK_FALSE(aead.open(readOf(bad), readOf(aad), readOf(cipher),
                              readOf(tag), writeOf(out)));
        CHECK(out == untouched);
    }

    SUBCASE("a nonce byte from the half the inner AEAD consumes") {
        std::vector<uint8_t> bad = nonce;
        bad[23] ^= 0x01;
        CHECK_FALSE(aead.open(readOf(bad), readOf(aad), readOf(cipher),
                              readOf(tag), writeOf(out)));
        CHECK(out == untouched);
    }
}

// The nonce is the whole point of this variant, so its length is worth a test of its own: a
// 12-byte nonce must be refused rather than silently read past or padded.
TEST_CASE("CXChaCha20Poly1305: argument validation") {
    const std::vector<uint8_t> key = fromHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<uint8_t> nonce = fromHex(
        "404142434445464748494a4b4c4d4e4f5051525354555657");

    std::vector<uint8_t> tag(CXChaCha20Poly1305::TAG_BYTES);
    std::vector<uint8_t> buffer(8, 0x11);
    std::vector<uint8_t> out(8);

    CXChaCha20Poly1305 unkeyed;
    CHECK_FALSE(unkeyed.keyed());
    CHECK_FALSE(unkeyed.seal(readOf(nonce), SReadOnlyByteSpan(nullptr, 0), readOf(buffer),
                             writeOf(out), writeOf(tag)));

    CHECK_FALSE(unkeyed.reset(SReadOnlyByteSpan(key.data(), 16)));
    REQUIRE(unkeyed.reset(readOf(key)));
    CHECK(unkeyed.keyed());

    // A 12-byte nonce -- the inner AEAD's length, and the mistake a caller porting from
    // CChaCha20Poly1305 would make.
    CHECK_FALSE(unkeyed.seal(SReadOnlyByteSpan(nonce.data(), 12), SReadOnlyByteSpan(nullptr, 0),
                             readOf(buffer), writeOf(out), writeOf(tag)));
    CHECK_FALSE(unkeyed.seal(SReadOnlyByteSpan(nonce.data(), 32), SReadOnlyByteSpan(nullptr, 0),
                             readOf(buffer), writeOf(out), writeOf(tag)));

    // Mismatched output length, and a short tag.
    std::vector<uint8_t> shortOut(7);
    CHECK_FALSE(unkeyed.seal(readOf(nonce), SReadOnlyByteSpan(nullptr, 0), readOf(buffer),
                             writeOf(shortOut), writeOf(tag)));

    std::vector<uint8_t> shortTag(15);
    CHECK_FALSE(unkeyed.seal(readOf(nonce), SReadOnlyByteSpan(nullptr, 0), readOf(buffer),
                             writeOf(out), writeOf(shortTag)));

    std::vector<uint8_t> subkey(CXChaCha20Poly1305::SUBKEY_BYTES);
    CHECK_FALSE(unkeyed.deriveSubkey(SReadOnlyByteSpan(nonce.data(), 16), writeOf(subkey)));
    CHECK_FALSE(unkeyed.deriveSubkey(readOf(nonce), SByteSpan(subkey.data(), 31)));
    CHECK(unkeyed.deriveSubkey(readOf(nonce), writeOf(subkey)));
}

// XChaCha20-Poly1305 is not ChaCha20-Poly1305 with a longer nonce bolted on: under the same key,
// the two produce different ciphertexts for the same message. Worth stating, because a wrapper
// that forgot to derive a subkey at all -- passing nonce[12:24] straight through -- would pass
// every round-trip test above.
TEST_CASE("CXChaCha20Poly1305: differs from CChaCha20Poly1305 under the same key") {
    const std::vector<uint8_t> key = fromHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<uint8_t> nonce24 = fromHex(
        "404142434445464748494a4b4c4d4e4f5051525354555657");
    const std::vector<uint8_t> plaintext = ascii("the same message, the same key");

    CXChaCha20Poly1305 extended;
    CChaCha20Poly1305 plain;
    REQUIRE(extended.reset(readOf(key)));
    REQUIRE(plain.reset(readOf(key)));

    std::vector<uint8_t> a(plaintext.size()), b(plaintext.size());
    std::vector<uint8_t> tagA(16), tagB(16);

    REQUIRE(extended.seal(readOf(nonce24), SReadOnlyByteSpan(nullptr, 0), readOf(plaintext),
                          writeOf(a), writeOf(tagA)));
    REQUIRE(plain.seal(SReadOnlyByteSpan(nonce24.data() + 12, 12), SReadOnlyByteSpan(nullptr, 0),
                       readOf(plaintext), writeOf(b), writeOf(tagB)));

    CHECK(a != b);
}

// A reused context is the intended usage -- one per link direction, only the nonce changing -- so
// many records in a row through one context must each come out right, with no state carried over.
TEST_CASE("CXChaCha20Poly1305: a reused context carries no state between records") {
    const std::vector<uint8_t> key = fromHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");

    CXChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    std::vector<uint8_t> nonce = fromHex(
        "404142434445464748494a4b4c4d4e4f5051525354555657");

    for (uint8_t record = 0; record < 24; ++record) {
        // Vary a byte in each half of the nonce, so both the subkey and the inner nonce change.
        nonce[0] = record;
        nonce[23] = uint8_t(0x57 ^ record);

        std::vector<uint8_t> plaintext(size_t(record) * 5 + 1, uint8_t(record * 3));
        std::vector<uint8_t> aad(size_t(record) % 19, uint8_t(record + 1));

        std::vector<uint8_t> buffer = plaintext;
        std::vector<uint8_t> tag(CXChaCha20Poly1305::TAG_BYTES);

        REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(buffer),
                          writeOf(buffer), writeOf(tag)));
        REQUIRE(aead.open(readOf(nonce), readOf(aad), readOf(buffer),
                          readOf(tag), writeOf(buffer)));
        CHECK(buffer == plaintext);
    }
}
