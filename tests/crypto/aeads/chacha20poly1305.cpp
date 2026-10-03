// Poly1305 and ChaCha20-Poly1305, against RFC 8439's published vectors: 2.5.2 (Poly1305),
// 2.6.2 (the one-time key derivation) and 2.8.2 (the AEAD).
//
// A round-trip proves almost nothing for this construction. Each of the three details most
// likely to be wrong -- encrypting from block counter 0 instead of 1, omitting Poly1305's key
// clamping, mis-ordering the MAC's four fields -- yields something that seals and opens
// perfectly against itself and interoperates with nothing. Only the RFC's bytes catch them,
// which is why the vectors below are checked at every intermediate step the RFC publishes
// rather than only end to end.

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
                continue;   // skip whitespace, so vectors can be laid out as the RFC prints them
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
}

// RFC 8439 2.5.2.
TEST_CASE("CPoly1305: RFC 8439 2.5.2") {
    const std::vector<uint8_t> key = fromHex(
        "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8"
        "01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
    const std::vector<uint8_t> message = ascii("Cryptographic Forum Research Group");
    const std::vector<uint8_t> expected = fromHex(
        "a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9");

    REQUIRE(key.size() == 32);
    REQUIRE(message.size() == 34);
    REQUIRE(expected.size() == 16);

    std::vector<uint8_t> tag(16);
    REQUIRE(CPoly1305::compute(readOf(key), readOf(message),
                               SByteSpan(tag.data(), tag.size())));
    CHECK(tag == expected);

    // The streaming path must agree regardless of how the message is divided -- 34 bytes is two
    // full blocks plus two, so a chunking bug shows up in the final partial block.
    for (size_t chunk : { size_t(1), size_t(3), size_t(16), size_t(17), size_t(33) }) {
        CPoly1305 mac;
        REQUIRE(mac.reset(readOf(key)));

        size_t offset = 0;
        while (offset < message.size()) {
            const size_t take = (message.size() - offset < chunk)
                ? (message.size() - offset) : chunk;
            REQUIRE(mac.push(SReadOnlyByteSpan(message.data() + offset, take)) == take);
            offset += take;
        }

        std::vector<uint8_t> streamed(16);
        REQUIRE(mac.finish(SByteSpan(streamed.data(), streamed.size())));
        REQUIRE(streamed == expected);
    }
}

TEST_CASE("CPoly1305: a one-time MAC refuses reuse, and sizes are checked") {
    const std::vector<uint8_t> key(32, 0x42);
    const std::vector<uint8_t> message = ascii("x");

    CPoly1305 mac;
    REQUIRE(mac.reset(readOf(key)));
    REQUIRE(mac.push(readOf(message)) == 1);

    std::vector<uint8_t> tag(16);
    REQUIRE(mac.finish(SByteSpan(tag.data(), tag.size())));

    // finish() consumes the state: this is a one-time MAC, and leaving it usable would invite
    // exactly the key reuse that breaks it.
    CHECK_FALSE(mac.finish(SByteSpan(tag.data(), tag.size())));
    CHECK(mac.push(readOf(message)) == 0);

    // Re-keying is how a second message is authenticated -- with a different key.
    const std::vector<uint8_t> otherKey(32, 0x43);
    CHECK(mac.reset(readOf(otherKey)));

    // Wrong sizes are refused.
    const std::vector<uint8_t> shortKey(31, 0x42);
    CPoly1305 other;
    CHECK_FALSE(other.reset(readOf(shortKey)));

    CPoly1305 third;
    REQUIRE(third.reset(readOf(key)));
    std::vector<uint8_t> shortTag(15);
    CHECK_FALSE(third.finish(SByteSpan(shortTag.data(), shortTag.size())));

    // An empty message is legal and has a well-defined tag.
    std::vector<uint8_t> emptyTag(16);
    CHECK(CPoly1305::compute(readOf(key), SReadOnlyByteSpan(nullptr, 0),
                             SByteSpan(emptyTag.data(), emptyTag.size())));
}

// RFC 8439 2.6.2: the one-time key derivation, which is the step that spends block counter 0.
TEST_CASE("CChaCha20Poly1305: RFC 8439 2.6.2 one-time key derivation") {
    const std::vector<uint8_t> key = fromHex(
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f");
    const std::vector<uint8_t> nonce = fromHex("00 00 00 00 00 01 02 03 04 05 06 07");
    const std::vector<uint8_t> expected = fromHex(
        "8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71"
        "a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46");

    REQUIRE(key.size() == 32);
    REQUIRE(nonce.size() == 12);
    REQUIRE(expected.size() == 32);

    CChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));
    CHECK(aead.keyed());

    std::vector<uint8_t> oneTimeKey(32);
    REQUIRE(aead.deriveOneTimeKey(readOf(nonce),
                                  SByteSpan(oneTimeKey.data(), oneTimeKey.size())));
    CHECK(oneTimeKey == expected);

    // An unkeyed context derives nothing.
    CChaCha20Poly1305 unkeyed;
    CHECK_FALSE(unkeyed.keyed());
    CHECK_FALSE(unkeyed.deriveOneTimeKey(readOf(nonce),
                                         SByteSpan(oneTimeKey.data(), oneTimeKey.size())));
}

// RFC 8439 2.8.2: the full AEAD. This is the vector that pins the counter-1 start and the MAC's
// field order at once.
TEST_CASE("CChaCha20Poly1305: RFC 8439 2.8.2") {
    const std::vector<uint8_t> plaintext = ascii(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
        "the future, sunscreen would be it.");
    const std::vector<uint8_t> aad = fromHex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
    const std::vector<uint8_t> key = fromHex(
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f");
    const std::vector<uint8_t> nonce = fromHex("07 00 00 00 40 41 42 43 44 45 46 47");

    const std::vector<uint8_t> expectedCiphertext = fromHex(
        "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
        "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
        "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
        "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
        "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
        "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
        "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
        "61 16");
    const std::vector<uint8_t> expectedTag = fromHex(
        "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91");

    REQUIRE(plaintext.size() == 114);
    REQUIRE(expectedCiphertext.size() == 114);
    REQUIRE(expectedTag.size() == 16);

    CChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(16);
    REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                      SByteSpan(ciphertext.data(), ciphertext.size()),
                      SByteSpan(tag.data(), tag.size())));

    CHECK(ciphertext == expectedCiphertext);
    CHECK(tag == expectedTag);

    // And back the other way, from the RFC's own ciphertext and tag.
    std::vector<uint8_t> recovered(expectedCiphertext.size());
    REQUIRE(aead.open(readOf(nonce), readOf(aad), readOf(expectedCiphertext),
                      readOf(expectedTag),
                      SByteSpan(recovered.data(), recovered.size())));
    CHECK(recovered == plaintext);
}

// What cskcwk needs: decrypting a record where it already sits, with nothing copied aside.
TEST_CASE("CChaCha20Poly1305: in-place seal and open") {
    const std::vector<uint8_t> key(32, 0x5A);
    const std::vector<uint8_t> nonce(12, 0x01);
    const std::vector<uint8_t> aad = ascii("record header");
    const std::vector<uint8_t> plaintext = ascii(
        "a record long enough to span several ChaCha20 blocks, so the keystream advances "
        "and an in-place XOR has somewhere to go wrong");

    CChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    // Seal with out == in.
    std::vector<uint8_t> buffer = plaintext;
    std::vector<uint8_t> tag(16);
    REQUIRE(aead.seal(readOf(nonce), readOf(aad),
                      SReadOnlyByteSpan(buffer.data(), buffer.size()),
                      SByteSpan(buffer.data(), buffer.size()),
                      SByteSpan(tag.data(), tag.size())));
    CHECK(buffer != plaintext);

    // It must match what a non-aliased seal produces.
    std::vector<uint8_t> separate(plaintext.size());
    std::vector<uint8_t> separateTag(16);
    REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                      SByteSpan(separate.data(), separate.size()),
                      SByteSpan(separateTag.data(), separateTag.size())));
    CHECK(buffer == separate);
    CHECK(tag == separateTag);

    // Open with out == in, recovering the plaintext in the same buffer.
    REQUIRE(aead.open(readOf(nonce), readOf(aad),
                      SReadOnlyByteSpan(buffer.data(), buffer.size()),
                      readOf(tag),
                      SByteSpan(buffer.data(), buffer.size())));
    CHECK(buffer == plaintext);
}

// The property that makes in-place open() safe: a forged tag must leave the buffer alone. If
// open() decrypted first and verified afterwards, an in-place caller would have its only copy of
// the ciphertext overwritten with unauthenticated plaintext before the forgery was noticed.
TEST_CASE("CChaCha20Poly1305: a failed open leaves the buffer untouched") {
    const std::vector<uint8_t> key(32, 0x77);
    const std::vector<uint8_t> nonce(12, 0x02);
    const std::vector<uint8_t> aad = ascii("aad");
    const std::vector<uint8_t> plaintext = ascii("authentic payload");

    CChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(16);
    REQUIRE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                      SByteSpan(ciphertext.data(), ciphertext.size()),
                      SByteSpan(tag.data(), tag.size())));

    SUBCASE("every single-bit change in the tag is rejected") {
        for (size_t i = 0; i < tag.size(); ++i) {
            for (int bit = 0; bit < 8; ++bit) {
                std::vector<uint8_t> forged = tag;
                forged[i] = uint8_t(forged[i] ^ (1u << bit));

                std::vector<uint8_t> buffer = ciphertext;
                REQUIRE_FALSE(aead.open(readOf(nonce), readOf(aad),
                                        SReadOnlyByteSpan(buffer.data(), buffer.size()),
                                        readOf(forged),
                                        SByteSpan(buffer.data(), buffer.size())));
                // In place, and rejected: the ciphertext must still be there.
                REQUIRE(buffer == ciphertext);
            }
        }
    }

    SUBCASE("a modified ciphertext is rejected") {
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            std::vector<uint8_t> buffer = ciphertext;
            buffer[i] ^= 0x01;
            const std::vector<uint8_t> modified = buffer;

            REQUIRE_FALSE(aead.open(readOf(nonce), readOf(aad),
                                    SReadOnlyByteSpan(buffer.data(), buffer.size()),
                                    readOf(tag),
                                    SByteSpan(buffer.data(), buffer.size())));
            REQUIRE(buffer == modified);
        }
    }

    SUBCASE("modified AAD is rejected, since it is authenticated too") {
        std::vector<uint8_t> otherAad = ascii("Aad");
        std::vector<uint8_t> out(ciphertext.size());
        CHECK_FALSE(aead.open(readOf(nonce), readOf(otherAad), readOf(ciphertext),
                              readOf(tag), SByteSpan(out.data(), out.size())));

        // Dropping the AAD entirely is also a change.
        CHECK_FALSE(aead.open(readOf(nonce), SReadOnlyByteSpan(nullptr, 0), readOf(ciphertext),
                              readOf(tag), SByteSpan(out.data(), out.size())));
    }

    SUBCASE("a different nonce is rejected") {
        std::vector<uint8_t> otherNonce = nonce;
        otherNonce[11] ^= 0x01;

        std::vector<uint8_t> out(ciphertext.size());
        CHECK_FALSE(aead.open(readOf(otherNonce), readOf(aad), readOf(ciphertext),
                              readOf(tag), SByteSpan(out.data(), out.size())));
    }

    SUBCASE("a different key is rejected") {
        CChaCha20Poly1305 other;
        const std::vector<uint8_t> otherKey(32, 0x78);
        REQUIRE(other.reset(readOf(otherKey)));

        std::vector<uint8_t> out(ciphertext.size());
        CHECK_FALSE(other.open(readOf(nonce), readOf(aad), readOf(ciphertext),
                               readOf(tag), SByteSpan(out.data(), out.size())));
    }
}

TEST_CASE("CChaCha20Poly1305: empty plaintext, empty AAD, and the size checks") {
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);

    CChaCha20Poly1305 aead;
    REQUIRE(aead.reset(readOf(key)));

    // An empty plaintext still produces a tag -- authenticating AAD alone is a legitimate use,
    // and the length footer is what makes it unambiguous.
    std::vector<uint8_t> tag(16);
    REQUIRE(aead.seal(readOf(nonce), SReadOnlyByteSpan(nullptr, 0), SReadOnlyByteSpan(nullptr, 0),
                      SByteSpan(nullptr, 0), SByteSpan(tag.data(), tag.size())));

    CHECK(aead.open(readOf(nonce), SReadOnlyByteSpan(nullptr, 0), SReadOnlyByteSpan(nullptr, 0),
                    readOf(tag), SByteSpan(nullptr, 0)));

    // AAD alone, with an empty payload.
    const std::vector<uint8_t> aad = ascii("header only");
    std::vector<uint8_t> aadTag(16);
    REQUIRE(aead.seal(readOf(nonce), readOf(aad), SReadOnlyByteSpan(nullptr, 0),
                      SByteSpan(nullptr, 0), SByteSpan(aadTag.data(), aadTag.size())));
    CHECK(aadTag != tag);
    CHECK(aead.open(readOf(nonce), readOf(aad), SReadOnlyByteSpan(nullptr, 0),
                    readOf(aadTag), SByteSpan(nullptr, 0)));

    // Sizes.
    const std::vector<uint8_t> plaintext = ascii("payload");
    std::vector<uint8_t> out(plaintext.size());
    std::vector<uint8_t> shortOut(plaintext.size() - 1);
    std::vector<uint8_t> shortTag(15);

    CHECK_FALSE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                          SByteSpan(shortOut.data(), shortOut.size()),
                          SByteSpan(tag.data(), tag.size())));
    CHECK_FALSE(aead.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                          SByteSpan(out.data(), out.size()),
                          SByteSpan(shortTag.data(), shortTag.size())));

    const std::vector<uint8_t> shortNonce(11, 0x22);
    CHECK_FALSE(aead.seal(readOf(shortNonce), readOf(aad), readOf(plaintext),
                          SByteSpan(out.data(), out.size()),
                          SByteSpan(tag.data(), tag.size())));

    const std::vector<uint8_t> shortKey(31, 0x11);
    CChaCha20Poly1305 bad;
    CHECK_FALSE(bad.reset(readOf(shortKey)));
    CHECK_FALSE(bad.keyed());
    CHECK_FALSE(bad.seal(readOf(nonce), readOf(aad), readOf(plaintext),
                         SByteSpan(out.data(), out.size()),
                         SByteSpan(tag.data(), tag.size())));
}

// How cskcwk will actually drive it: one context per direction, nonce = prefix || counter, keys
// from HKDF over an X25519 shared secret. This is an integration check that the pieces compose,
// not a vector test.
TEST_CASE("CChaCha20Poly1305: a counter-nonce record stream over HKDF-derived keys") {
    // Stand in for the X25519 shared secret and the transcript hash.
    const std::vector<uint8_t> sharedSecret(32, 0x9E);
    const std::vector<uint8_t> transcriptHash(32, 0x1D);

    auto deriveDirection = [&](const char* label) {
        std::vector<uint8_t> material(44);   // 32-byte key + 12-byte nonce prefix
        const std::vector<uint8_t> info = ascii(label);
        REQUIRE(CHkdf::derive(EHASH_SHA256, readOf(transcriptHash), readOf(sharedSecret),
                              readOf(info),
                              SByteSpan(material.data(), material.size())) == ERET_OK);
        return material;
    };

    const std::vector<uint8_t> c2s = deriveDirection("cskcwk c2s");
    const std::vector<uint8_t> s2c = deriveDirection("cskcwk s2c");
    REQUIRE(c2s != s2c);

    CChaCha20Poly1305 sender;
    CChaCha20Poly1305 receiver;
    REQUIRE(sender.reset(SReadOnlyByteSpan(c2s.data(), 32)));
    REQUIRE(receiver.reset(SReadOnlyByteSpan(c2s.data(), 32)));

    // nonce = 4-byte prefix || 64-bit big-endian counter, the shape RFC 8439 4 suggests.
    auto nonceFor = [&](uint64_t counter) {
        std::vector<uint8_t> nonce(12);
        std::memcpy(nonce.data(), c2s.data() + 32, 4);
        for (size_t i = 0; i < 8; ++i) {
            nonce[4 + i] = uint8_t(counter >> (8 * (7 - i)));
        }
        return nonce;
    };

    std::vector<std::vector<uint8_t>> sealed;
    std::vector<std::vector<uint8_t>> tags;

    for (uint64_t counter = 0; counter < 8; ++counter) {
        std::vector<uint8_t> record = ascii("record payload #");
        record.push_back(uint8_t('0' + counter));

        const std::vector<uint8_t> nonce = nonceFor(counter);
        std::vector<uint8_t> tag(16);

        // In place, as the real sender would.
        std::vector<uint8_t> buffer = record;
        REQUIRE(sender.seal(readOf(nonce), SReadOnlyByteSpan(nullptr, 0),
                            SReadOnlyByteSpan(buffer.data(), buffer.size()),
                            SByteSpan(buffer.data(), buffer.size()),
                            SByteSpan(tag.data(), tag.size())));

        sealed.push_back(buffer);
        tags.push_back(tag);

        std::vector<uint8_t> opened = buffer;
        REQUIRE(receiver.open(readOf(nonce), SReadOnlyByteSpan(nullptr, 0),
                              SReadOnlyByteSpan(opened.data(), opened.size()),
                              readOf(tag),
                              SByteSpan(opened.data(), opened.size())));
        REQUIRE(opened == record);
    }

    // Every record's ciphertext differs even where payloads are nearly identical, because the
    // nonce advances -- which is the whole reason the counter exists.
    for (size_t i = 0; i < sealed.size(); ++i) {
        for (size_t j = i + 1; j < sealed.size(); ++j) {
            REQUIRE(sealed[i] != sealed[j]);
            REQUIRE(tags[i] != tags[j]);
        }
    }

    // A record replayed under the wrong counter is rejected, which is what a nonce bound into
    // the authentication buys.
    std::vector<uint8_t> misplaced = sealed[3];
    std::vector<uint8_t> out(misplaced.size());
    CHECK_FALSE(receiver.open(readOf(nonceFor(4)), SReadOnlyByteSpan(nullptr, 0),
                              readOf(misplaced), readOf(tags[3]),
                              SByteSpan(out.data(), out.size())));

    // And the opposite direction's key cannot open this direction's records -- the property the
    // two HKDF labels exist to provide.
    CChaCha20Poly1305 wrongDirection;
    REQUIRE(wrongDirection.reset(SReadOnlyByteSpan(s2c.data(), 32)));
    CHECK_FALSE(wrongDirection.open(readOf(nonceFor(0)), SReadOnlyByteSpan(nullptr, 0),
                                    readOf(sealed[0]), readOf(tags[0]),
                                    SByteSpan(out.data(), sealed[0].size())));
}
