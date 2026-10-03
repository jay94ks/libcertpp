// AES-GCM, against the test cases published with the original GCM specification (McGrew-Viega,
// "The Galois/Counter Mode of Operation (GCM)", Appendix B) -- the twelve of the eighteen that
// use a 96-bit IV, which is the only IV length CAesGcm accepts. They cover all three key sizes,
// an empty plaintext, an empty AAD, and a plaintext and AAD that are both non-multiples of the
// block size.
//
// A round-trip proves almost nothing for this construction. Each of the details most likely to be
// wrong -- starting the payload counter at J0 instead of J0+1, putting the length block's two
// counts in bytes instead of bits or little-endian instead of big-endian, multiplying in GF(2^128)
// without GCM's bit reflection -- yields something that seals and opens perfectly against itself
// and interoperates with nothing. Only the published bytes catch them, and the subkey H each case
// publishes is checked too, so a mismatch separates "the block cipher is wrong" from "the hash
// is wrong".

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
                continue;   // skip whitespace, so vectors can be laid out as the spec prints them
            }
            const int hi = nibble(*p);
            ++p;
            while (*p && nibble(*p) < 0) { ++p; }
            if (!*p) { break; }
            out.push_back(uint8_t((hi << 4) | nibble(*p)));
        }
        return out;
    }

    SReadOnlyByteSpan readOf(const std::vector<uint8_t>& v) {
        return v.empty() ? SReadOnlyByteSpan(nullptr, 0) : SReadOnlyByteSpan(v.data(), v.size());
    }

    SByteSpan writeOf(std::vector<uint8_t>& v) {
        return v.empty() ? SByteSpan(nullptr, 0) : SByteSpan(v.data(), v.size());
    }

    struct SCase {
        const char* name;
        const char* key;
        const char* iv;
        const char* plaintext;
        const char* aad;
        const char* subkey;
        const char* ciphertext;
        const char* tag;
    };

    // The 64- and 60-byte plaintexts the spec reuses across key sizes; the 60-byte one is the
    // 64-byte one with its last four bytes removed, and the only one paired with an AAD.
    const char* P64 =
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255";
    const char* P60 =
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39";
    const char* AAD20 = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    const char* IV96 = "cafebabefacedbaddecaf888";

    const SCase CASES[] = {
        // --- AES-128 (Appendix B test cases 1-4) ---
        {
            "1", "00000000000000000000000000000000", "000000000000000000000000",
            "", "",
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        },
        {
            "2", "00000000000000000000000000000000", "000000000000000000000000",
            "00000000000000000000000000000000", "",
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        },
        {
            "3", "feffe9928665731c6d6a8f9467308308", IV96,
            P64, "",
            "b83b533708bf535d0aa6e52980d53b78",
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        },
        {
            "4", "feffe9928665731c6d6a8f9467308308", IV96,
            P60, AAD20,
            "b83b533708bf535d0aa6e52980d53b78",
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        },

        // --- AES-192 (Appendix B test cases 7-10) ---
        {
            "7", "000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "", "",
            "aae06992acbf52a3e8f4a96ec9300bd7",
            "",
            "cd33b28ac773f74ba00ed1f312572435",
        },
        {
            "8", "000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000", "",
            "aae06992acbf52a3e8f4a96ec9300bd7",
            "98e7247c07f0fe411c267e4384b0f600",
            "2ff58d80033927ab8ef4d4587514f0fb",
        },
        {
            "9", "feffe9928665731c6d6a8f9467308308feffe9928665731c", IV96,
            P64, "",
            "466923ec9ae682214f2c082badb39249",
            "3980ca0b3c00e841eb06fac4872a2757"
            "859e1ceaa6efd984628593b40ca1e19c"
            "7d773d00c144c525ac619d18c84a3f47"
            "18e2448b2fe324d9ccda2710acade256",
            "9924a7c8587336bfb118024db8674a14",
        },
        {
            "10", "feffe9928665731c6d6a8f9467308308feffe9928665731c", IV96,
            P60, AAD20,
            "466923ec9ae682214f2c082badb39249",
            "3980ca0b3c00e841eb06fac4872a2757"
            "859e1ceaa6efd984628593b40ca1e19c"
            "7d773d00c144c525ac619d18c84a3f47"
            "18e2448b2fe324d9ccda2710",
            "2519498e80f1478f37ba55bd6d27618c",
        },

        // --- AES-256 (Appendix B test cases 13-16) ---
        {
            "13", "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "", "",
            "dc95c078a2408989ad48a21492842087",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        },
        {
            "14", "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000", "",
            "dc95c078a2408989ad48a21492842087",
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        },
        {
            "15", "feffe9928665731c6d6a8f9467308308"
                  "feffe9928665731c6d6a8f9467308308", IV96,
            P64, "",
            "acbef20579b4b8ebce889bac8732dad7",
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662898015ad",
            "b094dac5d93471bdec1a502270e3cc6c",
        },
        {
            "16", "feffe9928665731c6d6a8f9467308308"
                  "feffe9928665731c6d6a8f9467308308", IV96,
            P60, AAD20,
            "acbef20579b4b8ebce889bac8732dad7",
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        },
    };
}

TEST_CASE("CAesGcm: the GCM specification's 96-bit-IV test cases") {
    for (const SCase& c : CASES) {
        const std::vector<uint8_t> key = fromHex(c.key);
        const std::vector<uint8_t> iv = fromHex(c.iv);
        const std::vector<uint8_t> plaintext = fromHex(c.plaintext);
        const std::vector<uint8_t> aad = fromHex(c.aad);
        const std::vector<uint8_t> expectedH = fromHex(c.subkey);
        const std::vector<uint8_t> expectedC = fromHex(c.ciphertext);
        const std::vector<uint8_t> expectedT = fromHex(c.tag);

        CAPTURE(c.name);

        // Every transcription below is checked for length before it is used, since a dropped or
        // doubled hex digit would otherwise show up as a cryptographic failure rather than as the
        // typo it is.
        REQUIRE((key.size() == 16 || key.size() == 24 || key.size() == 32));
        REQUIRE(iv.size() == 12);
        REQUIRE(expectedH.size() == 16);
        REQUIRE(expectedT.size() == 16);
        REQUIRE(expectedC.size() == plaintext.size());

        CAesGcm gcm;
        REQUIRE(gcm.reset(readOf(key)));
        CHECK(gcm.keyed());
        CHECK(gcm.keyBytes() == key.size());

        // H = E_K(0^128): the cheapest way to tell a wrong key schedule from a wrong hash.
        std::vector<uint8_t> h(16);
        REQUIRE(gcm.deriveSubkey(writeOf(h)));
        CHECK(h == expectedH);

        std::vector<uint8_t> ciphertext(plaintext.size());
        std::vector<uint8_t> tag(16);
        REQUIRE(gcm.seal(readOf(iv), readOf(aad), readOf(plaintext),
                         writeOf(ciphertext), writeOf(tag)));
        CHECK(ciphertext == expectedC);
        CHECK(tag == expectedT);

        // And back: open() must accept the spec's own ciphertext and tag, not merely whatever
        // seal() happened to produce.
        std::vector<uint8_t> recovered(expectedC.size());
        REQUIRE(gcm.open(readOf(iv), readOf(aad), readOf(expectedC), readOf(expectedT),
                         writeOf(recovered)));
        CHECK(recovered == plaintext);
    }
}

// Two short cases produced by an independent Python implementation of SP 800-38D, written and
// checked against the twelve published vectors above before these were taken from it. They are
// regression anchors for the single-byte edges -- a plaintext and an AAD shorter than one block --
// not independent evidence; the published cases are that.
TEST_CASE("CAesGcm: single-byte plaintext and single-byte AAD") {
    const std::vector<uint8_t> key = fromHex("feffe9928665731c6d6a8f9467308308");
    const std::vector<uint8_t> iv = fromHex(IV96);

    CAesGcm gcm;
    REQUIRE(gcm.reset(readOf(key)));

    SUBCASE("one plaintext byte, no AAD") {
        const std::vector<uint8_t> plaintext = fromHex("01");
        const std::vector<uint8_t> expectedC = fromHex("9a");
        const std::vector<uint8_t> expectedT = fromHex("d8f7dfac78a4024eb7d4bfe4e009a30e");

        std::vector<uint8_t> ciphertext(1);
        std::vector<uint8_t> tag(16);
        REQUIRE(gcm.seal(readOf(iv), SReadOnlyByteSpan(nullptr, 0), readOf(plaintext),
                         writeOf(ciphertext), writeOf(tag)));
        CHECK(ciphertext == expectedC);
        CHECK(tag == expectedT);
    }

    SUBCASE("one AAD byte, no plaintext") {
        const std::vector<uint8_t> aad = fromHex("03");
        const std::vector<uint8_t> expectedT = fromHex("b2884ba1ef240be21f54e0b9f035aec1");

        std::vector<uint8_t> tag(16);
        REQUIRE(gcm.seal(readOf(iv), readOf(aad), SReadOnlyByteSpan(nullptr, 0),
                         SByteSpan(nullptr, 0), writeOf(tag)));
        CHECK(tag == expectedT);
    }
}

TEST_CASE("CAesGcm: open() rejects a tampered tag, ciphertext, AAD or IV") {
    const std::vector<uint8_t> key = fromHex("feffe9928665731c6d6a8f9467308308");
    const std::vector<uint8_t> iv = fromHex(IV96);
    const std::vector<uint8_t> plaintext = fromHex(P60);
    const std::vector<uint8_t> aad = fromHex(AAD20);

    CAesGcm gcm;
    REQUIRE(gcm.reset(readOf(key)));

    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(16);
    REQUIRE(gcm.seal(readOf(iv), readOf(aad), readOf(plaintext),
                     writeOf(ciphertext), writeOf(tag)));

    std::vector<uint8_t> out(ciphertext.size());
    REQUIRE(gcm.open(readOf(iv), readOf(aad), readOf(ciphertext), readOf(tag), writeOf(out)));

    SUBCASE("one tag bit") {
        std::vector<uint8_t> bad = tag;
        bad[7] ^= 0x01;
        CHECK_FALSE(gcm.open(readOf(iv), readOf(aad), readOf(ciphertext), readOf(bad),
                             writeOf(out)));
    }

    SUBCASE("one ciphertext bit") {
        std::vector<uint8_t> bad = ciphertext;
        bad[17] ^= 0x01;
        CHECK_FALSE(gcm.open(readOf(iv), readOf(aad), readOf(bad), readOf(tag), writeOf(out)));
    }

    // The point of an AEAD: the AAD is not in the ciphertext, so only the tag can defend it.
    SUBCASE("one AAD byte") {
        std::vector<uint8_t> bad = aad;
        bad[0] ^= 0x01;
        CHECK_FALSE(gcm.open(readOf(iv), readOf(bad), readOf(ciphertext), readOf(tag),
                             writeOf(out)));
    }

    SUBCASE("a dropped trailing AAD byte") {
        const std::vector<uint8_t> shorter(aad.begin(), aad.end() - 1);
        CHECK_FALSE(gcm.open(readOf(iv), readOf(shorter), readOf(ciphertext), readOf(tag),
                             writeOf(out)));
    }

    SUBCASE("one IV byte") {
        std::vector<uint8_t> bad = iv;
        bad[3] ^= 0x01;
        CHECK_FALSE(gcm.open(readOf(bad), readOf(aad), readOf(ciphertext), readOf(tag),
                             writeOf(out)));
    }
}

TEST_CASE("CAesGcm: a failed open() leaves the output untouched, even in place") {
    const std::vector<uint8_t> key(32, 0x5a);
    const std::vector<uint8_t> iv(12, 0x11);
    const std::vector<uint8_t> plaintext(48, 0x33);
    const std::vector<uint8_t> aad(5, 0x77);

    CAesGcm gcm;
    REQUIRE(gcm.reset(readOf(key)));

    std::vector<uint8_t> buffer(plaintext.size());
    std::vector<uint8_t> tag(16);
    REQUIRE(gcm.seal(readOf(iv), readOf(aad), readOf(plaintext), writeOf(buffer), writeOf(tag)));

    const std::vector<uint8_t> ciphertext = buffer;

    std::vector<uint8_t> forged = tag;
    forged[15] ^= 0x80;

    // In place, and with a tag that will not verify: the buffer must still hold the ciphertext
    // afterwards. Writing plaintext first and checking later would have destroyed the caller's
    // only copy of it on the way to returning false.
    CHECK_FALSE(gcm.open(readOf(iv), readOf(aad),
                         SReadOnlyByteSpan(buffer.data(), buffer.size()), readOf(forged),
                         writeOf(buffer)));
    CHECK(buffer == ciphertext);
}

TEST_CASE("CAesGcm: out may alias in, both ways, at every length around a block") {
    const std::vector<uint8_t> key(16, 0x2b);
    const std::vector<uint8_t> iv(12, 0x07);

    CAesGcm gcm;
    REQUIRE(gcm.reset(readOf(key)));

    for (size_t length : { size_t(0), size_t(1), size_t(15), size_t(16), size_t(17),
                           size_t(31), size_t(32), size_t(33), size_t(64), size_t(100) }) {
        for (size_t aadLength : { size_t(0), size_t(1), size_t(16), size_t(20), size_t(33) }) {
            CAPTURE(length);
            CAPTURE(aadLength);

            std::vector<uint8_t> plaintext(length);
            for (size_t i = 0; i < length; ++i) {
                plaintext[i] = uint8_t(i * 7 + 1);
            }
            std::vector<uint8_t> aad(aadLength);
            for (size_t i = 0; i < aadLength; ++i) {
                aad[i] = uint8_t(i * 11 + 3);
            }

            // Sealed out of place first, to have something to compare the in-place result with.
            std::vector<uint8_t> apart(length);
            std::vector<uint8_t> apartTag(16);
            REQUIRE(gcm.seal(readOf(iv), readOf(aad), readOf(plaintext),
                             writeOf(apart), writeOf(apartTag)));

            std::vector<uint8_t> buffer = plaintext;
            std::vector<uint8_t> tag(16);
            REQUIRE(gcm.seal(readOf(iv), readOf(aad),
                             SReadOnlyByteSpan(buffer.data(), buffer.size()),
                             writeOf(buffer), writeOf(tag)));
            CHECK(buffer == apart);
            CHECK(tag == apartTag);

            REQUIRE(gcm.open(readOf(iv), readOf(aad),
                             SReadOnlyByteSpan(buffer.data(), buffer.size()), readOf(tag),
                             writeOf(buffer)));
            CHECK(buffer == plaintext);
        }
    }
}

TEST_CASE("CAesGcm: a truncated tag is the full tag's prefix, and verifies as one") {
    const std::vector<uint8_t> key = fromHex("feffe9928665731c6d6a8f9467308308");
    const std::vector<uint8_t> iv = fromHex(IV96);
    const std::vector<uint8_t> plaintext = fromHex(P60);
    const std::vector<uint8_t> aad = fromHex(AAD20);
    const std::vector<uint8_t> full = fromHex("5bc94fbc3221a5db94fae95ae7121a47");

    CAesGcm gcm;
    REQUIRE(gcm.reset(readOf(key)));

    std::vector<uint8_t> ciphertext(plaintext.size());

    // SP 800-38D 5.2.1.2's five permitted lengths are 128/120/112/104/96 bits, i.e. every byte
    // length from MIN_TAG_BYTES to TAG_BYTES.
    for (size_t length = CAesGcm::MIN_TAG_BYTES; length <= CAesGcm::TAG_BYTES; ++length) {
        CAPTURE(length);

        std::vector<uint8_t> tag(length);
        REQUIRE(gcm.seal(readOf(iv), readOf(aad), readOf(plaintext),
                         writeOf(ciphertext), writeOf(tag)));

        CHECK(tag == std::vector<uint8_t>(full.begin(), full.begin() + length));

        std::vector<uint8_t> out(ciphertext.size());
        CHECK(gcm.open(readOf(iv), readOf(aad), readOf(ciphertext), readOf(tag), writeOf(out)));
        CHECK(out == plaintext);

        std::vector<uint8_t> bad = tag;
        bad[length - 1] ^= 0x01;
        CHECK_FALSE(gcm.open(readOf(iv), readOf(aad), readOf(ciphertext), readOf(bad),
                             writeOf(out)));
    }

    // Shorter than 96 bits is outside what SP 800-38D permits for general use, so it is refused
    // rather than silently accepted at reduced strength.
    std::vector<uint8_t> tooShort(CAesGcm::MIN_TAG_BYTES - 1);
    CHECK_FALSE(gcm.seal(readOf(iv), readOf(aad), readOf(plaintext),
                         writeOf(ciphertext), writeOf(tooShort)));

    std::vector<uint8_t> tooLong(CAesGcm::TAG_BYTES + 1);
    CHECK_FALSE(gcm.seal(readOf(iv), readOf(aad), readOf(plaintext),
                         writeOf(ciphertext), writeOf(tooLong)));
}

TEST_CASE("CAesGcm: sizes and state are checked") {
    const std::vector<uint8_t> plaintext(16, 0x01);

    CAesGcm unkeyed;
    CHECK_FALSE(unkeyed.keyed());
    CHECK(unkeyed.keyBytes() == 0);

    std::vector<uint8_t> out(16);
    std::vector<uint8_t> tag(16);
    const std::vector<uint8_t> iv(12, 0x00);

    // Unkeyed: nothing works, and in particular nothing silently uses an all-zero key.
    CHECK_FALSE(unkeyed.seal(readOf(iv), SReadOnlyByteSpan(nullptr, 0), readOf(plaintext),
                             writeOf(out), writeOf(tag)));
    CHECK_FALSE(unkeyed.deriveSubkey(writeOf(out)));

    for (size_t bad : { size_t(0), size_t(15), size_t(17), size_t(23), size_t(31), size_t(33) }) {
        const std::vector<uint8_t> key(bad, 0x11);
        CAesGcm gcm;
        CHECK_FALSE(gcm.reset(bad == 0 ? SReadOnlyByteSpan(nullptr, 0) : readOf(key)));
        CHECK_FALSE(gcm.keyed());
    }

    const std::vector<uint8_t> key(16, 0x11);
    CAesGcm gcm;
    REQUIRE(gcm.reset(readOf(key)));

    // A rejected re-key must leave the context unkeyed rather than still holding the old key,
    // which would make the next seal() use a key its caller believes it replaced.
    const std::vector<uint8_t> badKey(20, 0x22);
    CHECK_FALSE(gcm.reset(readOf(badKey)));
    CHECK_FALSE(gcm.keyed());
    REQUIRE(gcm.reset(readOf(key)));

    // An IV of any other length is refused: only 96 bits is supported, and quietly padding or
    // hashing one of a different length would produce a record no peer agrees with.
    for (size_t bad : { size_t(0), size_t(8), size_t(11), size_t(13), size_t(16) }) {
        const std::vector<uint8_t> wrongIv(bad, 0x00);
        CHECK_FALSE(gcm.seal(bad == 0 ? SReadOnlyByteSpan(nullptr, 0) : readOf(wrongIv),
                             SReadOnlyByteSpan(nullptr, 0), readOf(plaintext),
                             writeOf(out), writeOf(tag)));
    }

    // out must be exactly as long as in.
    std::vector<uint8_t> shortOut(15);
    CHECK_FALSE(gcm.seal(readOf(iv), SReadOnlyByteSpan(nullptr, 0), readOf(plaintext),
                         writeOf(shortOut), writeOf(tag)));
}

TEST_CASE("CAesGcm: a 128-bit, a 192-bit and a 256-bit key under the same IV disagree") {
    // Not a spec requirement, just the cheapest check that the key size actually reaches the
    // cipher -- an AES-192 key truncated to 128 bits somewhere would otherwise be invisible here.
    const std::vector<uint8_t> iv(12, 0x09);
    const std::vector<uint8_t> plaintext(32, 0x41);

    std::vector<std::vector<uint8_t>> tags;
    for (size_t keyBytes : { size_t(16), size_t(24), size_t(32) }) {
        const std::vector<uint8_t> key(keyBytes, 0x66);

        CAesGcm gcm;
        REQUIRE(gcm.reset(readOf(key)));
        CHECK(gcm.keyBytes() == keyBytes);

        std::vector<uint8_t> ciphertext(plaintext.size());
        std::vector<uint8_t> tag(16);
        REQUIRE(gcm.seal(readOf(iv), SReadOnlyByteSpan(nullptr, 0), readOf(plaintext),
                         writeOf(ciphertext), writeOf(tag)));
        tags.push_back(tag);
    }

    CHECK(tags[0] != tags[1]);
    CHECK(tags[1] != tags[2]);
    CHECK(tags[0] != tags[2]);
}
