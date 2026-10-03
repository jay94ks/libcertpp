// PBKDF2 (RFC 8018 5.2), against RFC 6070's published HMAC-SHA1 vectors and RFC 7914 section
// 11's HMAC-SHA256 ones.
//
// Every expected value below was reproduced independently from Python's hashlib.pbkdf2_hmac
// before being written here, which is worth saying because two of them do not match what the
// RFCs are widely quoted as saying -- the recollection was wrong, not hashlib. RFC 6070's
// fourth case ends `...8b291a964cf2f07038`, and RFC 7914's first SHA-256 case has
// `...fec1691c22544b60...` with one `5` where it is easy to type two.
//
// What these vectors actually catch, which a self-consistency test cannot:
//
//  - T(i) being the XOR of every U(j) rather than just the last one. Keeping only U(c) costs
//    exactly the same to compute and matches no other implementation.
//  - The salt appearing only in U(1), not in every round.
//  - INT(i) being four big-endian bytes counting from 1, which only shows up once the output
//    runs past one digest (RFC 6070's 25-byte SHA-1 case and the 64-byte SHA-256 ones).

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <string>
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
        for (const char* p = hex; *p && *(p + 1); p += 2) {
            out.push_back(uint8_t((nibble(p[0]) << 4) | nibble(p[1])));
        }
        return out;
    }

    SReadOnlyByteSpan spanOf(const std::vector<uint8_t>& v) {
        return v.empty() ? SReadOnlyByteSpan(nullptr, 0)
                         : SReadOnlyByteSpan(v.data(), v.size());
    }

    // A password or salt given as a std::string rather than hex, since RFC 6070 states most of
    // its inputs as text -- and one of them contains an embedded NUL, which is exactly why this
    // takes a std::string with an explicit length rather than a `const char*`.
    SReadOnlyByteSpan bytesOf(const std::string& s) {
        return s.empty()
            ? SReadOnlyByteSpan(nullptr, 0)
            : SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    void checkVector(
        EHashers alg, const std::string& password, const std::string& salt,
        uint32_t iterations, size_t length, const char* expectedHex
    ) {
        const std::vector<uint8_t> expected = fromHex(expectedHex);
        REQUIRE(expected.size() == length);

        std::vector<uint8_t> derived(length, 0x00);
        REQUIRE(CPbkdf2::derive(
            alg, bytesOf(password), bytesOf(salt), iterations,
            SByteSpan(derived.data(), derived.size())) == ERET_OK);

        CHECK(derived == expected);
    }
} // namespace

// RFC 6070's five short-iteration cases. The 1- and 2-iteration ones pin the chaining at its
// smallest: with c=1 the output is U(1) alone, so a bug that drops the XOR passes this one and
// fails c=2, which is why both are here.
TEST_CASE("CPbkdf2: RFC 6070, PBKDF2-HMAC-SHA1") {
    checkVector(EHASH_SHA1, "password", "salt", 1, 20,
                "0c60c80f961f0e71f3a9b524af6012062fe037a6");

    checkVector(EHASH_SHA1, "password", "salt", 2, 20,
                "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");

    checkVector(EHASH_SHA1, "password", "salt", 4096, 20,
                "4b007901b765489abead49d926f721d065a429c1");

    // 25 bytes out of a 20-byte digest: two blocks, the second truncated. This is the case that
    // exercises INT(i) at all -- with dkLen <= hLen the counter is always 1 and a wrong
    // encoding of it is invisible.
    checkVector(EHASH_SHA1, "passwordPASSWORDpassword",
                "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");

    // An embedded NUL in both password and salt. A length-aware implementation handles this
    // without noticing; one that reached for strlen somewhere derives from "pass" and "sa".
    checkVector(EHASH_SHA1, std::string("pass\0word", 9), std::string("sa\0lt", 5),
                4096, 16, "56fa6aa75548099dcc37d7f03425e0c3");
}

// RFC 7914 section 11's PBKDF2-HMAC-SHA256 vectors, which scrypt quotes for exactly this
// purpose. 64 bytes out of a 32-byte digest is two full blocks, so the counter is exercised
// here too, and under a different digest length from the SHA-1 cases above.
TEST_CASE("CPbkdf2: RFC 7914 section 11, PBKDF2-HMAC-SHA256") {
    checkVector(EHASH_SHA256, "passwd", "salt", 1, 64,
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");

    // 80000 iterations, which also serves as the cost sanity check: if this returns instantly,
    // the iteration loop is not running.
    checkVector(EHASH_SHA256, "Password", "NaCl", 80000, 64,
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d");
}

// RFC 6070's 16777216-iteration case is deliberately absent: it is the same derivation as the
// 4096-iteration one with a larger c, and at this library's own SHA-1 throughput it runs for
// minutes, which is not a cost worth paying on every `ctest` run to re-test the one loop the
// 4096- and 80000-iteration cases above already drive. The two vectors below stand in for what
// it would have added, and are reproduced from Python's hashlib rather than from an RFC --
// stated plainly, because a vector this file generated itself proves interoperability only
// against hashlib and not against the RFC.
TEST_CASE("CPbkdf2: cross-checked against hashlib for the lengths the RFCs do not cover") {
    // 80 bytes out of SHA-256: three blocks, the third truncated to 16.
    checkVector(EHASH_SHA256, "password", "salt", 4096, 80,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
                "f7ad98c1b458ce3fd74ca35beba3cda7b8d1038d6a87071b918f837405f3fe77"
                "28ffe7f0976fc35dd82fc0e5e46ce9ce");

    // SHA-512, whose 128-byte HMAC block size is a different code path inside CHmac.
    checkVector(EHASH_SHA512, "password", "salt", 4096, 64,
                "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
                "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5");
}

TEST_CASE("CPbkdf2: an iteration count of 0 is rejected, not treated as unstretched") {
    uint8_t out[32] = { 0 };
    const std::vector<uint8_t> salt(8, 0x11);

    CHECK(CPbkdf2::derive(EHASH_SHA256, bytesOf("pw"), spanOf(salt), 0,
                          SByteSpan(out, sizeof(out))) == ERET_BADREQ);

    // The output buffer must be left alone on a refusal, so that a caller who ignores the
    // return code gets zeroes rather than something that looks like a key.
    for (size_t i = 0; i < sizeof(out); ++i) {
        CHECK(out[i] == 0x00);
    }

    CHECK(CPbkdf2::derive(EHASH_SHA256, bytesOf("pw"), spanOf(salt), 1,
                          SByteSpan(out, sizeof(out))) == ERET_OK);
}

TEST_CASE("CPbkdf2: the output-length bound and the other refusals") {
    const std::vector<uint8_t> salt(8, 0x11);

    // (2^32 - 1) * hLen, which is the ceiling INT(i) imposes.
    CHECK(CPbkdf2::maxDeriveBytes(EHASH_SHA1) == size_t(0xFFFFFFFFull * 20ull));
    CHECK(CPbkdf2::maxDeriveBytes(EHASH_SHA256) == size_t(0xFFFFFFFFull * 32ull));
    CHECK(CPbkdf2::maxDeriveBytes(EHASH_SHA512) == size_t(0xFFFFFFFFull * 64ull));

    // SHAKE is an XOF, so HMAC is not defined over it and neither is this.
    CHECK(CPbkdf2::maxDeriveBytes(EHASH_SHAKE256) == 0);
    CHECK(CPbkdf2::maxDeriveBytes(EHASH_UNKNOWN) == 0);

    uint8_t out[32];
    CHECK(CPbkdf2::derive(EHASH_SHAKE256, bytesOf("pw"), spanOf(salt), 1,
                          SByteSpan(out, sizeof(out))) == ERET_NOTSUP);

    // An empty output has no meaning, and a null one with a non-zero size is a caller bug.
    CHECK(CPbkdf2::derive(EHASH_SHA256, bytesOf("pw"), spanOf(salt), 1,
                          SByteSpan(out, 0)) == ERET_BADREQ);
    CHECK(CPbkdf2::derive(EHASH_SHA256, bytesOf("pw"), spanOf(salt), 1,
                          SByteSpan(nullptr, 32)) == ERET_BADREQ);

    // A length past the bound is refused rather than silently wrapping the counter. Only
    // reachable where size_t is wide enough to express it.
    if (sizeof(size_t) >= 8) {
        const size_t tooLong = CPbkdf2::maxDeriveBytes(EHASH_SHA256) + 1;
        CHECK(CPbkdf2::derive(EHASH_SHA256, bytesOf("pw"), spanOf(salt), 1,
                              SByteSpan(out, tooLong)) == ERET_BADREQ);
    }
}

TEST_CASE("CPbkdf2: an empty password and an empty salt are permitted") {
    // RFC 8018 puts no minimum on either. Allowing them matters for reading somebody else's
    // container, which may well contain a short or absent salt; it is not an endorsement.
    uint8_t a[20], b[20];
    REQUIRE(CPbkdf2::derive(EHASH_SHA1, SReadOnlyByteSpan(nullptr, 0), bytesOf("salt"), 2,
                            SByteSpan(a, sizeof(a))) == ERET_OK);
    REQUIRE(CPbkdf2::derive(EHASH_SHA1, bytesOf("password"), SReadOnlyByteSpan(nullptr, 0), 2,
                            SByteSpan(b, sizeof(b))) == ERET_OK);

    CHECK(std::memcmp(a, b, sizeof(a)) != 0);
}

TEST_CASE("CPbkdf2: the iteration count and salt both change the output") {
    // Not a known-answer test; a guard against a `derive()` that quietly ignores one of its
    // arguments, which the RFC vectors would also catch but only for the exact values they use.
    uint8_t base[32], moreRounds[32], otherSalt[32];

    REQUIRE(CPbkdf2::derive(EHASH_SHA256, bytesOf("pw"), bytesOf("saltsalt"), 1000,
                            SByteSpan(base, sizeof(base))) == ERET_OK);
    REQUIRE(CPbkdf2::derive(EHASH_SHA256, bytesOf("pw"), bytesOf("saltsalt"), 1001,
                            SByteSpan(moreRounds, sizeof(moreRounds))) == ERET_OK);
    REQUIRE(CPbkdf2::derive(EHASH_SHA256, bytesOf("pw"), bytesOf("saltsalu"), 1000,
                            SByteSpan(otherSalt, sizeof(otherSalt))) == ERET_OK);

    CHECK(std::memcmp(base, moreRounds, sizeof(base)) != 0);
    CHECK(std::memcmp(base, otherSalt, sizeof(base)) != 0);
}

TEST_CASE("CPbkdf2: a prefix of a longer derivation equals the shorter one") {
    // PBKDF2's blocks are independent given the counter, so DK(n) is a prefix of DK(m > n).
    // Pinning it catches a per-call salt or counter that depends on the requested length.
    uint8_t shortDk[20], longDk[60];

    REQUIRE(CPbkdf2::derive(EHASH_SHA1, bytesOf("password"), bytesOf("salt"), 100,
                            SByteSpan(shortDk, sizeof(shortDk))) == ERET_OK);
    REQUIRE(CPbkdf2::derive(EHASH_SHA1, bytesOf("password"), bytesOf("salt"), 100,
                            SByteSpan(longDk, sizeof(longDk))) == ERET_OK);

    CHECK(std::memcmp(shortDk, longDk, sizeof(shortDk)) == 0);
}
