#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

/* SHAKE128/SHAKE256::squeeze() -- the genuine extendable-output interface, added because
 * finish() can only ever produce the one fixed byteWidth() an instance was constructed with, and
 * FIPS 203/204's rejection samplers read from a SHAKE stream until enough candidates are accepted,
 * with no length known in advance (see docs/pqc-review.md's Phase 2).
 *
 * The property that actually matters is chunk-invariance: squeezing n bytes must give the same n
 * bytes no matter how they are split across calls, including splits that land exactly on, just
 * before and just after a rate-block boundary (168 for SHAKE128, 136 for SHAKE256) -- that
 * boundary is where the sponge permutes, and an off-by-one in the cursor would only show up there.
 *
 * The expected streams below come from Python's hashlib (a mature independent implementation),
 * 3 rate blocks plus 7 bytes long so several boundaries are crossed. The first 32 bytes of the
 * SHAKE128 empty-message stream also match the NIST CSRC published vector already used in
 * tests/crypto/hashers/shake128.cpp. */

namespace {

    bool hexToBytes(const char* hex, CBuffer& out) {
        TArray<uint8_t> bytes;
        if (!CHex::decode(hex, bytes)) {
            return false;
        }

        if (!out.resize(bytes.size())) {
            return false;
        }

        std::memcpy(out.toPtr(), bytes.begin(), bytes.size());
        return true;
    }

    constexpr const char* SHAKE128_EMPTY =
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
        "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
        "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea"
        "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef"
        "aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d"
        "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9"
        "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619"
        "f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b"
        "1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f"
        "1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06"
        "bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9"
        "d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2"
        "e770d01efde86e721a3f7c6cce275dabe6e2143f1af18da7efddc4c7b70b5e34"
        "5db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b4"
        "43e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b";

    constexpr const char* SHAKE128_ABC =
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378"
        "9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232"
        "a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4"
        "a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a"
        "cc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd"
        "4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b988b4"
        "75375faad996eb1b9176ecb0f8b2871723d6dbb804e23357e50732f5cfc904b1"
        "319795000d7361d9e5e1b77b4b8f5774aa1482cfa58f83096bdb2e06a3eed543"
        "a38919b57ecbec737f4086be007f8ef80094ceea8807193d46e9be540b6e99b4"
        "c1c71507095028a024e8d39aa8f4c5854cedd50d30a223e7d54e9a24f0a2526b"
        "31002afbd1b4ebea69c8400c3deb4c1c35d6dbb75651b284076f5fde47b4a058"
        "6ee173e30bd4d08f2bc59c6114bdd745d20876bee2bf800bd7d8b5e51536c844"
        "c73256f7d1ada1870c7bbaf83af10a6fdd7c02967811815459cfd02d67b936e9"
        "75c6007c63ea7ae087f0a6b0a1319668bb61788eaa3d3b78e3f2061adcdead40"
        "7085901803ec6f17f0ec650a292198275211a56bf13f0bf7241268b50d3f1e";

    constexpr const char* SHAKE256_EMPTY =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        "141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853"
        "349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86"
        "f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6"
        "77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c"
        "aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2"
        "03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f"
        "5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390b"
        "f9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dc"
        "f722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11"
        "f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837"
        "143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369d";

    constexpr const char* SHAKE256_ABC =
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        "1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78"
        "dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334"
        "e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3"
        "3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b67"
        "7513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195"
        "bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412"
        "fc346b1bb39b878330e026b12ddf384af3334560ea1d363966caa7d8ddcbec7d"
        "a52b42215c11d5f8ee57f341e399343ce63a752fc5edec99124a0eb314403e5f"
        "358b8b83d05be2d2970099284b00dcc33d7c753d1f752ab743325bc53d91aa67"
        "1e50f9c3f93abf6e9662f90145c61954f2abbd26edad1553ea3a626f359e8f79"
        "ade16384e151755c47e822fc74c5d7100fd31f667564c6debc7d20d99e109f";

    /* Squeezes `total` bytes in chunks of exactly `chunk` (the last one short if it doesn't
     * divide), and compares the whole result against `expected`. */
    template<typename Shake>
    void checkChunked(const char* message, const char* expectedHex, size_t chunk) {
        CBuffer expected;
        REQUIRE(hexToBytes(expectedHex, expected));

        const size_t total = expected.size();
        CBuffer got(total);
        REQUIRE(got.size() == total);
        std::memset(got.toPtr(), 0xAA, total);

        Shake h;
        if (message && *message) {
            const SReadOnlyByteSpan in(
                reinterpret_cast<const uint8_t*>(message), std::strlen(message)
            );
            REQUIRE(h.push(in) == in.size);
        }

        size_t produced = 0;
        while (produced < total) {
            size_t take = chunk;
            if (take > total - produced) {
                take = total - produced;
            }

            REQUIRE(h.squeeze(SByteSpan(got.toPtr() + produced, take)));
            produced += take;
        }

        CHECK(std::memcmp(got.toPtr(), expected.toPtr(), total) == 0);
    }

} // namespace

TEST_CASE("SHAKE128::squeeze(): matches the reference stream for every chunk size") {
    // 1 and 2 catch cursor arithmetic; 167/168/169 straddle the rate boundary exactly; the larger
    // sizes cross several boundaries per call.
    for (size_t chunk : { size_t(1), size_t(2), size_t(7), size_t(31), size_t(32), size_t(64),
                          size_t(167), size_t(168), size_t(169), size_t(335), size_t(336),
                          size_t(337), size_t(511) })
    {
        CAPTURE(chunk);
        checkChunked<SHAKE128>("", SHAKE128_EMPTY, chunk);
        checkChunked<SHAKE128>("abc", SHAKE128_ABC, chunk);
    }
}

TEST_CASE("SHAKE256::squeeze(): matches the reference stream for every chunk size") {
    for (size_t chunk : { size_t(1), size_t(2), size_t(7), size_t(31), size_t(32), size_t(64),
                          size_t(135), size_t(136), size_t(137), size_t(271), size_t(272),
                          size_t(273), size_t(415) })
    {
        CAPTURE(chunk);
        checkChunked<SHAKE256>("", SHAKE256_EMPTY, chunk);
        checkChunked<SHAKE256>("abc", SHAKE256_ABC, chunk);
    }
}

/* squeeze() must not be bounded by byteWidth(): that is the whole point of adding it. An instance
 * constructed for 32 bytes has to be able to stream far more than 32. */
TEST_CASE("SHAKE128/SHAKE256::squeeze(): output length is independent of byteWidth()") {
    CBuffer expected;
    REQUIRE(hexToBytes(SHAKE128_EMPTY, expected));

    SHAKE128 small(1);   // byteWidth() == 1, deliberately tiny
    CBuffer got(expected.size());
    REQUIRE(small.squeeze(got.toSpan()));
    CHECK(std::memcmp(got.toPtr(), expected.toPtr(), expected.size()) == 0);

    CBuffer expected256;
    REQUIRE(hexToBytes(SHAKE256_EMPTY, expected256));

    SHAKE256 small256(1);
    CBuffer got256(expected256.size());
    REQUIRE(small256.squeeze(got256.toSpan()));
    CHECK(std::memcmp(got256.toPtr(), expected256.toPtr(), expected256.size()) == 0);
}

/* squeeze() finalizes absorption on its first call, so push() afterwards must be rejected the same
 * way it is after finish(). */
TEST_CASE("SHAKE128::squeeze(): finalizes absorption, so push() is rejected afterwards") {
    SHAKE128 h;
    const uint8_t data[3] = { 'a', 'b', 'c' };
    REQUIRE(h.push(SReadOnlyByteSpan(data, sizeof(data))) == sizeof(data));

    uint8_t out[16] = { 0 };
    REQUIRE(h.squeeze(SByteSpan(out, sizeof(out))));

    CHECK(h.push(SReadOnlyByteSpan(data, sizeof(data))) == 0);
}

/* finish() deliberately leaves the squeeze cursor alone, so it still reports the stream's first
 * byteWidth() bytes when called before any squeeze(). Both views agree on that prefix. */
TEST_CASE("SHAKE128::finish(): agrees with squeeze()'s first bytes, and stays repeatable") {
    CBuffer expected;
    REQUIRE(hexToBytes(SHAKE128_ABC, expected));

    const uint8_t data[3] = { 'a', 'b', 'c' };

    SHAKE128 viaFinish(64);
    REQUIRE(viaFinish.push(SReadOnlyByteSpan(data, sizeof(data))) == sizeof(data));

    uint8_t first[64] = { 0 };
    SByteSpan firstSpan(first, sizeof(first));
    REQUIRE(viaFinish.finish(firstSpan));
    CHECK(std::memcmp(first, expected.toPtr(), sizeof(first)) == 0);

    // Still repeatable, and unaffected by having been called once.
    uint8_t again[64] = { 0 };
    SByteSpan againSpan(again, sizeof(again));
    REQUIRE(viaFinish.finish(againSpan));
    CHECK(std::memcmp(again, first, sizeof(first)) == 0);

    // And squeeze() on the same instance still starts at the beginning of the stream, since
    // finish() squeezed from a copy.
    uint8_t streamed[64] = { 0 };
    REQUIRE(viaFinish.squeeze(SByteSpan(streamed, sizeof(streamed))));
    CHECK(std::memcmp(streamed, first, sizeof(first)) == 0);
}

TEST_CASE("SHAKE128/SHAKE256::squeeze(): degenerate arguments") {
    SHAKE128 h;

    // An empty request is a no-op success, and must not disturb the stream.
    CHECK(h.squeeze(SByteSpan(nullptr, 0)));

    uint8_t out[8] = { 0 };
    REQUIRE(h.squeeze(SByteSpan(out, sizeof(out))));

    CBuffer expected;
    REQUIRE(hexToBytes(SHAKE128_EMPTY, expected));
    CHECK(std::memcmp(out, expected.toPtr(), sizeof(out)) == 0);

    // A null buffer with a non-zero size is a caller error, not something to write through.
    SHAKE256 h256;
    CHECK_FALSE(h256.squeeze(SByteSpan(nullptr, 16)));
}

/* reset() has to clear the squeeze cursor along with everything else, or a reused instance would
 * resume mid-stream instead of starting over. */
TEST_CASE("SHAKE128::reset(): clears the squeeze cursor") {
    CBuffer expected;
    REQUIRE(hexToBytes(SHAKE128_EMPTY, expected));

    SHAKE128 h;

    uint8_t burn[200] = { 0 };
    REQUIRE(h.squeeze(SByteSpan(burn, sizeof(burn)))); // past the first rate block

    h.reset();

    CBuffer got(expected.size());
    REQUIRE(h.squeeze(got.toSpan()));
    CHECK(std::memcmp(got.toPtr(), expected.toPtr(), expected.size()) == 0);
}
