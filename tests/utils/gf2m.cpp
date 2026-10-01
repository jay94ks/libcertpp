#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;

namespace {
    int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    std::vector<uint8_t> hexToBytes(const char* hex) {
        std::vector<uint8_t> out;
        size_t len = std::char_traits<char>::length(hex);
        for (size_t i = 0; i + 1 < len; i += 2) {
            out.push_back(uint8_t((hexVal(hex[i]) << 4) | hexVal(hex[i + 1])));
        }
        return out;
    }

    CGf2m parse(const SGf2mField& field, const char* hex) {
        auto bytes = hexToBytes(hex);
        CGf2m out;
        bool ok = CGf2m::fromBigEndian(field, SReadOnlyByteSpan(bytes.data(), bytes.size()), out);
        REQUIRE(ok);
        return out;
    }

    // Known-answer vectors (a, b, a*b, a^-1) per field, cross-derived via a standalone Python
    // implementation of GF(2^m) polynomial arithmetic (schoolbook multiply + the same binary
    // extended Euclidean inversion algorithm, but written independently of the C++ limb-wise
    // implementation under test) rather than transcribed from any single external source.
    struct KnownAnswer {
        EGf2mKnownField field;
        const char* a;
        const char* b;
        const char* ab;
        const char* aInv;
    };

    const KnownAnswer KNOWN_ANSWERS[] = {
        {
            EGF2M_M163,
            "0294dc13fc115ac6cb3c58fd846ec5c07ff6908e53",
            "009c8be3e693af8a68f77282bd1201af823a0a4fe1",
            "02f9d993f9ba6ee30eb4c182fd6c17a8bf4a119b42",
            "02ed5bc4b9a2599366429f9accfb14dffae4cd2f2c",
        },
        {
            EGF2M_M233,
            "01d6c8fa65ab0e3605cd9ab15d0be84644de88c3d52b0c43f62912f8a9a5",
            "00dbcc3f525d91da942bf2f44203de05ef1e2cd6ad8e3ff33516d38e5433",
            "01dbb6559f62aa53cb546b9714bbc0d294328313ab72f1975c91c821754e",
            "01edfbec7204e7fc82c638990e0a34daa3cc8e9e6a64ba55bec73cb9b1af",
        },
        {
            EGF2M_M283,
            "03a98a85af395ddf588590d1cb31a5a541346ec0ac2c81558b8df6d7a58a40e3aec4faa1",
            "043e9b52673abc2b0f98219db51641898c29aec5bf56e7cf7e7b91bca9655dc7aa94affd",
            "04f0a2bd4f6056407dfcc42c64625e64c71779ed6ca8efb7964365b5e5f1b1016d193902",
            "00022c3fb4963ddb9e7a468ff0e4930e13c00e099964c013ca5cef5ebf6c5ae788cf9c3a",
        },
        {
            EGF2M_M409,
            "01a45f0f914bfaf280dd7c1531a01101800f36d7d7f978f0a674894eaf61acfe376ceae9ae8692ade621e464dc6828588dd77855",
            "014cfd2130bc65d57594e68e791fa9adf8e3dd706ecb52454c5082af09e88a08330ec367de3d130e41b64a8d9ca805e18be822ed",
            "005f121ec08320594b96fd6fbed2dfa5ae3d1e486b91fc8226fb8d5da2744cd852e14886a8f878e834ceb0a3b0000cd80e82428d",
            "01276714ec120dfaf525ecae74ce85791fd09484d9ebc364b173ba29c2e414e5df27d73b32f055bfcd6b628a913497a150464345",
        },
        {
            EGF2M_M571,
            "04cfd5f1814f7172b4b161ddd150543490055b197c7132c159d4756a0a10302d86464ed67338bd3217baa6642a507bd5336ed46492d516fee5a381a0c9d32a03d4ccaf167412c30d",
            "05c5dc610511f14d57dd04f7d0cf27d0706a18e7c67212978e9a42f0fdf3f46ffca3df48d3489ccf392312b11a4f6af7e78cf12eda67d1ac65301b6d2485634d68be1a780bcf2845",
            "04e9a142dc7e0e353bf191335b89bf81ab88b7384dee8444a9afa09bec79e3e7ccf7e9b5851e01cba546eb343279d596c23f6a435aa10b8cc3d1a9370a668833716a424a482ffcc2",
            "0182f18148cc9fba1f0b645cfb01fa0776d3d7b8d41703a2e3ae45eaaf3af4414efed8226d156c733d3a25704286df60c5e9255744b8b61c8a53c8c8ab4de89b8552f594cb0a3967",
        },
    };
}

TEST_CASE("CGf2m: knownField() returns the five NIST binary field descriptors") {
    SGf2mField field;
    CHECK_FALSE(CGf2m::knownField(EGF2M_UNKNOWN, field));
    CHECK_FALSE(CGf2m::knownField(EGF2M_MAX, field));

    REQUIRE(CGf2m::knownField(EGF2M_M163, field));
    CHECK(field.m == 163);
    REQUIRE(CGf2m::knownField(EGF2M_M233, field));
    CHECK(field.m == 233);
    REQUIRE(CGf2m::knownField(EGF2M_M283, field));
    CHECK(field.m == 283);
    REQUIRE(CGf2m::knownField(EGF2M_M409, field));
    CHECK(field.m == 409);
    REQUIRE(CGf2m::knownField(EGF2M_M571, field));
    CHECK(field.m == 571);
}

TEST_CASE("CGf2m: multiply/inverse known-answer vectors, independently cross-derived per field") {
    for (const auto& kat : KNOWN_ANSWERS) {
        SGf2mField field;
        REQUIRE(CGf2m::knownField(kat.field, field));

        CGf2m a = parse(field, kat.a);
        CGf2m b = parse(field, kat.b);
        CGf2m expectedAb = parse(field, kat.ab);
        CGf2m expectedAInv = parse(field, kat.aInv);

        CGf2m ab(a);
        ab.mul(b);
        CHECK(ab == expectedAb);

        CGf2m aInv(a);
        aInv.inverse();
        CHECK(aInv == expectedAInv);

        CGf2m product(a);
        product.mul(aInv);
        CHECK(product == CGf2m(field, 1));
    }
}

TEST_CASE("CGf2m: encode/decode round-trips for every known field") {
    EGf2mKnownField ids[] = { EGF2M_M163, EGF2M_M233, EGF2M_M283, EGF2M_M409, EGF2M_M571 };

    for (auto id : ids) {
        SGf2mField field;
        REQUIRE(CGf2m::knownField(id, field));

        for (const auto& kat : KNOWN_ANSWERS) {
            if (kat.field != id) {
                continue;
            }

            CGf2m a = parse(field, kat.a);

            TArray<uint8_t> encoded;
            a.toBigEndian(encoded);
            CHECK(encoded.size() == (field.m + 7) / 8);

            CGf2m decoded;
            REQUIRE(CGf2m::fromBigEndian(field, SReadOnlyByteSpan(encoded.begin(), encoded.size()), decoded));
            CHECK(decoded == a);
        }
    }
}

TEST_CASE("CGf2m: fromBigEndian rejects a value with a bit set at or above m") {
    SGf2mField field;
    REQUIRE(CGf2m::knownField(EGF2M_M163, field));

    // fieldByteLen(163) == 21 bytes (bits 0..167 representable); set bit index 163 itself, the
    // first bit at or beyond field.m == 163 -- must be rejected even though it fits in the
    // buffer's width.
    uint8_t oversized[21] = { 0 };
    oversized[0] = 0x08; // byte 0 (most significant, big-endian) covers bits 160..167; bit 3 of it is bit 163

    CGf2m out;
    CHECK_FALSE(CGf2m::fromBigEndian(field, SReadOnlyByteSpan(oversized, sizeof(oversized)), out));
}

TEST_CASE("CGf2m: field axioms hold for each known field (a+a=0, square()==mul(self), distributivity spot check)") {
    for (const auto& kat : KNOWN_ANSWERS) {
        SGf2mField field;
        REQUIRE(CGf2m::knownField(kat.field, field));

        CGf2m a = parse(field, kat.a);
        CGf2m b = parse(field, kat.b);
        CGf2m one(field, 1);
        CGf2m zero(field, 0);

        CGf2m aPlusA(a);
        aPlusA.add(a);
        CHECK(aPlusA == zero);

        CGf2m aSquared(a);
        aSquared.square();
        CGf2m aTimesA(a);
        aTimesA.mul(a);
        CHECK(aSquared == aTimesA);

        CGf2m aTimesOne(a);
        aTimesOne.mul(one);
        CHECK(aTimesOne == a);

        CGf2m aTimesZero(a);
        aTimesZero.mul(zero);
        CHECK(aTimesZero == zero);

        // distributivity: a*(b+1) == a*b + a*1 (a spot check, not a general proof, but enough
        // to catch a broken multiply/add/reduce interaction)
        CGf2m bPlusOne(b);
        bPlusOne.add(one);

        CGf2m lhs(a);
        lhs.mul(bPlusOne);

        CGf2m ab(a);
        ab.mul(b);

        CGf2m aTimesOne2(a);
        aTimesOne2.mul(one);

        CGf2m rhs(ab);
        rhs.add(aTimesOne2);

        CHECK(lhs == rhs);
    }
}
