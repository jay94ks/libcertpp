// NIST CAVP "FIPS 186-3 DSA" SigVer known-answer vectors.
//
// Source: csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/
// documents/dss/186-3dsatestvectors.zip, file SigVer.rsp, sections
// [mod = L=1024, N=160, SHA-256] and [mod = L=2048, N=256, SHA-256]. The (P, Q, G) domain
// parameters head each section and are inlined into every vector here; X is a signing value and
// is unused for verification.
//
// SHA-256 against an N=160 subgroup also exercises FIPS 186-4 6.4 truncation (a 32-byte digest
// cut to the leftmost 160 bits), though note every DSA N in FIPS 186-4 (160, 224, 256) is a
// whole number of bytes, so DSA cannot reach the sub-byte shift that the binary curves in
// kat_ecdsa.cpp do.
//
// Transcription was cross-checked by re-implementing DSA verification in Python and confirming
// the verdict matched CAVP's Result column for all four records.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    /* Decodes an even-length hex literal into raw bytes. */
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

    /* Computes a digest over msg with one of the library's own built-in hashers. */
    std::vector<uint8_t> digestOf(EHashers alg, const std::vector<uint8_t>& msg) {
        IHasherPtr hasher;
        REQUIRE(IHasher::create(alg, hasher) == ERET_OK);
        REQUIRE(hasher);

        hasher->push(SReadOnlyByteSpan(msg.data(), msg.size()));

        std::vector<uint8_t> out(hasher->byteWidth());
        SByteSpan outSpan(out.data(), out.size());
        REQUIRE(hasher->finish(outSpan));
        return out;
    }

    // --> Every encoder below is hand-built rather than reached through asn1::CDer, so that a
    // --> vector's expected input never depends on the same encoder under test elsewhere.
    /* Appends a DER definite-length field: short form below 128, minimal long form above. */
    void appendDerLength(std::vector<uint8_t>& out, size_t len) {
        if (len < 0x80) {
            out.push_back(uint8_t(len));
            return;
        }

        uint8_t bytes[sizeof(size_t)];
        size_t count = 0;
        for (size_t v = len; v; v >>= 8) {
            bytes[count++] = uint8_t(v & 0xFF);
        }

        out.push_back(uint8_t(0x80 | count));
        while (count) {
            out.push_back(bytes[--count]);
        }
    }

    /* Appends a minimally-encoded DER INTEGER holding a non-negative big-endian magnitude. */
    void appendDerInteger(std::vector<uint8_t>& out, const std::vector<uint8_t>& magnitude) {
        REQUIRE_FALSE(magnitude.empty());

        size_t at = 0;
        while (at + 1 < magnitude.size() && magnitude[at] == 0x00) {
            ++at;
        }

        std::vector<uint8_t> body;
        if (magnitude[at] & 0x80) {
            body.push_back(0x00); // --> keep the value non-negative under DER's sign convention.
        }
        body.insert(body.end(), magnitude.begin() + at, magnitude.end());

        out.push_back(0x02);
        appendDerLength(out, body.size());
        out.insert(out.end(), body.begin(), body.end());
    }

    /* Wraps already-encoded content in a DER SEQUENCE. */
    std::vector<uint8_t> derSequence(const std::vector<uint8_t>& inner) {
        std::vector<uint8_t> der;
        der.push_back(0x30);
        appendDerLength(der, inner.size());
        der.insert(der.end(), inner.begin(), inner.end());
        return der;
    }

    /* Builds Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } from a vector's raw r/s hex. */
    std::vector<uint8_t> derSignature(const char* rHex, const char* sHex) {
        std::vector<uint8_t> inner;
        appendDerInteger(inner, fromHex(rHex));
        appendDerInteger(inner, fromHex(sHex));
        return derSequence(inner);
    }
}

namespace {
    /* One CAVP 186-3 DSA SigVer record, with its own (p, q, g) domain parameters. */
    struct DsaSigVerVector {
        const char* label;
        const char* p;
        const char* q;
        const char* g;
        const char* y;
        const char* r;
        const char* s;
        const char* msg;
        bool shouldVerify;
    };

    const DsaSigVerVector VECTORS[] = {
        {
            "mod = L=1024, N=160, SHA-256 Result = F (1 - Message changed)",
            "be365a60635e80455c13362b9febfb3a89ce15fb15bdae3ed9821a805412fa1f"
            "fe44fd4598d87e1376cbc4d71d7dfac11ac93b9042062faf4ea315dda571b5cd"
            "578fb789e9a5bf52c6fc76b4efad69c59d25b919a54c2d2e93c1da290a584b06"
            "946dfd697ef42380ed0fbf6f783e46ff8fe6ca06863b2797e5e5b312ff26d2f1",
            "cea68e6d533ea16e36a85b5f934cc77101b467ab",
            "23af09eee977ea0b98670cacbb8ed1138059336db29ef19cca4fc578d84bbfc1"
            "03cfbbdbdd9e8dc56d93aeadaecb86e85cc459ac3ee70cc729d4822e45310d28"
            "4424713cf3a3762e9389330d3b4535773cc3738a456a39df28f8220428734085"
            "e0b86dc64b4e5380cada4bd45f08606fad5a3c9b1adaaa7c341797286db47cc7",
            "162e2fbfd6e3cabb1d83800051fb14315812e6d68c8faf65c883b6d9923af8c6"
            "f91c30fb0f385b8fe2117a925f4a35b6d3326c90a676d872006e516e9e75df7b"
            "abbf164a943a0004b8e7f2273bde6aec7dce31b2073fffed4406becbff975b3b"
            "e2c99fec1b25307acad9c5d4b186e83cc76fc6a6819a3effbbaf463b7290b54b",
            "2492cd52b194a86d2848b697456b06de5bc0c131",
            "329c80d06e6ffc5a504ac066849f4006584561cb",
            "edc82a03fb29309320ca7ea7de1e5aeaa23ec8bc192b9e517b25a6c7478feb24"
            "f31d7c01afcd4d182591a9a116da2f75a037165062c9e09edc38c1cca5d71a10"
            "d63836bb6a00f52f7aa04c7b345b5d75ec06aac1ba0ca0c216d8f4a355ba5058"
            "ae92fbcb3eaf16251972a96dd6f58542655d5954f498161d04844e8d4d2d9fb7",
            false
        },
        {
            "mod = L=1024, N=160, SHA-256 Result = P",
            "be365a60635e80455c13362b9febfb3a89ce15fb15bdae3ed9821a805412fa1f"
            "fe44fd4598d87e1376cbc4d71d7dfac11ac93b9042062faf4ea315dda571b5cd"
            "578fb789e9a5bf52c6fc76b4efad69c59d25b919a54c2d2e93c1da290a584b06"
            "946dfd697ef42380ed0fbf6f783e46ff8fe6ca06863b2797e5e5b312ff26d2f1",
            "cea68e6d533ea16e36a85b5f934cc77101b467ab",
            "23af09eee977ea0b98670cacbb8ed1138059336db29ef19cca4fc578d84bbfc1"
            "03cfbbdbdd9e8dc56d93aeadaecb86e85cc459ac3ee70cc729d4822e45310d28"
            "4424713cf3a3762e9389330d3b4535773cc3738a456a39df28f8220428734085"
            "e0b86dc64b4e5380cada4bd45f08606fad5a3c9b1adaaa7c341797286db47cc7",
            "54294fc337ce875e2cd775ea2f070b217990281fcebbf69c62d0ec9f992e4c04"
            "d30dd17326a08e918231cdda26a46293af877243b96cae0bff256857a60a3046"
            "cd6bda442ee8b2df261d716afcfac9d734fe881ea810062a87930b7139814757"
            "4dd64ad5f2812ca03301dabb6a0868a12aab5bee00f29ee5d0b61ba04bcd9621",
            "0ddd11a77b70780ed4c22d4c6b5da69140d4cb14",
            "9e390130cdce95d9b12599c195acf24df37bcba2",
            "ab806e1cd9a590c37738d76d17e05d4fdd5a27c8d35a8386a47576175bc2e9f3"
            "33bdec993965d706dad1535195b08a1d3c692e466da5f0d55671e16a01705263"
            "1dfadc8e51b2679249bea5d971437ae6899f5a58913a38540a6afe639d1170a3"
            "a9f15b0b02499e6c7fb38396f75a451dd6a4f890361ffe0e310cf908c23f3fbd",
            true
        },
        {
            "mod = L=2048, N=256, SHA-256 Result = F (1 - Message changed)",
            "cdf428329e226cf715f18eed005e439a8c7b927edd24c866be6c1b370057059e"
            "a426d06f584f8e3c89f02fe8d4042604a2fe0db63a87ff018dfaec7790b88fd1"
            "da8396561ae62df6f18d3540992efc5ecce63068f5f595687b8bbeed5801d5b6"
            "c6bdf362dadebb80e190d719d144db693fc43cefbd72b149570a96282fd9441c"
            "397d98b15d73f8cfaa8f6514a16f5992a0a02fd7b6e4932b1e7e7ef2db717815"
            "b11e867e187aae26f9c16ca0a5ca434acf8f3356c3711765fe5e548b1edce381"
            "bdd843580f9a881d702f00a0719c3bfa8576304decb616b08ef8db6f8c3d4892"
            "3a2a30b9b505ad737af1cbb0019558487400379738fd89c1ee01285e76e2d98b",
            "daf3ebd85f57a8731538596876e8a34e73c732bc69b4d64b010bd7d5b63a09ef",
            "6cb6a8c1b8ea97173e5ae1d2a2d530468fd932b81a4f3c3e11042d56a61a504b"
            "9c207da7cdca293c04f78583cf218e1cd2c1a92637ab4ff61d2eaa5e8e8221bf"
            "e17e6a741791f21c799221ae4c703262a6dc2e295e36939e248dacaaffe67307"
            "1f6dc7a90d7ca3427556fb99fb1fdca9de3f745b5e56be5b5933ebcba4f0c60f"
            "ef3798cdca519997ef74acd7000d3a286d01c7000a66fe0066be4381842aa040"
            "c3bf465306c38752d41c29162c4d294f2b1f7e9ad9232aadb469047f4050b085"
            "bafa06283def7d84958528a3f129a3bc81466c0ccd493fcaa87e805e7bd44500"
            "90ce55652dba15271234fbe0cfef66f3ed9d569e565bd1218f2856637a5b26a4",
            "2cc1264427522aa6ff6c9e3beb23e1d1714e7a3cd3b592faa74ff44e8d81a18b"
            "416c887a97a6e2f4592529116090a6ec4f0e73a45a9984c483cf7206e302c7d7"
            "7e27e5eb11ac581821bd2b91b9857764e155f850f5c25b909d6fe23c19595dde"
            "40750c7fb0e62d95c2944081c0d10767a11dbeb092c9b08d6d197dd34cdbd873"
            "f8db7c3d33987ed2fd2e395c86588edf131fadb936ef8085741f28c8f9d7848c"
            "65a709f9c44b8db85989732332d809544c8c5362b39f97331b66086af5d3dc70"
            "3a2c30d96ef0763e13c171728d7b057b302c0c04642aa77b896c743da9f0d303"
            "49745e2e552bac2a4178591019af33058a1948ae4059c2efd7aa9f05df06bb",
            "59f9e094d7d55d3a3a362c6671542a92034e89f36354da25bd4f3efd65b430ef",
            "47a78ba3f773f398361c41266ce6c84d0443b9b233b52c7939b9dc6d69051e9c",
            "bc3414673a2a567aad487af1385b90bd1adb92361f59e27ede8af63e964ece90"
            "b1aa7a330a8e41549e3d1e0cd32b339fbaf1120a79ca3768bd1f60bea4def3ea"
            "a4625cb9b19169248800f82837feb151fd5d24dece7bb1f7de45175cf77dfada"
            "a12ae77f3f2cf55ddfd38714892d556ec91886c9734842304f1be1af439a56e8",
            false
        },
        {
            "mod = L=2048, N=256, SHA-256 Result = P",
            "cdf428329e226cf715f18eed005e439a8c7b927edd24c866be6c1b370057059e"
            "a426d06f584f8e3c89f02fe8d4042604a2fe0db63a87ff018dfaec7790b88fd1"
            "da8396561ae62df6f18d3540992efc5ecce63068f5f595687b8bbeed5801d5b6"
            "c6bdf362dadebb80e190d719d144db693fc43cefbd72b149570a96282fd9441c"
            "397d98b15d73f8cfaa8f6514a16f5992a0a02fd7b6e4932b1e7e7ef2db717815"
            "b11e867e187aae26f9c16ca0a5ca434acf8f3356c3711765fe5e548b1edce381"
            "bdd843580f9a881d702f00a0719c3bfa8576304decb616b08ef8db6f8c3d4892"
            "3a2a30b9b505ad737af1cbb0019558487400379738fd89c1ee01285e76e2d98b",
            "daf3ebd85f57a8731538596876e8a34e73c732bc69b4d64b010bd7d5b63a09ef",
            "6cb6a8c1b8ea97173e5ae1d2a2d530468fd932b81a4f3c3e11042d56a61a504b"
            "9c207da7cdca293c04f78583cf218e1cd2c1a92637ab4ff61d2eaa5e8e8221bf"
            "e17e6a741791f21c799221ae4c703262a6dc2e295e36939e248dacaaffe67307"
            "1f6dc7a90d7ca3427556fb99fb1fdca9de3f745b5e56be5b5933ebcba4f0c60f"
            "ef3798cdca519997ef74acd7000d3a286d01c7000a66fe0066be4381842aa040"
            "c3bf465306c38752d41c29162c4d294f2b1f7e9ad9232aadb469047f4050b085"
            "bafa06283def7d84958528a3f129a3bc81466c0ccd493fcaa87e805e7bd44500"
            "90ce55652dba15271234fbe0cfef66f3ed9d569e565bd1218f2856637a5b26a4",
            "1c3aa2f539438145b05dd13a17d666022944fe6e3dc2a14e41a32fbc85546e0d"
            "a88b5b9d822a17f0c30ed317f4cc716f2847871c192ea4dda488aea291ec31fb"
            "5a73424d12b034b642e175f25b102217a0bf1de695923900c87f3f2911107ee0"
            "6bb9f58cef4d18c29a016ebf63a4bea851c3a7e85a7c3d69e8896f59f9c7f1d7"
            "7386c1e80391a1b9c4f82eaf59b6d72c7e8663b121fdd3b5510d5db5971658d2"
            "33e25b646a27b1e1ae0c859dc73f7763b91fff6b3140e284c3a4650d17beeca2"
            "319c5c4a545f6de728137f5bbac6e3027e5588294ae5532891b8053dc9cbd044"
            "9a09e54f4e3ac4eaf7e1bd2a727de8f14a001db92870807898bb504f5f4389bc",
            "96246546c49d2a00c5605cc5bcb18e229e272374c4d7fa6c8ace99eafc080342",
            "b77d5dd30b6daae84580cf2b3cf31eca713c884dd5659cf5307c91e525991487",
            "f93230c8e56f77d8507cadb3d3b930c715e06763f2f38cc735ec626e650e4d3b"
            "76b4f0427500106daa2671dcebbfaf04a8c660fa285cc059894c685b5eb0098d"
            "12e406a47200c66818c255a7a55edbb4d0a94fef563af9330bd90286e9a18591"
            "0d741c19be9965f44b630fbbb5f434967101ccbc693545a39430402cc0dc270c",
            true
        },
    };

    /* Builds this library's DSA public key blob: SEQUENCE { p, q, g, y }, all INTEGERs. */
    std::vector<uint8_t> dsaPublicKeyDer(
        const char* p, const char* q, const char* g, const char* y
    ) {
        std::vector<uint8_t> inner;
        appendDerInteger(inner, fromHex(p));
        appendDerInteger(inner, fromHex(q));
        appendDerInteger(inner, fromHex(g));
        appendDerInteger(inner, fromHex(y));
        return derSequence(inner);
    }
}

TEST_CASE("DSA: CAVP 186-3 SigVer known-answer vectors verify as published") {
    IAsymmetricPtr dsa = IAsymmetric::builtIn(EASYM_DSA);
    REQUIRE(dsa);

    for (const DsaSigVerVector& v : VECTORS) {
        INFO("vector: " << v.label);

        std::vector<uint8_t> der = dsaPublicKeyDer(v.p, v.q, v.g, v.y);
        IPublicKeyPtr pub = dsa->createPublicKey(SReadOnlyByteSpan(der.data(), der.size()));
        REQUIRE(pub);

        IAsymmetricContextPtr ctx = dsa->createContext();
        REQUIRE(ctx);
        ctx->keyPair(pub, nullptr);

        std::vector<uint8_t> digest = digestOf(EHASH_SHA256, fromHex(v.msg));
        std::vector<uint8_t> sig = derSignature(v.r, v.s);

        ERetCode got = ctx->verify(
            SReadOnlyByteSpan(digest.data(), digest.size()),
            SReadOnlyByteSpan(sig.data(), sig.size()));

        if (v.shouldVerify) {
            CHECK(got == ERET_OK);
        } else {
            CHECK(got != ERET_OK);
        }
    }
}
