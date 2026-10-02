// NIST CAVP "FIPS 186-3 RSA" SigVer PKCS#1 v1.5 known-answer vectors.
//
// Source: csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/
// documents/dss/186-3rsatestvectors.zip, file SigVer15_186-3.rsp, section [mod = 2048],
// the SHAAlg = SHA256 records. Note the modulus n is carried in its own record ahead of the
// per-signature records in that file; it is inlined into each vector here.
//
// The signature is kept at the full 256-byte modulus width (leading zero bytes included),
// because verify() requires signature.size to equal ceil(n.bitLength() / 8) exactly. The hash
// is not named anywhere in the API -- RSA verify() infers it from the digest length, so a
// 32-byte digest selects the SHA-256 DigestInfo prefix.
//
// Transcription was cross-checked by re-implementing PKCS#1 v1.5 verification in Python
// (modexp, then a full re-encode-and-compare of the padded EM) and confirming the verdict
// matched CAVP's Result column for both records.

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
    /* One CAVP 186-3 "SigVer PKCS#1 Ver 1.5" record, 2048-bit modulus with SHA-256. */
    struct RsaSigVerVector {
        const char* label;
        const char* n;
        const char* e;
        const char* sig;        // --> full modulus width; verify() requires exactly that length.
        const char* msg;
        bool shouldVerify;
    };

    const RsaSigVerVector VECTORS[] = {
        {
            "RSA-2048/SHA-256 Result = P",
            "c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026b"
            "cb2399bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae85208"
            "7d25f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d"
            "11542a705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671"
            "de874bb9cecb058c6c8344aa8c93754d6effcd44a41ed7de0a9dcd9144437f21"
            "2b18881d042d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189"
            "ff968b92f33c266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce9"
            "8f54ed237b4a04a4159a5f6250a296a902880204e61d891c4da29f2d65f34cbb",
            "49d2a1",
            "51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027"
            "d39365de70a31db05e9e10eb6148cb7f6425f0c93c4fb0e2291adbd22c77656a"
            "fc196858a11e1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd"
            "509e896f63884e9424f69c1c5397959f1e52a368667a598a1fc90125273d9341"
            "295d2f8e1cc4969bf228c860e07a3546be2eeda1cde48ee94d062801fe666e4a"
            "7ae8cb9cd79262c017b081af874ff00453ca43e34efdb43fffb0bb42a4e2d32a"
            "5e5cc9e8546a221fe930250e5f5333e0efe58ffebf19369a3b8ae5a67f6a048b"
            "c9ef915bda25160729b508667ada84a0c27e7e26cf2abca413e5e4693f4a9405",
            "95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad75"
            "6fbd918c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632a"
            "d30b3dc3ce0ba97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af59"
            "0824ca98d74fbca934d0b6867aa1991f3040b707e806de6e66b5934f05509bea",
            true
        },
        {
            "RSA-2048/SHA-256 Result = F",
            "c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026b"
            "cb2399bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae85208"
            "7d25f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d"
            "11542a705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671"
            "de874bb9cecb058c6c8344aa8c93754d6effcd44a41ed7de0a9dcd9144437f21"
            "2b18881d042d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189"
            "ff968b92f33c266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce9"
            "8f54ed237b4a04a4159a5f6250a296a902880204e61d891c4da29f2d65f34cbb",
            "49d2a1",
            "ba48538708512d45c0edcac57a9b4fb637e9721f72003c60f13f5c9a36c968ce"
            "f9be8f54665418141c3d9ecc02a5bf952cfc055fb51e18705e9d8850f4e1f5a3"
            "44af550de84ffd0805e27e557f6aa50d2645314c64c1c71aa6bb44faf8f29ca6"
            "578e2441d4510e36052f46551df341b2dcf43f761f08b946ca0b7081dadbb88e"
            "955e820fd7f657c4dd9f4554d167dd7c9a487ed41ced2b40068098deedc95106"
            "0faf7e15b1f0f80ae67ff2ee28a238d80bf72dd71c8d95c79bc156114ece8ec8"
            "37573a4b66898d45b45a5eacd0b0e41447d8fa08a367f437645e50c9920b88a1"
            "6bc0880147acfb9a79de9e351b3fa00b3f4e9f182f45553dffca55e393c5eab6",
            "f89fd2f6c45a8b5066a651410b8e534bfec0d9a36f3e2b887457afd44dd651d1"
            "ec79274db5a455f182572fceea5e9e39c3c7c5d9e599e4fe31c37c34d253b419"
            "c3e8fb6b916aef6563f87d4c37224a456e5952698ba3d01b38945d998a795bd2"
            "85d69478e3131f55117284e27b441f16095dca7ce9c5b68890b09a2bfbb010a5",
            false
        },
    };

    /* Builds PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }. */
    std::vector<uint8_t> rsaPublicKeyDer(const char* nHex, const char* eHex) {
        std::vector<uint8_t> inner;
        appendDerInteger(inner, fromHex(nHex));
        appendDerInteger(inner, fromHex(eHex));
        return derSequence(inner);
    }
}

TEST_CASE("RSA: CAVP 186-3 PKCS#1 v1.5 SigVer known-answer vectors verify as published") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    REQUIRE(rsa);

    for (const RsaSigVerVector& v : VECTORS) {
        INFO("vector: " << v.label);

        std::vector<uint8_t> der = rsaPublicKeyDer(v.n, v.e);
        IPublicKeyPtr pub = rsa->createPublicKey(SReadOnlyByteSpan(der.data(), der.size()));
        REQUIRE(pub);

        IAsymmetricContextPtr ctx = rsa->createContext();
        REQUIRE(ctx);
        ctx->keyPair(pub, nullptr);

        std::vector<uint8_t> digest = digestOf(EHASH_SHA256, fromHex(v.msg));
        std::vector<uint8_t> sig = fromHex(v.sig);
        REQUIRE(sig.size() == ctx->sizeOfSign());

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
