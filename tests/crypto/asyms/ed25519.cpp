#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    constexpr SKeySize TEST_KEY_SIZE = 256;

    const SKeyPair& sharedTestKeyPair() {
        static SKeyPair pair = [] {
            IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
            SKeyPair result;
            ed->generateKeyPair(TEST_KEY_SIZE, result);
            return result;
        }();

        return pair;
    }

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
}

// RFC 8032 Section 7.1, TEST 1: an empty message. EdDSA signing is fully deterministic (no
// per-signature randomness, unlike DSA/ECDSA), so reproducing this exact signature validates
// the whole pipeline at once -- field arithmetic, the derived curve/group constants, key
// clamping, and the signing algorithm itself -- far more strongly than a self-consistency
// round-trip alone could.
TEST_CASE("Ed25519: RFC 8032 TEST 1 vector (empty message)") {
    auto secretKey = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    auto publicKey = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    auto signature = hexToBytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    REQUIRE(secretKey.size() == 32);
    REQUIRE(publicKey.size() == 32);
    REQUIRE(signature.size() == 64);

    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    REQUIRE(ed);

    IPrivateKeyPtr priv = ed->createPrivateKey(SReadOnlyByteSpan(secretKey.data(), secretKey.size()));
    REQUIRE(priv);

    COctet derivedPub;
    REQUIRE(priv->publicKey()->serialize(derivedPub) == ERET_OK);
    REQUIRE(derivedPub.size() == 32);
    CHECK(derivedPub.toSpan().sequencialEqual(SReadOnlyByteSpan(publicKey.data(), publicKey.size())));

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(priv->publicKey(), priv);

    TArray<uint8_t> producedSignature;
    producedSignature.resize(ctx->sizeOfSign());
    SByteSpan producedSignatureSpan(producedSignature.begin(), producedSignature.size());
    REQUIRE(ctx->sign(SReadOnlyByteSpan(nullptr, 0), producedSignatureSpan) == ERET_OK);
    producedSignature.resize(producedSignatureSpan.size);
    REQUIRE(producedSignature.size() == 64);

    for (size_t i = 0; i < 64; ++i) {
        CHECK(producedSignature[i] == signature[i]);
    }

    CHECK(ctx->verify(SReadOnlyByteSpan(nullptr, 0),
        SReadOnlyByteSpan(signature.data(), signature.size())) == ERET_OK);
}

TEST_CASE("Ed25519: builtIn(EASYM_ED25519) returns a usable algorithm instance") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    REQUIRE(ed);

    bool acceptsTestSize = false;
    for (size_t i = 0; i < ed->keySizes().size(); ++i) {
        if (ed->keySizes()[i].includes(TEST_KEY_SIZE)) {
            acceptsTestSize = true;
        }
    }
    CHECK(acceptsTestSize);
}

TEST_CASE("Ed25519: generateKeyPair produces a matched, usable key pair") {
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);
    REQUIRE(pair.publicKey->keySize() == TEST_KEY_SIZE);
    REQUIRE(pair.privateKey->keySize() == TEST_KEY_SIZE);
    CHECK(pair.privateKey->publicKey()->compare(pair.publicKey) == 0);
}

TEST_CASE("Ed25519: generateKeyPair rejects a key size other than 256") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    SKeyPair pair;
    ed->generateKeyPair(384, pair);
    CHECK(pair.empty());
}

TEST_CASE("Ed25519: public/private key round-trips through serialize()/create*Key()") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    COctet pubBytes, privBytes;
    REQUIRE(pair.publicKey->serialize(pubBytes) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privBytes) == ERET_OK);

    CHECK(pubBytes.size() == 32);
    CHECK(privBytes.size() == 32);

    IPublicKeyPtr parsedPub = ed->createPublicKey(pubBytes);
    IPrivateKeyPtr parsedPriv = ed->createPrivateKey(privBytes);

    REQUIRE(parsedPub);
    REQUIRE(parsedPriv);
    CHECK(parsedPub->compare(pair.publicKey) == 0);
    CHECK(parsedPriv->compare(pair.privateKey) == 0);
}

TEST_CASE("Ed25519: createPublicKey rejects a point not on the curve") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);

    // y = 2 has no valid x on edwards25519 for either sign bit (verified offline: (y^2-1)/(d*y^2+1)
    // is not a quadratic residue mod p) -- deterministically invalid, unlike flipping a random bit
    // of a real encoded point, which has roughly even odds of still landing on a valid point
    // (about half of field elements are quadratic residues).
    uint8_t invalid[32] = { 2 };

    IPublicKeyPtr parsed = ed->createPublicKey(SReadOnlyByteSpan(invalid, sizeof(invalid)));
    CHECK_FALSE(parsed);
}

TEST_CASE("Ed25519: sign/verify round-trips for a non-empty message") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    const uint8_t message[] = "certpp Ed25519 test message";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(ctx->sign(messageSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);
    REQUIRE(signature.size() == 64);
    CHECK(ctx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

    // Tampering with the message must invalidate the signature.
    uint8_t tamperedMessage[sizeof(message) - 1];
    for (size_t i = 0; i < sizeof(tamperedMessage); ++i) {
        tamperedMessage[i] = message[i];
    }
    tamperedMessage[0] ^= 0xFF;

    CHECK(ctx->verify(SReadOnlyByteSpan(tamperedMessage, sizeof(tamperedMessage)),
        SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("Ed25519: signing is deterministic (same seed and message produce the same signature)") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    const uint8_t message[] = "deterministic";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> sig1, sig2;
    sig1.resize(ctx->sizeOfSign());
    sig2.resize(ctx->sizeOfSign());
    SByteSpan sig1Span(sig1.begin(), sig1.size());
    SByteSpan sig2Span(sig2.begin(), sig2.size());
    REQUIRE(ctx->sign(messageSpan, sig1Span) == ERET_OK);
    REQUIRE(ctx->sign(messageSpan, sig2Span) == ERET_OK);
    sig1.resize(sig1Span.size);
    sig2.resize(sig2Span.size);

    REQUIRE(sig1.size() == sig2.size());
    for (size_t i = 0; i < sig1.size(); ++i) {
        CHECK(sig1[i] == sig2[i]);
    }
}

TEST_CASE("Ed25519: verify rejects a tampered signature") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    const uint8_t message[] = "tamper test";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(ctx->sign(messageSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);
    REQUIRE(ctx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

    signature[signature.size() - 1] ^= 0xFF;
    CHECK(ctx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("Ed25519: createPublicKey rejects the identity point (universal-forgery guard)") {
    // The identity point encodes as y=1, x=0 (little-endian: 0x01 followed by 31 zero bytes).
    // If accepted as a public key, the all-zero signature (R == identity, S == 0) would verify
    // against *any* message under it, since scalarMul(0)*B == identity and
    // pointAdd(identity, scalarMul(identity, k)) == identity for every k -- a universal
    // signature forgery in the same spirit as CVE-2022-21449's missing ECDSA r/s == 0 checks.
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);

    uint8_t identityEncoded[32] = { 0 };
    identityEncoded[0] = 0x01;

    IPublicKeyPtr identityKey = ed->createPublicKey(SReadOnlyByteSpan(identityEncoded, sizeof(identityEncoded)));
    CHECK_FALSE(identityKey);
}

TEST_CASE("Ed25519: verify rejects a signature whose R is the identity point, even against a real key") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair.publicKey, nullptr);

    uint8_t forgedSignature[64] = { 0 };
    forgedSignature[0] = 0x01; // R == identity point; S == 0 (the rest stays zero)

    const uint8_t anyMessage[] = "this message was never signed";
    CHECK(ctx->verify(
        SReadOnlyByteSpan(anyMessage, sizeof(anyMessage) - 1),
        SReadOnlyByteSpan(forgedSignature, sizeof(forgedSignature))
    ) != ERET_OK);
}

TEST_CASE("Ed25519: verify rejects a signature produced by a different key pair") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    SKeyPair otherPair;

    ed->generateKeyPair(TEST_KEY_SIZE, otherPair);
    REQUIRE(otherPair);

    IAsymmetricContextPtr signCtx = ed->createContext();
    signCtx->keyPair(otherPair);

    const uint8_t message[] = "different key";
    SReadOnlyByteSpan messageSpan(message, sizeof(message) - 1);

    TArray<uint8_t> signature;
    signature.resize(signCtx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(signCtx->sign(messageSpan, sigSpan) == ERET_OK);
    signature.resize(sigSpan.size);

    IAsymmetricContextPtr verifyCtx = ed->createContext();
    verifyCtx->keyPair(pair);
    CHECK(verifyCtx->verify(messageSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
}

TEST_CASE("Ed25519: createEncrypter()/createDecrypter() are unsupported") {
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    const SKeyPair& pair = sharedTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = ed->createContext();
    ctx->keyPair(pair);

    IAsymmetricTransformerPtr transformer;
    CHECK(ctx->createEncrypter(transformer) == ERET_NOTSUP);
    CHECK(ctx->createDecrypter(transformer) == ERET_NOTSUP);
}

// RFC 8032 Section 7.1's remaining Ed25519 vectors: TEST 2 and TEST 3 (a one- and a two-byte
// message), TEST SHA(abc) (64 bytes), and TEST 1024 (1023 bytes, the only one long enough to
// cross SHA-512 block boundaries repeatedly). TEST 1 above already covers the empty message.
//
// Added when the field arithmetic moved from CBigNum onto Fe25519. Ed25519 is byte-exact -- one
// key and one message produce one signature and no other -- so these are the strongest available
// statement that the new field agrees with the world rather than merely with itself: a field that
// was wrong in any way at all would produce different bytes here. One vector would arguably do,
// but the differing message lengths also exercise the SHA-512 prefix hashing around the curve
// arithmetic, and they cost milliseconds now that they are not paying for a big-number division
// per field multiplication.
namespace {
    void checkRfc8032Vector(const char* secretHex, const char* publicHex,
        const char* messageHex, const char* signatureHex) {
        const std::vector<uint8_t> secretKey = hexToBytes(secretHex);
        const std::vector<uint8_t> publicKey = hexToBytes(publicHex);
        const std::vector<uint8_t> message = hexToBytes(messageHex);
        const std::vector<uint8_t> signature = hexToBytes(signatureHex);

        REQUIRE(secretKey.size() == 32);
        REQUIRE(publicKey.size() == 32);
        REQUIRE(signature.size() == 64);

        IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
        REQUIRE(ed);

        IPrivateKeyPtr priv = ed->createPrivateKey(SReadOnlyByteSpan(secretKey.data(), secretKey.size()));
        REQUIRE(priv);

        // The public key the seed derives has to be the one the RFC lists -- scalarMulBase() and
        // the compressed encoding, independently of signing.
        COctet derivedPub;
        REQUIRE(priv->publicKey()->serialize(derivedPub) == ERET_OK);
        REQUIRE(derivedPub.size() == 32);
        REQUIRE(derivedPub.toSpan().sequencialEqual(SReadOnlyByteSpan(publicKey.data(), publicKey.size())));

        // And the same bytes have to decode back into a usable point, which is the path an
        // imported peer key takes (decodePoint's canonical-y and subgroup checks).
        IPublicKeyPtr imported = ed->createPublicKey(SReadOnlyByteSpan(publicKey.data(), publicKey.size()));
        REQUIRE(imported);

        const SReadOnlyByteSpan messageSpan(message.empty() ? nullptr : message.data(), message.size());

        IAsymmetricContextPtr ctx = ed->createContext();
        ctx->keyPair(priv->publicKey(), priv);

        TArray<uint8_t> produced;
        produced.resize(ctx->sizeOfSign());
        SByteSpan producedSpan(produced.begin(), produced.size());
        REQUIRE(ctx->sign(messageSpan, producedSpan) == ERET_OK);
        REQUIRE(producedSpan.size == 64);

        for (size_t i = 0; i < 64; ++i) {
            REQUIRE(produced[i] == signature[i]);
        }

        REQUIRE(ctx->verify(messageSpan,
            SReadOnlyByteSpan(signature.data(), signature.size())) == ERET_OK);

        // Verification through the separately imported public key, not the one the private key
        // carries -- so a broken decodePoint cannot hide behind a working scalarMulBase.
        IAsymmetricContextPtr importedCtx = ed->createContext();
        importedCtx->keyPair(imported, nullptr);
        REQUIRE(importedCtx->verify(messageSpan,
            SReadOnlyByteSpan(signature.data(), signature.size())) == ERET_OK);
    }
}

TEST_CASE("Ed25519: RFC 8032 TEST 2 vector (one-byte message)") {
    checkRfc8032Vector(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
}

TEST_CASE("Ed25519: RFC 8032 TEST 3 vector (two-byte message)") {
    checkRfc8032Vector(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
}

TEST_CASE("Ed25519: RFC 8032 TEST SHA(abc) vector (64-byte message)") {
    checkRfc8032Vector(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");
}

// The long one: 1023 bytes, which is the vector most likely to catch something the short ones
// cannot -- anything in the SHA-512 prefix hashing that happens to work only while the message
// fits in a block or two.
TEST_CASE("Ed25519: RFC 8032 TEST 1024 vector (1023-byte message)") {
    checkRfc8032Vector(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
        "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");
}
