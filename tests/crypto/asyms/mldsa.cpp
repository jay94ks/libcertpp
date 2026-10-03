// CMlDsa as an IAsymmetric: key objects, contexts, serialization and the two conventions that
// are easy to get wrong at this layer rather than in the algorithm.
//
// The algorithm itself is pinned by kat_mldsa.cpp/kat_mldsaver.cpp against NIST's ACVP vectors,
// and the IdenTrust root in tests/x509/realcerts.cpp verifies a third party's real signature end
// to end. What is left for this file is the wiring, where a mistake looks nothing like a
// cryptographic error:
//
//  - **sign()/verify() take the message, not a digest.** Hashing first and passing the digest
//    produces a perfectly valid ML-DSA signature over a 32-byte string that no other
//    implementation would produce or check. sizeOfDigest() reporting 0 is the signal, and it is
//    asserted here.
//  - **Signing is hedged**, so two signatures over one message differ. A test that compares two
//    signatures for equality would fail, and a library that made them equal would have dropped
//    the per-signature randomness.
//  - **A private key does not carry its public key**, so publicKey() re-derives it. That
//    derivation has to agree with the one keygen produced, and has to reject a key whose stored
//    tr contradicts it.
//  - **The three parameter sets are not interchangeable**, and because the X.509 OIDs for them
//    are consecutive (.17/.18/.19) a mix-up is a realistic failure rather than a hypothetical.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    struct ParamSet {
        EAsymmetrics which;
        const char* name;
        SKeySize keySize;
        size_t publicKeyBytes;
        size_t privateKeyBytes;
        size_t signatureBytes;
    };

    // FIPS 204 Table 2's figures, written out here rather than derived, so this file disagrees
    // with the implementation if either drifts.
    const ParamSet PARAM_SETS[] = {
        { EASYM_MLDSA44, "ML-DSA-44", 44, 1312, 2560, 2420 },
        { EASYM_MLDSA65, "ML-DSA-65", 65, 1952, 4032, 3309 },
        { EASYM_MLDSA87, "ML-DSA-87", 87, 2592, 4896, 4627 },
    };

    std::vector<uint8_t> message(const char* text) {
        std::vector<uint8_t> out;
        for (const char* p = text; *p; ++p) {
            out.push_back(uint8_t(*p));
        }
        return out;
    }

    SReadOnlyByteSpan toSpan(const std::vector<uint8_t>& bytes) {
        return bytes.empty()
            ? SReadOnlyByteSpan(nullptr, 0)
            : SReadOnlyByteSpan(bytes.data(), bytes.size());
    }
}

TEST_CASE("CMlDsa: IAsymmetric::builtIn() serves all three parameter sets") {
    for (const ParamSet& set : PARAM_SETS) {
        SUBCASE(set.name) {
            IAsymmetricPtr algo = IAsymmetric::builtIn(set.which);
            REQUIRE(algo);

            REQUIRE(algo->keySizes().size() == 1);
            CHECK(algo->keySizes()[0].includes(set.keySize));

            // The key size is the parameter set's name, not a bit length -- so neither a
            // plausible-looking bit count nor another set's name is accepted.
            CHECK_FALSE(algo->keySizes()[0].includes(256));
            CHECK_FALSE(algo->keySizes()[0].includes(set.keySize + 1));

            CHECK(CMlDsa::isMlDsa(set.which));
        }
    }

    CHECK_FALSE(CMlDsa::isMlDsa(EASYM_ED25519));
    CHECK_FALSE(CMlDsa::isMlDsa(EASYM_P256));
    CHECK_FALSE(CMlDsa::isMlDsa(EASYM_UNKNOWN));

    // An EAsymmetrics that names no ML-DSA set yields an instance that refuses everything,
    // rather than one that silently runs ML-DSA-44.
    CMlDsa bogus(EASYM_RSA);
    CHECK(bogus.which() == EASYM_UNKNOWN);
    CHECK(bogus.keySizes().size() == 0);

    SKeyPair unused;
    CHECK(bogus.generateKeyPair(44, unused) == ERET_NOTSUP);
    CHECK_FALSE(bogus.createPublicKey(SReadOnlyByteSpan(nullptr, 0)));
}

TEST_CASE("CMlDsa: generate, sign and verify through the IAsymmetric interface") {
    for (const ParamSet& set : PARAM_SETS) {
        SUBCASE(set.name) {
            IAsymmetricPtr algo = IAsymmetric::builtIn(set.which);
            REQUIRE(algo);

            SKeyPair pair;
            REQUIRE(algo->generateKeyPair(set.keySize, pair) == ERET_OK);
            REQUIRE(pair);

            CHECK(pair.publicKey->algorithm() == set.which);
            CHECK(pair.privateKey->algorithm() == set.which);
            CHECK(pair.publicKey->keySize() == set.keySize);
            CHECK(algo->checkPrivateKey(pair.privateKey) == ERET_OK);

            // A generated key pair serializes to FIPS 204's own encodings and nothing else.
            COctet publicBytes;
            COctet privateBytes;
            REQUIRE(pair.publicKey->serialize(publicBytes) == ERET_OK);
            REQUIRE(pair.privateKey->serialize(privateBytes) == ERET_OK);
            CHECK(publicBytes.size() == set.publicKeyBytes);
            CHECK(privateBytes.size() == set.privateKeyBytes);

            IAsymmetricContextPtr ctx = algo->createContext();
            REQUIRE(ctx);
            ctx->keyPair(pair);

            CHECK(ctx->sizeOfSign() == set.signatureBytes);
            CHECK(ctx->sizeOfDigest() == 0);  // --> no external digest; pass the message.

            std::vector<uint8_t> data = message("a message, not a digest");

            CBuffer signature;
            REQUIRE(signature.resize(ctx->sizeOfSign()));
            SByteSpan out(signature.toPtr(), signature.size());

            REQUIRE(ctx->sign(toSpan(data), out) == ERET_OK);
            CHECK(out.size == set.signatureBytes);

            CHECK(ctx->verify(toSpan(data), SReadOnlyByteSpan(out.data, out.size)) == ERET_OK);

            // A verifier holding only the public half -- the normal case for someone else's
            // signature -- works the same way.
            IAsymmetricContextPtr verifyOnly = algo->createContext();
            REQUIRE(verifyOnly);
            verifyOnly->keyPair(pair.publicKey, nullptr);
            CHECK(verifyOnly->sizeOfSign() == set.signatureBytes);
            CHECK(verifyOnly->verify(
                toSpan(data), SReadOnlyByteSpan(out.data, out.size)) == ERET_OK);
            CHECK(verifyOnly->sign(toSpan(data), out) == ERET_KEY_EMPTY);

            // Neither encryption nor key agreement exists for a signature scheme.
            IAsymmetricTransformerPtr transformer;
            CHECK(ctx->createEncrypter(transformer) == ERET_NOTSUP);
            CHECK(ctx->createDecrypter(transformer) == ERET_NOTSUP);

            CBuffer secret;
            REQUIRE(secret.resize(32));
            SByteSpan secretOut(secret.toPtr(), secret.size());
            CHECK(ctx->deriveSharedSecret(pair.publicKey, secretOut) == ERET_NOTSUP);
        }
    }
}

TEST_CASE("CMlDsa: a tampered message or signature is refused") {
    IAsymmetricPtr algo = IAsymmetric::builtIn(EASYM_MLDSA44);
    REQUIRE(algo);

    SKeyPair pair;
    REQUIRE(algo->generateKeyPair(44, pair) == ERET_OK);

    IAsymmetricContextPtr ctx = algo->createContext();
    REQUIRE(ctx);
    ctx->keyPair(pair);

    std::vector<uint8_t> data = message("the quick brown fox");

    CBuffer signature;
    REQUIRE(signature.resize(ctx->sizeOfSign()));
    SByteSpan out(signature.toPtr(), signature.size());
    REQUIRE(ctx->sign(toSpan(data), out) == ERET_OK);

    std::vector<uint8_t> original(out.data, out.data + out.size);

    for (size_t index : { size_t(0), out.size / 2, out.size - 1 }) {
        std::vector<uint8_t> broken = original;
        broken[index] = uint8_t(broken[index] ^ 0x01u);
        CHECK(ctx->verify(toSpan(data), toSpan(broken)) != ERET_OK);
    }

    for (size_t index : { size_t(0), data.size() - 1 }) {
        std::vector<uint8_t> broken = data;
        broken[index] = uint8_t(broken[index] ^ 0x01u);
        CHECK(ctx->verify(toSpan(broken), toSpan(original)) != ERET_OK);
    }

    // A truncated or extended signature is a structural refusal, not a comparison failure.
    std::vector<uint8_t> truncated(original.begin(), original.end() - 1);
    std::vector<uint8_t> extended = original;
    extended.push_back(0);
    CHECK(ctx->verify(toSpan(data), toSpan(truncated)) == ERET_BADREQ);
    CHECK(ctx->verify(toSpan(data), toSpan(extended)) == ERET_BADREQ);

    // The empty message is a legal message, and its signature is not interchangeable with any
    // other -- the length prefix in the external interface's M' is what makes that true.
    CBuffer emptySignature;
    REQUIRE(emptySignature.resize(ctx->sizeOfSign()));
    SByteSpan emptyOut(emptySignature.toPtr(), emptySignature.size());
    REQUIRE(ctx->sign(SReadOnlyByteSpan(nullptr, 0), emptyOut) == ERET_OK);
    CHECK(ctx->verify(
        SReadOnlyByteSpan(nullptr, 0),
        SReadOnlyByteSpan(emptyOut.data, emptyOut.size)) == ERET_OK);
    CHECK(ctx->verify(
        toSpan(data), SReadOnlyByteSpan(emptyOut.data, emptyOut.size)) != ERET_OK);
}

TEST_CASE("CMlDsa: signing is hedged, so two signatures over one message differ") {
    // --> Both must verify. If they were equal, the per-signature rnd would have been dropped;
    // if only one verified, the randomness would be leaking into something it should not.
    IAsymmetricPtr algo = IAsymmetric::builtIn(EASYM_MLDSA44);
    REQUIRE(algo);

    SKeyPair pair;
    REQUIRE(algo->generateKeyPair(44, pair) == ERET_OK);

    IAsymmetricContextPtr ctx = algo->createContext();
    REQUIRE(ctx);
    ctx->keyPair(pair);

    std::vector<uint8_t> data = message("hedged");

    CBuffer first;
    CBuffer second;
    REQUIRE(first.resize(ctx->sizeOfSign()));
    REQUIRE(second.resize(ctx->sizeOfSign()));

    SByteSpan firstOut(first.toPtr(), first.size());
    SByteSpan secondOut(second.toPtr(), second.size());
    REQUIRE(ctx->sign(toSpan(data), firstOut) == ERET_OK);
    REQUIRE(ctx->sign(toSpan(data), secondOut) == ERET_OK);

    REQUIRE(firstOut.size == secondOut.size);
    CHECK(std::memcmp(firstOut.data, secondOut.data, firstOut.size) != 0);

    CHECK(ctx->verify(toSpan(data), SReadOnlyByteSpan(firstOut.data, firstOut.size)) == ERET_OK);
    CHECK(ctx->verify(toSpan(data), SReadOnlyByteSpan(secondOut.data, secondOut.size)) == ERET_OK);
}

TEST_CASE("CMlDsa: a key survives a serialize/import round trip") {
    for (const ParamSet& set : PARAM_SETS) {
        SUBCASE(set.name) {
            IAsymmetricPtr algo = IAsymmetric::builtIn(set.which);
            REQUIRE(algo);

            SKeyPair pair;
            REQUIRE(algo->generateKeyPair(set.keySize, pair) == ERET_OK);

            COctet publicBytes;
            COctet privateBytes;
            REQUIRE(pair.publicKey->serialize(publicBytes) == ERET_OK);
            REQUIRE(pair.privateKey->serialize(privateBytes) == ERET_OK);

            IPublicKeyPtr importedPublic = algo->createPublicKey(publicBytes);
            REQUIRE(importedPublic);
            CHECK(importedPublic->compare(pair.publicKey) == 0);
            CHECK(importedPublic->algorithm() == set.which);

            IPrivateKeyPtr importedPrivate = algo->createPrivateKey(privateBytes);
            REQUIRE(importedPrivate);
            CHECK(importedPrivate->compare(pair.privateKey) == 0);
            CHECK(algo->checkPrivateKey(importedPrivate) == ERET_OK);

            // --> The re-derivation, not a stored copy: an ML-DSA private key holds
            // tr = H(pk) but never pk itself, so publicKey() recomputes t from rho/s1/s2. It has
            // to land on exactly the key keygen published.
            IPublicKeyPtr rederived = importedPrivate->publicKey();
            REQUIRE(rederived);
            CHECK(rederived->compare(pair.publicKey) == 0);

            // A signature made with the re-imported private key verifies under the original
            // public key, which is the only end-to-end evidence that the import kept s1 and s2
            // rather than merely something of the right length.
            IAsymmetricContextPtr signCtx = algo->createContext();
            REQUIRE(signCtx);
            signCtx->keyPair(rederived, importedPrivate);

            std::vector<uint8_t> data = message("round trip");
            CBuffer signature;
            REQUIRE(signature.resize(signCtx->sizeOfSign()));
            SByteSpan out(signature.toPtr(), signature.size());
            REQUIRE(signCtx->sign(toSpan(data), out) == ERET_OK);

            IAsymmetricContextPtr verifyCtx = algo->createContext();
            REQUIRE(verifyCtx);
            verifyCtx->keyPair(pair.publicKey, nullptr);
            CHECK(verifyCtx->verify(
                toSpan(data), SReadOnlyByteSpan(out.data, out.size)) == ERET_OK);
        }
    }
}

TEST_CASE("CMlDsa: a malformed or foreign key is refused on import") {
    IAsymmetricPtr mlDsa65 = IAsymmetric::builtIn(EASYM_MLDSA65);
    IAsymmetricPtr mlDsa87 = IAsymmetric::builtIn(EASYM_MLDSA87);
    REQUIRE(mlDsa65);
    REQUIRE(mlDsa87);

    SKeyPair pair;
    REQUIRE(mlDsa65->generateKeyPair(65, pair) == ERET_OK);

    COctet publicBytes;
    COctet privateBytes;
    REQUIRE(pair.publicKey->serialize(publicBytes) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privateBytes) == ERET_OK);

    // --> The consecutive-OID case: an ML-DSA-65 key offered to ML-DSA-87. Every parameter set
    // has a different key length, so this is refused on length alone rather than producing a
    // key that would later fail to verify anything.
    CHECK_FALSE(mlDsa87->createPublicKey(publicBytes));
    CHECK_FALSE(mlDsa87->createPrivateKey(privateBytes));

    // Truncated, extended and empty.
    std::vector<uint8_t> truncated(publicBytes.toPtr(), publicBytes.toPtr() + publicBytes.size() - 1);
    std::vector<uint8_t> extended(publicBytes.toPtr(), publicBytes.toPtr() + publicBytes.size());
    extended.push_back(0);
    CHECK_FALSE(mlDsa65->createPublicKey(toSpan(truncated)));
    CHECK_FALSE(mlDsa65->createPublicKey(toSpan(extended)));
    CHECK_FALSE(mlDsa65->createPublicKey(SReadOnlyByteSpan(nullptr, 0)));

    // --> skDecode's range check, reached through the public API. s1 begins at offset 128
    // (rho || K || tr); at eta = 4 its field is four bits wide and 2*eta + 1 == 9 is not a power
    // of two, so the pattern 1111 decodes to 4 - 15 == -11, far outside [-4, 4]. FIPS 204
    // Algorithm 25 requires rejecting such a key, and createPrivateKey() must not hand back
    // something that would sign with it.
    std::vector<uint8_t> badPrivate(privateBytes.toPtr(), privateBytes.toPtr() + privateBytes.size());
    badPrivate[128] = uint8_t(badPrivate[128] | 0x0Fu);
    CHECK_FALSE(mlDsa65->createPrivateKey(toSpan(badPrivate)));

    // A key whose body is otherwise legal but whose tr contradicts the rest is inconsistent, and
    // is refused too -- tr is H(pk), so it cannot be chosen independently of s1/s2/rho.
    std::vector<uint8_t> badTr(privateBytes.toPtr(), privateBytes.toPtr() + privateBytes.size());
    badTr[64] = uint8_t(badTr[64] ^ 0x01u);     // tr occupies [64, 128)
    CHECK_FALSE(mlDsa65->createPrivateKey(toSpan(badTr)));

    // --> t0 is the one part of a private key no decode check can reach: its field is exactly
    // 13 bits wide for a 13-bit range, so every byte string decodes to a legal t0, and tr is
    // H(pk) -- which t0 does not enter. A wrong t0 would otherwise sail through import and
    // produce hints no verifier accepts, with nothing saying why. The remaining check is to
    // re-derive it: Power2Round's low part is the t0 this key should carry.
    // t0 starts after rho || K || tr and the s1/s2 blocks: 128 + (l + k) * 32 * etaBitWidth().
    const size_t t0Offset = 128 + (5 + 6) * 32 * 4;     // ML-DSA-65: l = 5, k = 6, eta = 4
    REQUIRE(t0Offset < privateBytes.size());

    std::vector<uint8_t> badT0(privateBytes.toPtr(), privateBytes.toPtr() + privateBytes.size());
    badT0[t0Offset] = uint8_t(badT0[t0Offset] ^ 0x01u);
    CHECK_FALSE(mlDsa65->createPrivateKey(toSpan(badT0)));

    // It is specifically the re-derivation that catches it, not a length or range check: the
    // tampered key still decodes cleanly.
    CHECK(mlDsa65->createPublicKey(publicBytes));

    // A key pair from another algorithm entirely is a wrong concrete type, not a bad parameter.
    IAsymmetricPtr ed = IAsymmetric::builtIn(EASYM_ED25519);
    REQUIRE(ed);
    SKeyPair edPair;
    REQUIRE(ed->generateKeyPair(256, edPair) == ERET_OK);
    CHECK(mlDsa65->checkPrivateKey(edPair.privateKey) == ERET_KEY_FORMAT);
}

TEST_CASE("CMlDsa: a signature does not transfer between parameter sets or keys") {
    IAsymmetricPtr algo = IAsymmetric::builtIn(EASYM_MLDSA44);
    REQUIRE(algo);

    SKeyPair first;
    SKeyPair second;
    REQUIRE(algo->generateKeyPair(44, first) == ERET_OK);
    REQUIRE(algo->generateKeyPair(44, second) == ERET_OK);
    CHECK(first.publicKey->compare(second.publicKey) != 0);

    IAsymmetricContextPtr signCtx = algo->createContext();
    REQUIRE(signCtx);
    signCtx->keyPair(first);

    std::vector<uint8_t> data = message("bound to one key");
    CBuffer signature;
    REQUIRE(signature.resize(signCtx->sizeOfSign()));
    SByteSpan out(signature.toPtr(), signature.size());
    REQUIRE(signCtx->sign(toSpan(data), out) == ERET_OK);

    IAsymmetricContextPtr otherCtx = algo->createContext();
    REQUIRE(otherCtx);
    otherCtx->keyPair(second.publicKey, nullptr);
    CHECK(otherCtx->verify(toSpan(data), SReadOnlyByteSpan(out.data, out.size)) != ERET_OK);

    // The same bytes offered to a different parameter set: the length alone rules it out.
    IAsymmetricPtr bigger = IAsymmetric::builtIn(EASYM_MLDSA87);
    REQUIRE(bigger);
    SKeyPair biggerPair;
    REQUIRE(bigger->generateKeyPair(87, biggerPair) == ERET_OK);

    IAsymmetricContextPtr biggerCtx = bigger->createContext();
    REQUIRE(biggerCtx);
    biggerCtx->keyPair(biggerPair.publicKey, nullptr);
    CHECK(biggerCtx->verify(
        toSpan(data), SReadOnlyByteSpan(out.data, out.size)) == ERET_BADREQ);
}

TEST_CASE("CMlDsa: a key-less context, a wrong key size and a short output buffer all fail cleanly") {
    IAsymmetricPtr algo = IAsymmetric::builtIn(EASYM_MLDSA65);
    REQUIRE(algo);

    SKeyPair pair;
    CHECK(algo->generateKeyPair(44, pair) == ERET_KEY_SIZE);    // --> another set's own number
    CHECK(algo->generateKeyPair(1952, pair) == ERET_KEY_SIZE);  // --> a key *length*, not a name
    CHECK_FALSE(pair);

    REQUIRE(algo->generateKeyPair(65, pair) == ERET_OK);

    IAsymmetricContextPtr ctx = algo->createContext();
    REQUIRE(ctx);

    std::vector<uint8_t> data = message("x");
    CBuffer scratch;
    REQUIRE(scratch.resize(4096));
    SByteSpan out(scratch.toPtr(), scratch.size());

    CHECK(ctx->sign(toSpan(data), out) == ERET_KEY_EMPTY);
    CHECK(ctx->verify(toSpan(data), SReadOnlyByteSpan(out.data, 3309)) == ERET_KEY_EMPTY);

    ctx->keyPair(pair);
    CHECK(ctx->sizeOfSign() == 3309);

    SByteSpan tooSmall(scratch.toPtr(), 3308);
    CHECK(ctx->sign(toSpan(data), tooSmall) == ERET_NOSPC);

    // reset() drops the key material and the sizes derived from it.
    ctx->reset();
    CHECK(ctx->sizeOfSign() == 0);
    CHECK(ctx->sign(toSpan(data), out) == ERET_KEY_EMPTY);
}
