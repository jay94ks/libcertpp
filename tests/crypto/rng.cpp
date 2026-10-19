#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

#include <cstring>
#include <memory>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    class SequenceRng final : public IRng {
    private:
        mutable uint8_t _next;
        mutable size_t _nonZeroCalls;

    public:
        explicit SequenceRng(uint8_t first = 1) : _next(first), _nonZeroCalls(0) { }

        ERetCode clone(std::shared_ptr<IRng>& out) const override {
            out = std::make_shared<SequenceRng>(_next);
            return ERET_OK;
        }

        ERetCode fillTo(const SByteSpan& out) const override {
            for (size_t i = 0; i < out.size; ++i) {
                out.data[i] = _next++;
            }
            return ERET_OK;
        }

        ERetCode fillNonZeroTo(const SByteSpan& out) const override {
            ++_nonZeroCalls;
            std::memset(out.data, 0xA5, out.size);
            return ERET_OK;
        }

        size_t nonZeroCalls() const { return _nonZeroCalls; }
    };

    class UncloneableRng final : public IRng {
    public:
        ERetCode clone(std::shared_ptr<IRng>& out) const override {
            out.reset();
            return ERET_NOTSUP;
        }

        ERetCode fillTo(const SByteSpan&) const override {
            return ERET_NOTSUP;
        }
    };
}

TEST_CASE("CRng::fill fills a buffer and is not all-zero") {
    uint8_t buf[64] = { 0 };
    CHECK(CRng::fill(SByteSpan(buf, sizeof(buf))) == ERET_OK);

    bool allZero = true;
    for (size_t i = 0; i < sizeof(buf); ++i) {
        if (buf[i] != 0) {
            allZero = false;
            break;
        }
    }

    CHECK_FALSE(allZero);
}

TEST_CASE("CRng::fill on empty span succeeds trivially") {
    CHECK(CRng::fill(SByteSpan(nullptr, 0)) == ERET_OK);
}

TEST_CASE("CRng::fillNonZero fills a buffer with no zero bytes") {
    uint8_t buf[256] = { 0 };
    CHECK(CRng::fillNonZero(SByteSpan(buf, sizeof(buf))) == ERET_OK);

    for (size_t i = 0; i < sizeof(buf); ++i) {
        CHECK(buf[i] != 0);
    }
}

TEST_CASE("CRng::fillNonZero on empty span succeeds trivially") {
    CHECK(CRng::fillNonZero(SByteSpan(nullptr, 0)) == ERET_OK);
}

TEST_CASE("IRng operations are const, cloneable and virtually dispatch nonzero filling") {
    const SequenceRng rng(7);

    std::shared_ptr<IRng> clone;
    REQUIRE(rng.clone(clone) == ERET_OK);
    REQUIRE(clone);

    uint8_t originalBytes[4] = { 0 };
    uint8_t clonedBytes[4] = { 0 };
    REQUIRE(rng.fillTo(SByteSpan(originalBytes, sizeof(originalBytes))) == ERET_OK);
    REQUIRE(clone->fillTo(SByteSpan(clonedBytes, sizeof(clonedBytes))) == ERET_OK);
    CHECK(std::memcmp(originalBytes, clonedBytes, sizeof(originalBytes)) == 0);

    uint8_t nonzero[8] = { 0 };
    REQUIRE(rng.fillNonZeroTo(SByteSpan(nonzero, sizeof(nonzero))) == ERET_OK);
    CHECK(rng.nonZeroCalls() == 1);
    for (uint8_t value : nonzero) {
        CHECK(value == 0xA5);
    }
}

TEST_CASE("symmetric key and IV generation use the supplied IRng") {
    const SequenceRng rng(1);
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);
    REQUIRE(aes);

    ISymmetricKeyPtr key;
    REQUIRE(aes->generateKey(rng, key, SKeySizeSpec(128)) == ERET_OK);
    REQUIRE(key);
    REQUIRE(key->keyData().size() == 16);
    for (size_t i = 0; i < key->keyData().size(); ++i) {
        CHECK(key->keyData().toPtr()[i] == uint8_t(i + 1));
    }

    CBuffer iv;
    REQUIRE(aes->generateIV(rng, key, iv) == ERET_OK);
    REQUIRE(iv.size() == 16);
    for (size_t i = 0; i < iv.size(); ++i) {
        CHECK(iv[i] == uint8_t(i + 17));
    }
}

TEST_CASE("asymmetric contexts clone and own their RNG at creation") {
    Ed25519 algorithm;
    const SequenceRng source(0x31);

    IAsymmetricContextPtr context;
    REQUIRE(algorithm.createContext(context, source) == ERET_OK);
    REQUIRE(context);

    const UncloneableRng uncloneable;
    CHECK(algorithm.createContext(context, uncloneable) == ERET_NOTSUP);
    CHECK_FALSE(context);

    std::shared_ptr<IRng> missing;
    CHECK(algorithm.createContext(context, missing) == ERET_BADREQ);
    CHECK_FALSE(context);

    std::shared_ptr<IRng> owned = std::make_shared<SequenceRng>(0x52);
    std::weak_ptr<IRng> lifetime = owned;
    IAsymmetricContextPtr ownedContext = algorithm.createContext(owned);
    REQUIRE(ownedContext);
    owned.reset();
    CHECK_FALSE(lifetime.expired());
    ownedContext.reset();
    CHECK(lifetime.expired());
}

TEST_CASE("key parsers report why creation failed and clear stale output") {
    Ed25519 asymmetric;
    const SequenceRng keyRng(0x23);
    SKeyPair pair;
    REQUIRE(asymmetric.generateKeyPair(keyRng, 256, pair) == ERET_OK);

    COctet publicBytes, privateBytes;
    REQUIRE(pair.publicKey->serialize(publicBytes) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privateBytes) == ERET_OK);
    IPublicKeyPtr restoredPublic;
    IPrivateKeyPtr restoredPrivate;
    REQUIRE(asymmetric.createPublicKey(restoredPublic, publicBytes) == ERET_OK);
    REQUIRE(asymmetric.createPrivateKey(restoredPrivate, privateBytes) == ERET_OK);
    REQUIRE(restoredPublic);
    REQUIRE(restoredPrivate);
    CHECK(restoredPublic->compare(pair.publicKey) == 0);
    CHECK(restoredPrivate->compare(pair.privateKey) == 0);

    uint8_t shortPrivate[31] = { 0 };
    IPrivateKeyPtr privateKey = pair.privateKey;
    CHECK(asymmetric.createPrivateKey(
        privateKey, SReadOnlyByteSpan(shortPrivate, sizeof(shortPrivate))) == ERET_KEY_SIZE);
    CHECK_FALSE(privateKey);

    AES symmetric;
    uint8_t shortSymmetric[15] = { 0 };
    ISymmetricKeyPtr symmetricKey;
    CHECK(symmetric.createKey(
        symmetricKey, SReadOnlyByteSpan(shortSymmetric, sizeof(shortSymmetric))) == ERET_KEY_SIZE);
    CHECK_FALSE(symmetricKey);

    MLKEM kem(EKEM_MLKEM512);
    uint8_t shortKem[31] = { 0 };
    IKemPublicKeyPtr kemKey;
    CHECK(kem.createPublicKey(
        kemKey, SReadOnlyByteSpan(shortKem, sizeof(shortKem))) == ERET_KEY_SIZE);
    CHECK_FALSE(kemKey);
}

TEST_CASE("ML-KEM encapsulation uses the RNG sealed into its context") {
    MLKEM kem(EKEM_MLKEM512);
    const SequenceRng keyRng(0x11);
    SKemKeyPair pair;
    REQUIRE(kem.generateKeyPair(keyRng, 512, pair) == ERET_OK);

    auto firstRng = std::make_shared<SequenceRng>(0x61);
    auto secondRng = std::make_shared<SequenceRng>(0x61);
    IKemContextPtr first = kem.createContext(firstRng);
    IKemContextPtr second = kem.createContext(secondRng);
    REQUIRE(first);
    REQUIRE(second);
    first->keyPair(pair.publicKey, nullptr);
    second->keyPair(pair.publicKey, nullptr);

    COctet firstCiphertext, firstSecret;
    COctet secondCiphertext, secondSecret;
    REQUIRE(first->encapsulate(firstCiphertext, firstSecret) == ERET_OK);
    REQUIRE(second->encapsulate(secondCiphertext, secondSecret) == ERET_OK);
    CHECK(firstCiphertext.toSpan().sequencialEqual(secondCiphertext.toSpan()));
    CHECK(firstSecret.toSpan().sequencialEqual(secondSecret.toSpan()));

    IKemContextPtr receiver = kem.createContext();
    REQUIRE(receiver);
    receiver->keyPair(pair);
    COctet recovered;
    REQUIRE(receiver->decapsulate(firstCiphertext.toSpan(), recovered) == ERET_OK);
    CHECK(recovered.toSpan().sequencialEqual(firstSecret.toSpan()));
}
