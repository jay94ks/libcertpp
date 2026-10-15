#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

TEST_CASE("owning hash and signature APIs size their outputs") {
    IHasherPtr hasher;
    REQUIRE(IHasher::create(EHASH_SHA256, hasher) == ERET_OK);
    const uint8_t message[] = { 'o', 'w', 'n', 'e', 'd' };
    REQUIRE(hasher->push(SReadOnlyByteSpan(message, sizeof(message))) == sizeof(message));

    COctet digest;
    REQUIRE(hasher->finishOwned(digest));
    REQUIRE(digest.size() == 32);

    IAsymmetricPtr algorithm = IAsymmetric::builtIn(EASYM_ED25519);
    REQUIRE(algorithm);
    SKeyPair pair;
    REQUIRE(algorithm->generateKeyPair(256, pair) == ERET_OK);

    IAsymmetricContextPtr context = algorithm->createContext();
    REQUIRE(context);
    context->keyPair(pair);

    COctet signature;
    REQUIRE(context->sign(digest, signature) == ERET_OK);
    CHECK(signature.size() == context->sizeOfSign());
    CHECK(context->verify(digest, signature) == ERET_OK);
}

TEST_CASE("owning KEM APIs allocate ciphertext and matching shared secrets") {
    IKemPtr kem = IKem::builtIn(EKEM_MLKEM512);
    REQUIRE(kem);
    SKemKeyPair pair;
    REQUIRE(kem->generateKeyPair(512, pair) == ERET_OK);

    IKemContextPtr sender = kem->createContext();
    IKemContextPtr receiver = kem->createContext();
    REQUIRE(sender);
    REQUIRE(receiver);
    sender->keyPair(pair.publicKey, nullptr);
    receiver->keyPair(nullptr, pair.privateKey);

    COctet ciphertext;
    COctet senderSecret;
    REQUIRE(sender->encapsulate(ciphertext, senderSecret) == ERET_OK);
    CHECK(ciphertext.size() == sender->sizeOfCiphertext());
    CHECK(senderSecret.size() == sender->sizeOfSharedSecret());

    COctet receiverSecret;
    REQUIRE(receiver->decapsulate(ciphertext, receiverSecret) == ERET_OK);
    CHECK(receiverSecret.toSpan().sequencialEqual(senderSecret.toSpan()));
}
