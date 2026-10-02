// ML-KEM through the IKem/IKemContext interface.
//
// The algorithm itself is pinned against NIST's ACVP vectors in
// tests/crypto/kems/kat_mlkem.cpp. This file covers only what the wrapper adds: the EKems dispatch,
// key objects and their serialization, the size bookkeeping IKemContext exposes, and the fact
// that encapsulate() draws fresh randomness rather than being a function of the key. There is
// no known-answer test to be had here -- encapsulate() has no seed parameter, by design.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    struct ParamSet {
        EKems which;
        SKeySize keySize;
        SMlKemParams params;
    };

    const ParamSet PARAM_SETS[] = {
        { EKEM_MLKEM512,   512, SMlKemParams::mlKem512() },
        { EKEM_MLKEM768,   768, SMlKemParams::mlKem768() },
        { EKEM_MLKEM1024, 1024, SMlKemParams::mlKem1024() },
    };

    /* Generates a key pair, failing the test rather than returning an empty one. */
    SKemKeyPair generate(const IKemPtr& kem, SKeySize keySize) {
        SKemKeyPair pair;
        REQUIRE(kem->generateKeyPair(keySize, pair) == ERET_OK);
        REQUIRE(pair.publicKey);
        REQUIRE(pair.privateKey);
        return pair;
    }
}

TEST_CASE("MLKEM: IKem::builtIn dispatches the three parameter sets") {
    for (const ParamSet& set : PARAM_SETS) {
        IKemPtr kem = IKem::builtIn(set.which);
        REQUIRE(kem);

        REQUIRE(kem->keySizes().size() == 1);
        CHECK(kem->keySizes()[0].minSize == set.keySize);
        CHECK(kem->keySizes()[0].maxSize == set.keySize);

        auto mlkem = std::dynamic_pointer_cast<MLKEM>(kem);
        REQUIRE(mlkem);
        CHECK(mlkem->params().equals(set.params));
    }

    // EKEM_MAX is the marker, not an algorithm, and EKEM_UNKNOWN never names one.
    CHECK_FALSE(IKem::builtIn(EKEM_MAX));
    CHECK_FALSE(IKem::builtIn(EKEM_UNKNOWN));
    CHECK_FALSE(IKem::builtIn(EKems(1000)));
}

// A directly constructed MLKEM with a value that names no parameter set has to be inert rather
// than half-built: keySizes() empty, every operation refusing. builtIn() returns null for such a
// value, so this is only reachable by constructing the class directly -- which the public header
// allows, so it has to be defined behaviour.
TEST_CASE("MLKEM: an unrecognized parameter set yields an inert instance") {
    MLKEM kem(EKEM_UNKNOWN);

    CHECK(kem.keySizes().empty());

    SKemKeyPair pair;
    CHECK(kem.generateKeyPair(768, pair) == ERET_KEY_SIZE);
    CHECK(pair.empty());

    std::vector<uint8_t> bytes(1184, 0x00);
    CHECK_FALSE(kem.createPublicKey(SReadOnlyByteSpan(bytes.data(), bytes.size())));
    CHECK_FALSE(kem.createPrivateKey(SReadOnlyByteSpan(bytes.data(), bytes.size())));
}

TEST_CASE("MLKEM: generated keys have FIPS 203's sizes and pass validation") {
    for (const ParamSet& set : PARAM_SETS) {
        SUBCASE(set.which == EKEM_MLKEM512 ? "ML-KEM-512"
              : set.which == EKEM_MLKEM768 ? "ML-KEM-768" : "ML-KEM-1024") {
            IKemPtr kem = IKem::builtIn(set.which);
            REQUIRE(kem);

            SKemKeyPair pair = generate(kem, set.keySize);

            CHECK(pair.publicKey->algorithm() == set.which);
            CHECK(pair.privateKey->algorithm() == set.which);
            CHECK(pair.publicKey->keySize() == set.keySize);
            CHECK(pair.privateKey->keySize() == set.keySize);

            COctet ek;
            COctet dk;
            REQUIRE(pair.publicKey->serialize(ek) == ERET_OK);
            REQUIRE(pair.privateKey->serialize(dk) == ERET_OK);
            CHECK(ek.size() == set.params.ekBytes());
            CHECK(dk.size() == set.params.dkBytes());

            CHECK(kem->checkPrivateKey(pair.privateKey) == ERET_OK);

            // The private key's public half is the one embedded in the decapsulation key at
            // offset dkPkeBytes(), not a recomputed or unrelated key.
            COctet derived;
            REQUIRE(pair.privateKey->publicKey()->serialize(derived) == ERET_OK);
            REQUIRE(derived.size() == set.params.ekBytes());
            CHECK(derived.toSpan().sequencialEqual(ek.toSpan()));
            CHECK(std::memcmp(
                dk.toPtr() + set.params.dkPkeBytes(), ek.toPtr(), set.params.ekBytes()) == 0);

            // A size this algorithm doesn't accept is refused, and leaves the output empty.
            SKemKeyPair rejected;
            CHECK(kem->generateKeyPair(set.keySize + 1, rejected) == ERET_KEY_SIZE);
            CHECK(rejected.empty());
        }
    }
}

TEST_CASE("MLKEM: keys round-trip through serialize and create*Key") {
    IKemPtr kem = IKem::builtIn(EKEM_MLKEM768);
    REQUIRE(kem);

    SKemKeyPair pair = generate(kem, 768);

    COctet ek;
    COctet dk;
    REQUIRE(pair.publicKey->serialize(ek) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(dk) == ERET_OK);

    IKemPublicKeyPtr reloadedPublic = kem->createPublicKey(ek);
    IKemPrivateKeyPtr reloadedPrivate = kem->createPrivateKey(dk);
    REQUIRE(reloadedPublic);
    REQUIRE(reloadedPrivate);

    CHECK(reloadedPublic->compare(pair.publicKey) == 0);
    CHECK(reloadedPrivate->compare(pair.privateKey) == 0);
    CHECK(kem->checkPrivateKey(reloadedPrivate) == ERET_OK);

    // Wrong lengths are refused outright.
    CHECK_FALSE(kem->createPublicKey(SReadOnlyByteSpan(ek.toPtr(), ek.size() - 1)));
    CHECK_FALSE(kem->createPrivateKey(SReadOnlyByteSpan(dk.toPtr(), dk.size() - 1)));

    // So is a key of another parameter set's length, even though it is a perfectly good key --
    // this instance runs ML-KEM-768 and nothing else.
    IKemPtr other = IKem::builtIn(EKEM_MLKEM1024);
    REQUIRE(other);
    SKemKeyPair otherPair = generate(other, 1024);

    COctet otherEk;
    REQUIRE(otherPair.publicKey->serialize(otherEk) == ERET_OK);
    CHECK_FALSE(kem->createPublicKey(otherEk));

    // And a key object belonging to a different parameter set is rejected by type rather than
    // silently validated against the wrong sizes.
    CHECK(kem->checkPrivateKey(otherPair.privateKey) == ERET_KEY_FORMAT);
}

TEST_CASE("MLKEM: a decapsulation key with a corrupted H(ek) is refused") {
    IKemPtr kem = IKem::builtIn(EKEM_MLKEM512);
    REQUIRE(kem);

    SKemKeyPair pair = generate(kem, 512);

    COctet dk;
    REQUIRE(pair.privateKey->serialize(dk) == ERET_OK);

    const SMlKemParams params = SMlKemParams::mlKem512();
    std::vector<uint8_t> tampered(dk.toPtr(), dk.toPtr() + dk.size());

    // dk = dk_PKE || ek || H(ek) || z, so H(ek) starts at 768*k + 32.
    tampered[768 * params.k + 32] ^= 0x01;
    CHECK_FALSE(kem->createPrivateKey(
        SReadOnlyByteSpan(tampered.data(), tampered.size())));

    // The embedded encapsulation key is checked for canonicality too: a 12-bit segment of all
    // ones is 4095, which is above q and so cannot have come from ByteEncode.
    std::vector<uint8_t> noisy(dk.toPtr(), dk.toPtr() + dk.size());
    noisy[params.dkPkeBytes()] = 0xFF;
    noisy[params.dkPkeBytes() + 1] = 0xFF;
    CHECK_FALSE(kem->createPrivateKey(SReadOnlyByteSpan(noisy.data(), noisy.size())));
}

TEST_CASE("MLKEM: encapsulate/decapsulate agree, and sizes are reported before use") {
    for (const ParamSet& set : PARAM_SETS) {
        SUBCASE(set.which == EKEM_MLKEM512 ? "ML-KEM-512"
              : set.which == EKEM_MLKEM768 ? "ML-KEM-768" : "ML-KEM-1024") {
            IKemPtr kem = IKem::builtIn(set.which);
            REQUIRE(kem);

            SKemKeyPair pair = generate(kem, set.keySize);

            // The sender's side: only the peer's public key, bound via the two-key overload.
            IKemContextPtr sender = kem->createContext();
            REQUIRE(sender);

            // Nothing is bound yet, so there is nothing to report and nothing to do.
            CHECK(sender->sizeOfCiphertext() == 0);
            CHECK(sender->sizeOfSharedSecret() == 0);

            SByteSpan nowhere;
            CHECK(sender->encapsulate(nowhere, nowhere) == ERET_KEY_EMPTY);

            sender->keyPair(pair.publicKey, nullptr);
            CHECK(sender->sizeOfCiphertext() == set.params.ciphertextBytes());
            CHECK(sender->sizeOfSharedSecret() == set.params.sharedSecretBytes());

            std::vector<uint8_t> ciphertextBuffer(sender->sizeOfCiphertext());
            std::vector<uint8_t> senderSecretBuffer(sender->sizeOfSharedSecret());
            SByteSpan ciphertext(ciphertextBuffer.data(), ciphertextBuffer.size());
            SByteSpan senderSecret(senderSecretBuffer.data(), senderSecretBuffer.size());
            REQUIRE(sender->encapsulate(ciphertext, senderSecret) == ERET_OK);

            CHECK(ciphertext.size == set.params.ciphertextBytes());
            CHECK(senderSecret.size == set.params.sharedSecretBytes());

            // The receiver's side: the private key, which also carries its public half.
            IKemContextPtr receiver = kem->createContext();
            REQUIRE(receiver);

            SByteSpan unbound;
            CHECK(receiver->decapsulate(
                SReadOnlyByteSpan(ciphertext.data, ciphertext.size), unbound) == ERET_KEY_EMPTY);

            receiver->keyPair(pair);
            CHECK(receiver->sizeOfCiphertext() == set.params.ciphertextBytes());
            CHECK(receiver->sizeOfSharedSecret() == set.params.sharedSecretBytes());

            std::vector<uint8_t> receiverSecretBuffer(receiver->sizeOfSharedSecret());
            SByteSpan receiverSecret(receiverSecretBuffer.data(), receiverSecretBuffer.size());
            REQUIRE(receiver->decapsulate(
                SReadOnlyByteSpan(ciphertext.data, ciphertext.size), receiverSecret) == ERET_OK);

            CHECK(receiverSecret.size == set.params.sharedSecretBytes());
            CHECK(senderSecretBuffer == receiverSecretBuffer);

            // reset() discards the key and the sizes with it.
            receiver->reset();
            CHECK(receiver->sizeOfCiphertext() == 0);
            CHECK(receiver->sizeOfSharedSecret() == 0);
        }
    }
}

// encapsulate() draws its own message from the CSPRNG, so two calls against the same public key
// must produce different ciphertexts and different secrets. If they didn't, the shared secret
// would be a function of the key alone and every session would reuse it.
TEST_CASE("MLKEM: encapsulate is randomized, not a function of the key") {
    IKemPtr kem = IKem::builtIn(EKEM_MLKEM768);
    REQUIRE(kem);

    SKemKeyPair pair = generate(kem, 768);

    IKemContextPtr sender = kem->createContext();
    REQUIRE(sender);
    sender->keyPair(pair.publicKey, nullptr);

    std::vector<std::vector<uint8_t>> ciphertexts;
    std::vector<std::vector<uint8_t>> secrets;

    for (int i = 0; i < 4; ++i) {
        std::vector<uint8_t> ciphertextBuffer(sender->sizeOfCiphertext());
        std::vector<uint8_t> secretBuffer(sender->sizeOfSharedSecret());
        SByteSpan ciphertext(ciphertextBuffer.data(), ciphertextBuffer.size());
        SByteSpan secret(secretBuffer.data(), secretBuffer.size());
        REQUIRE(sender->encapsulate(ciphertext, secret) == ERET_OK);

        // Every one of them still decapsulates to what the sender derived.
        IKemContextPtr receiver = kem->createContext();
        receiver->keyPair(pair);

        std::vector<uint8_t> recovered(receiver->sizeOfSharedSecret());
        SByteSpan recoveredSpan(recovered.data(), recovered.size());
        REQUIRE(receiver->decapsulate(
            SReadOnlyByteSpan(ciphertextBuffer.data(), ciphertextBuffer.size()),
            recoveredSpan) == ERET_OK);
        CHECK(recovered == secretBuffer);

        ciphertexts.push_back(ciphertextBuffer);
        secrets.push_back(secretBuffer);
    }

    for (size_t i = 0; i < ciphertexts.size(); ++i) {
        for (size_t j = i + 1; j < ciphertexts.size(); ++j) {
            CHECK(ciphertexts[i] != ciphertexts[j]);
            CHECK(secrets[i] != secrets[j]);
        }
    }
}

// The Fujisaki-Okamoto requirement, at the interface level: a tampered ciphertext must come back
// ERET_OK with a different secret, never an error code. An implementation that reported failure
// here would hand a chosen-ciphertext attacker the decryption oracle the transform exists to
// deny, and no amount of care elsewhere would make up for it.
TEST_CASE("MLKEM: a tampered ciphertext decapsulates successfully to a different secret") {
    IKemPtr kem = IKem::builtIn(EKEM_MLKEM512);
    REQUIRE(kem);

    SKemKeyPair pair = generate(kem, 512);

    IKemContextPtr sender = kem->createContext();
    sender->keyPair(pair.publicKey, nullptr);

    std::vector<uint8_t> ciphertextBuffer(sender->sizeOfCiphertext());
    std::vector<uint8_t> senderSecret(sender->sizeOfSharedSecret());
    SByteSpan ciphertext(ciphertextBuffer.data(), ciphertextBuffer.size());
    SByteSpan secret(senderSecret.data(), senderSecret.size());
    REQUIRE(sender->encapsulate(ciphertext, secret) == ERET_OK);

    IKemContextPtr receiver = kem->createContext();
    receiver->keyPair(pair);

    for (size_t offset : { size_t(0), ciphertextBuffer.size() / 2, ciphertextBuffer.size() - 1 }) {
        std::vector<uint8_t> tampered = ciphertextBuffer;
        tampered[offset] ^= 0x01;

        std::vector<uint8_t> recovered(receiver->sizeOfSharedSecret());
        SByteSpan recoveredSpan(recovered.data(), recovered.size());

        CHECK(receiver->decapsulate(
            SReadOnlyByteSpan(tampered.data(), tampered.size()), recoveredSpan) == ERET_OK);
        CHECK(recovered.size() == 32);
        CHECK(recovered != senderSecret);
    }

    // A ciphertext of the wrong *length*, by contrast, is a structural error and is reported as
    // one -- it carries no information about any key, so there is no oracle to protect.
    std::vector<uint8_t> recovered(receiver->sizeOfSharedSecret());
    SByteSpan recoveredSpan(recovered.data(), recovered.size());
    CHECK(receiver->decapsulate(
        SReadOnlyByteSpan(ciphertextBuffer.data(), ciphertextBuffer.size() - 1),
        recoveredSpan) == ERET_BADREQ);

    // And too small an output buffer is likewise structural.
    SByteSpan tooSmall(recovered.data(), 16);
    CHECK(receiver->decapsulate(
        SReadOnlyByteSpan(ciphertextBuffer.data(), ciphertextBuffer.size()),
        tooSmall) == ERET_NOSPC);
}

// Two independently generated key pairs must not decapsulate each other's ciphertexts to the same
// secret -- which, for a KEM with implicit rejection, means the mismatch shows up as a *different
// secret* rather than as an error.
TEST_CASE("MLKEM: a ciphertext for one key does not open under another") {
    IKemPtr kem = IKem::builtIn(EKEM_MLKEM768);
    REQUIRE(kem);

    SKemKeyPair alice = generate(kem, 768);
    SKemKeyPair bob = generate(kem, 768);

    CHECK(alice.publicKey->compare(bob.publicKey) != 0);

    IKemContextPtr sender = kem->createContext();
    sender->keyPair(alice.publicKey, nullptr);

    std::vector<uint8_t> ciphertext(sender->sizeOfCiphertext());
    std::vector<uint8_t> senderSecret(sender->sizeOfSharedSecret());
    SByteSpan ciphertextSpan(ciphertext.data(), ciphertext.size());
    SByteSpan senderSecretSpan(senderSecret.data(), senderSecret.size());
    REQUIRE(sender->encapsulate(ciphertextSpan, senderSecretSpan) == ERET_OK);

    IKemContextPtr wrongReceiver = kem->createContext();
    wrongReceiver->keyPair(bob);

    std::vector<uint8_t> wrongSecret(wrongReceiver->sizeOfSharedSecret());
    SByteSpan wrongSecretSpan(wrongSecret.data(), wrongSecret.size());
    CHECK(wrongReceiver->decapsulate(
        SReadOnlyByteSpan(ciphertext.data(), ciphertext.size()), wrongSecretSpan) == ERET_OK);
    CHECK(wrongSecret != senderSecret);
}
