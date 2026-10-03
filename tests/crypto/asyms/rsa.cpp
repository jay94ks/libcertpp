#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

#include <cstring>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    // 1024 bits is the smallest size that leaves room for a SHA-512 DigestInfo under PKCS#1
    // v1.5 padding (64 + 19-byte prefix + 11 bytes overhead = 94 bytes = 752 bits, rounded up
    // to the next 8-bit step); still fast enough for a test suite with this schoolbook bignum
    // (no CRT/Montgomery speedups). Production use should request a much larger size.
    constexpr SKeySize TEST_KEY_SIZE = 1024;

    SKeyPair generateTestKeyPair() {
        IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
        SKeyPair result;
        rsa->generateKeyPair(TEST_KEY_SIZE, result);
        return result;
    }
}

TEST_CASE("RSA: builtIn(EASYM_RSA) returns a usable algorithm instance") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    REQUIRE(rsa);

    bool acceptsTestSize = false;
    for (size_t i = 0; i < rsa->keySizes().size(); ++i) {
        if (rsa->keySizes()[i].includes(TEST_KEY_SIZE)) {
            acceptsTestSize = true;
        }
    }
    CHECK(acceptsTestSize);
}

TEST_CASE("RSA: generateKeyPair produces a matched, usable key pair") {
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);
    REQUIRE(pair.publicKey->keySize() == TEST_KEY_SIZE);
    REQUIRE(pair.privateKey->keySize() == TEST_KEY_SIZE);
    CHECK(pair.privateKey->publicKey()->compare(pair.publicKey) == 0);
}

TEST_CASE("RSA: generateKeyPair rejects a key size outside keySizes()") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair;
    rsa->generateKeyPair(13, pair); // not in the 512-8192/8 spec
    CHECK(pair.empty());
}

TEST_CASE("RSA: public/private key DER round-trips through serialize()/create*Key()") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    COctet pubDer, privDer;
    REQUIRE(pair.publicKey->serialize(pubDer) == ERET_OK);
    REQUIRE(pair.privateKey->serialize(privDer) == ERET_OK);

    IPublicKeyPtr parsedPub = rsa->createPublicKey(pubDer);
    IPrivateKeyPtr parsedPriv = rsa->createPrivateKey(privDer);

    REQUIRE(parsedPub);
    REQUIRE(parsedPriv);
    CHECK(parsedPub->compare(pair.publicKey) == 0);
    CHECK(parsedPriv->compare(pair.privateKey) == 0);
}

TEST_CASE("RSA: sign/verify round-trips for every supported digest length") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    const size_t digestLens[] = { 16, 20, 32, 48, 64 }; // MD5, SHA-1, SHA-256, SHA-384, SHA-512

    for (size_t len : digestLens) {
        TArray<uint8_t> digest;
        digest.resize(len);
        for (size_t i = 0; i < len; ++i) {
            digest[i] = uint8_t(i * 7 + 1);
        }

        SReadOnlyByteSpan digestSpan(digest.begin(), digest.size());

        TArray<uint8_t> signature;
        signature.resize(ctx->sizeOfSign());
        SByteSpan sigSpan(signature.begin(), signature.size());
        REQUIRE(ctx->sign(digestSpan, sigSpan) == ERET_OK);
        signature.resize(sigSpan.size);
        CHECK(ctx->verify(digestSpan, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK);

        // Tampering with the digest must invalidate the signature.
        digest[0] ^= 0xFF;
        CHECK(ctx->verify(SReadOnlyByteSpan(digest.begin(), digest.size()),
            SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK);
    }
}

TEST_CASE("RSA: sign/verify rejects an unrecognized digest length") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    uint8_t oddDigest[17] = { 0 };
    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    CHECK(ctx->sign(SReadOnlyByteSpan(oddDigest, sizeof(oddDigest)), sigSpan) == ERET_NOTSUP);
}

TEST_CASE("RSA: encrypt/decrypt round-trips via createEncrypter()/createDecrypter()") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    const uint8_t plaintext[] = "certpp RSA test message";
    COctet message(plaintext, sizeof(plaintext));

    IAsymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    SByteSpan unused;
    TArray<uint8_t> ciphertext;
    ciphertext.resize(encrypter->blockSize());
    SByteSpan ciphertextSpan(ciphertext.begin(), ciphertext.size());
    REQUIRE(encrypter->transform(message.toSpan(), unused) == ERET_OK);
    REQUIRE(encrypter->transformFinal(ciphertextSpan) == ERET_OK);
    ciphertext.resize(ciphertextSpan.size);
    CHECK(ciphertext.size() == TEST_KEY_SIZE / 8);

    IAsymmetricTransformerPtr decrypter;
    REQUIRE(ctx->createDecrypter(decrypter) == ERET_OK);

    SByteSpan unused2;
    TArray<uint8_t> recovered;
    recovered.resize(decrypter->blockSize());
    SByteSpan recoveredSpan(recovered.begin(), recovered.size());
    REQUIRE(decrypter->transform(SReadOnlyByteSpan(ciphertext.begin(), ciphertext.size()), unused2) == ERET_OK);
    REQUIRE(decrypter->transformFinal(recoveredSpan) == ERET_OK);
    recovered.resize(recoveredSpan.size);

    REQUIRE(recovered.size() == message.size());
    CHECK(SReadOnlyByteSpan(recovered.begin(), recovered.size()).sequencialEqual(message.toSpan()));
}

TEST_CASE("RSA: transform() processes complete blocks eagerly, block by block") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    // TEST_KEY_SIZE/8 - 11 = 117 bytes of plaintext per block; 300 bytes spans 3 blocks
    // (117 + 117 + 66), so a single transform() call must process more than one block itself
    // rather than only ever deferring to transformFinal().
    TArray<uint8_t> plaintext;
    plaintext.resize(300);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(i);
    }

    IAsymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    TArray<uint8_t> ciphertext;
    ciphertext.resize(encrypter->blockSize() * 3);
    SByteSpan ciphertextSpan(ciphertext.begin(), ciphertext.size());

    REQUIRE(encrypter->transform(SReadOnlyByteSpan(plaintext.begin(), plaintext.size()), ciphertextSpan) == ERET_OK);
    // Two complete 117-byte blocks were available immediately, so transform() must have
    // already produced their ciphertext instead of buffering it for transformFinal().
    CHECK(ciphertextSpan.size == encrypter->blockSize() * 2);

    SByteSpan finalSpan(ciphertext.begin() + ciphertextSpan.size, ciphertext.size() - ciphertextSpan.size);
    REQUIRE(encrypter->transformFinal(finalSpan) == ERET_OK);
    CHECK(finalSpan.size == encrypter->blockSize());

    size_t totalCiphertext = ciphertextSpan.size + finalSpan.size;
    CHECK(totalCiphertext == encrypter->blockSize() * 3);

    IAsymmetricTransformerPtr decrypter;
    REQUIRE(ctx->createDecrypter(decrypter) == ERET_OK);

    TArray<uint8_t> recovered;
    recovered.resize(plaintext.size());
    SByteSpan recoveredSpan(recovered.begin(), recovered.size());

    // totalCiphertext is an exact multiple of the 128-byte decrypt block size (3 * 128), and
    // recoveredSpan has room for the full 300-byte plaintext, so transform() can eagerly
    // decrypt all 3 blocks itself, leaving nothing for transformFinal() to do.
    REQUIRE(decrypter->transform(SReadOnlyByteSpan(ciphertext.begin(), totalCiphertext), recoveredSpan) == ERET_OK);
    CHECK(recoveredSpan.size == 300);

    SByteSpan recoveredFinalSpan(recovered.begin() + recoveredSpan.size, recovered.size() - recoveredSpan.size);
    REQUIRE(decrypter->transformFinal(recoveredFinalSpan) == ERET_OK);
    CHECK(recoveredFinalSpan.size == 0);

    size_t totalRecovered = recoveredSpan.size + recoveredFinalSpan.size;
    REQUIRE(totalRecovered == plaintext.size());
    CHECK(SReadOnlyByteSpan(recovered.begin(), totalRecovered).sequencialEqual(
        SReadOnlyByteSpan(plaintext.begin(), plaintext.size())));
}

TEST_CASE("RSA: decrypt rejects a tampered ciphertext") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    SKeyPair pair = generateTestKeyPair();
    REQUIRE(pair);

    IAsymmetricContextPtr ctx = rsa->createContext();
    ctx->keyPair(pair);

    const uint8_t plaintext[] = "tamper test";
    COctet message(plaintext, sizeof(plaintext));

    IAsymmetricTransformerPtr encrypter;
    REQUIRE(ctx->createEncrypter(encrypter) == ERET_OK);

    SByteSpan unused;
    TArray<uint8_t> ciphertext;
    ciphertext.resize(encrypter->blockSize());
    SByteSpan ciphertextSpan(ciphertext.begin(), ciphertext.size());
    REQUIRE(encrypter->transform(message.toSpan(), unused) == ERET_OK);
    REQUIRE(encrypter->transformFinal(ciphertextSpan) == ERET_OK);
    ciphertext.resize(ciphertextSpan.size);

    TArray<uint8_t> tampered;
    tampered.resize(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        tampered[i] = ciphertext[i];
    }
    tampered[0] ^= 0xFF;

    IAsymmetricTransformerPtr decrypter;
    REQUIRE(ctx->createDecrypter(decrypter) == ERET_OK);

    SByteSpan unused2;
    TArray<uint8_t> recovered;
    recovered.resize(decrypter->blockSize());
    SByteSpan recoveredSpan(recovered.begin(), recovered.size());

    // Processing is block-by-block now, so the tampered block's padding may be rejected as
    // soon as transform() sees the complete block, rather than only at transformFinal().
    ERetCode rc = decrypter->transform(SReadOnlyByteSpan(tampered.begin(), tampered.size()), unused2);
    if (rc == ERET_OK) {
        rc = decrypter->transformFinal(recoveredSpan);
    }
    CHECK(rc != ERET_OK);
}

// RFC 8017 3.2 allows d to be the inverse of e modulo either lambda(n) = lcm(p-1, q-1) or
// phi(n) = (p-1)(q-1). The vectors below are one 1024-bit key -- same n, e, p, q -- encoded
// as PKCS#1 RSAPrivateKey once in each form, generated from an `openssl genrsa` key whose
// gcd(p-1, q-1) is 24 so that the two d values genuinely differ. Both must be accepted;
// checkPrivateKey used to compare d against the phi(n) inverse alone and so rejected every
// OpenSSL-2048/dnssec-keygen/ldns key.
namespace {
    // d = e^-1 mod lambda(n), the form OpenSSL/BIND/ldns emit. gcd(p-1, q-1) = 24 here,
    // so this d is 24x smaller than the phi(n) one and the two are genuinely different.
    const char* LAMBDA_FORM_KEY =
        "3082025c02010002818100d826754fe7ad468d073dc30f2aa8bf815782963509"
        "a33e9c1c77cf323aeee52b02469ea50ac83200f473e407920cbe08065bba7d5d"
        "92a3802b770e9177292c5c21ebe8e918cb7d9d868e8d4fc7d19df9955c277086"
        "39feaa761a6f180203b39854ed2c96fefb0801c1a0ee99d26e5794fd2154d84e"
        "6b2c1f9ced23d63ab77ef90203010001028180044800ba02dbfd022a984d2930"
        "a9092aaf43217aae9f45371e3390f9a24eb1e07ff49fa1a3bcc836c4cb6dd868"
        "e01291d749bbaace2ec073cd08983e8686722a88a87f23eece88a300b84ec4c8"
        "1d4cc88c41f852e304064a7074ec9bfe6e1e0689591464a01f724521ba882177"
        "f7b8b07d606bf88d453b1933c80283db4c1901024100fe1118f8cd91615d3fde"
        "74f1ddf3f0933b32914c835b2d917d940f32f371c75f3010338968fd1c6585e4"
        "faf64d85e67abd029c4e3c58b0304250f6ce6588c681024100d9cb808ebb9469"
        "9e1029a9cf94c086ba0316c92a458365a3ba4813296edaaba7979e64610db3f4"
        "133822ba54e4c4065e4281077683e84e644ae7faa2cc33ac7902405d4fde4213"
        "0e201a6588c89ec48c0181b1ae42db3d2b51b32bd2233aed5a8e85115c01f1a7"
        "d3be88330304814dbbae08ca3e9935cac82ffda97d9f07f316a7010240778f60"
        "a67a5111dde48f8a99dad609dfc95c53d871ca9d1c5161c9ab2020c8c4bad607"
        "d2c39bfb2c25cfe2ac41dd5e85964a90d73db86478682a8b0b9dbfec39024100"
        "bb959398142fa84d672ef897aef80076ee659cdd45af69e7730df6e21f721255"
        "2e58af823e274e277d0914c5ffbaf197c97b384ebacfed7aa804a267be633748";

    // The same p, q and e with d = e^-1 mod phi(n) -- the other form RFC 8017 3.2 allows,
    // and the one this library's own generateKeyPair() produces.
    const char* PHI_FORM_KEY =
        "3082025d02010002818100d826754fe7ad468d073dc30f2aa8bf815782963509"
        "a33e9c1c77cf323aeee52b02469ea50ac83200f473e407920cbe08065bba7d5d"
        "92a3802b770e9177292c5c21ebe8e918cb7d9d868e8d4fc7d19df9955c277086"
        "39feaa761a6f180203b39854ed2c96fefb0801c1a0ee99d26e5794fd2154d84e"
        "6b2c1f9ced23d63ab77ef9020301000102818100825e6fd34a0110d46ed1a99c"
        "b436238b77a4a3c44993d46784241f2c44af6239969dd181ea06e561fe0f0832"
        "28bcd6c13054931e9a199fd3e66360be0c09215f33dc181cd7ef30d6f5dc0f42"
        "79c3a357bf0cefe491795a4ed4c3eeb41b9903b0c6684073ef9fed550e7e943a"
        "000cf6f37bfc68994addd5aa5246753ecb33e001024100fe1118f8cd91615d3f"
        "de74f1ddf3f0933b32914c835b2d917d940f32f371c75f3010338968fd1c6585"
        "e4faf64d85e67abd029c4e3c58b0304250f6ce6588c681024100d9cb808ebb94"
        "699e1029a9cf94c086ba0316c92a458365a3ba4813296edaaba7979e64610db3"
        "f4133822ba54e4c4065e4281077683e84e644ae7faa2cc33ac7902405d4fde42"
        "130e201a6588c89ec48c0181b1ae42db3d2b51b32bd2233aed5a8e85115c01f1"
        "a7d3be88330304814dbbae08ca3e9935cac82ffda97d9f07f316a7010240778f"
        "60a67a5111dde48f8a99dad609dfc95c53d871ca9d1c5161c9ab2020c8c4bad6"
        "07d2c39bfb2c25cfe2ac41dd5e85964a90d73db86478682a8b0b9dbfec390241"
        "00bb959398142fa84d672ef897aef80076ee659cdd45af69e7730df6e21f7212"
        "552e58af823e274e277d0914c5ffbaf197c97b384ebacfed7aa804a267be6337"
        "48";

    // d one past the lambda(n) inverse, with dP/dQ recomputed to match it, so the only
    // thing wrong is the e*d congruence itself.
    const char* NON_INVERSE_KEY =
        "3082025c02010002818100d826754fe7ad468d073dc30f2aa8bf815782963509"
        "a33e9c1c77cf323aeee52b02469ea50ac83200f473e407920cbe08065bba7d5d"
        "92a3802b770e9177292c5c21ebe8e918cb7d9d868e8d4fc7d19df9955c277086"
        "39feaa761a6f180203b39854ed2c96fefb0801c1a0ee99d26e5794fd2154d84e"
        "6b2c1f9ced23d63ab77ef90203010001028180044800ba02dbfd022a984d2930"
        "a9092aaf43217aae9f45371e3390f9a24eb1e07ff49fa1a3bcc836c4cb6dd868"
        "e01291d749bbaace2ec073cd08983e8686722a88a87f23eece88a300b84ec4c8"
        "1d4cc88c41f852e304064a7074ec9bfe6e1e0689591464a01f724521ba882177"
        "f7b8b07d606bf88d453b1933c80283db4c1902024100fe1118f8cd91615d3fde"
        "74f1ddf3f0933b32914c835b2d917d940f32f371c75f3010338968fd1c6585e4"
        "faf64d85e67abd029c4e3c58b0304250f6ce6588c681024100d9cb808ebb9469"
        "9e1029a9cf94c086ba0316c92a458365a3ba4813296edaaba7979e64610db3f4"
        "133822ba54e4c4065e4281077683e84e644ae7faa2cc33ac7902405d4fde4213"
        "0e201a6588c89ec48c0181b1ae42db3d2b51b32bd2233aed5a8e85115c01f1a7"
        "d3be88330304814dbbae08ca3e9935cac82ffda97d9f07f316a7020240778f60"
        "a67a5111dde48f8a99dad609dfc95c53d871ca9d1c5161c9ab2020c8c4bad607"
        "d2c39bfb2c25cfe2ac41dd5e85964a90d73db86478682a8b0b9dbfec3a024100"
        "bb959398142fa84d672ef897aef80076ee659cdd45af69e7730df6e21f721255"
        "2e58af823e274e277d0914c5ffbaf197c97b384ebacfed7aa804a267be633748";
    /* Decodes an even-length hex literal into raw bytes. */
    std::vector<uint8_t> derFromHex(const char* hex) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') { return c - '0'; }
            if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
            return -1;
        };

        std::vector<uint8_t> out;
        for (const char* p = hex; *p && *(p + 1); p += 2) {
            out.push_back(uint8_t((nibble(p[0]) << 4) | nibble(p[1])));
        }
        return out;
    }

    IPrivateKeyPtr importKey(const IAsymmetricPtr& rsa, const char* hex) {
        std::vector<uint8_t> der = derFromHex(hex);
        return rsa->createPrivateKey(SReadOnlyByteSpan(der.data(), der.size()));
    }
}

TEST_CASE("RSA: checkPrivateKey accepts both the lambda(n) and phi(n) forms of d") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);

    IPrivateKeyPtr lambdaForm = importKey(rsa, LAMBDA_FORM_KEY);
    IPrivateKeyPtr phiForm = importKey(rsa, PHI_FORM_KEY);
    REQUIRE(lambdaForm);
    REQUIRE(phiForm);

    // Same key material, so the two forms must agree on the public half.
    CHECK(lambdaForm->publicKey()->compare(phiForm->publicKey()) == 0);

    CHECK(rsa->checkPrivateKey(lambdaForm) == ERET_OK);
    CHECK(rsa->checkPrivateKey(phiForm) == ERET_OK);
}

TEST_CASE("RSA: a lambda(n)-form key signs and verifies, which is what made the old rejection wrong") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    IPrivateKeyPtr lambdaForm = importKey(rsa, LAMBDA_FORM_KEY);
    REQUIRE(lambdaForm);
    REQUIRE(rsa->checkPrivateKey(lambdaForm) == ERET_OK);

    IAsymmetricContextPtr ctx = rsa->createContext();
    REQUIRE(ctx);
    ctx->keyPair(SKeyPair(lambdaForm->publicKey(), lambdaForm));

    uint8_t digest[32];
    std::memset(digest, 0x5a, sizeof(digest));
    SReadOnlyByteSpan digestSpan(digest, sizeof(digest));

    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());
    SByteSpan sigSpan(signature.begin(), signature.size());
    REQUIRE(ctx->sign(digestSpan, sigSpan) == ERET_OK);

    CHECK(ctx->verify(digestSpan, SReadOnlyByteSpan(sigSpan.data, sigSpan.size)) == ERET_OK);
}

TEST_CASE("RSA: checkPrivateKey still rejects a d that is not an inverse at all") {
    IAsymmetricPtr rsa = IAsymmetric::builtIn(EASYM_RSA);
    IPrivateKeyPtr bogus = importKey(rsa, NON_INVERSE_KEY);
    REQUIRE(bogus);
    CHECK(rsa->checkPrivateKey(bogus) == ERET_KEY_PARAM);
}
