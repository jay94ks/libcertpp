#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <string>

using namespace certpp;
using namespace certpp::dnssec;

namespace {
    CBuffer fromBase64(const char* text) {
        CBuffer out;
        REQUIRE(CBase64::decode(out, CString(text)));
        return out;
    }

    SDnskey makeKey(uint16_t flags, EDnsAlgorithms algorithm, const char* keyBase64) {
        SDnskey key;
        key.flags = flags;
        key.protocol = SDnskey::PROTOCOL_DNSSEC;
        key.algorithm = algorithm;
        key.publicKey = fromBase64(keyBase64);
        return key;
    }

    /* Converts a DNSKEY to a public key and straight back, and reports whether the DNS encoding
     * survived unchanged. This is the property that matters: both directions are pure
     * re-encodings, so anything lost in one of them shows up here. */
    bool roundTrips(const SDnskey& key) {
        crypto::IPublicKeyPtr parsed;
        if (!CDnssecKeys::toPublicKey(key, parsed) || !parsed) {
            return false;
        }

        SDnskey rebuilt;
        if (!CDnssecKeys::fromPublicKey(parsed, key.algorithm, key.flags, rebuilt)) {
            return false;
        }

        return rebuilt.flags == key.flags
            && rebuilt.algorithm == key.algorithm
            && rebuilt.publicKey.size() == key.publicKey.size()
            && std::memcmp(rebuilt.publicKey.toPtr(), key.publicKey.toPtr(),
                           key.publicKey.size()) == 0;
    }
}

TEST_CASE("CDnssecKeys: the published DNSKEYs convert to keys and back unchanged") {
    // RFC 6605 6.1 -- ECDSA P-256. The conversion has to prepend the SEC1 0x04 on the way in
    // and strip it on the way out; a round trip that kept the prefix would come back 65 bytes.
    CHECK(roundTrips(makeKey(257, EDNSALG_ECDSAP256SHA256,
        "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb"
        "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==")));

    // RFC 6605 6.2 -- ECDSA P-384.
    CHECK(roundTrips(makeKey(257, EDNSALG_ECDSAP384SHA384,
        "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1"
        "w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8"
        "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40")));

    // RFC 8080 -- Ed25519 and Ed448, which are pass-throughs in both directions.
    CHECK(roundTrips(makeKey(257, EDNSALG_ED25519,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")));
    CHECK(roundTrips(makeKey(257, EDNSALG_ED448,
        "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx"
        "1FYYUcJKm1MDpJtIA")));

    // RFC 5702 -- RSA, where DNS writes exponent-then-modulus and this library's DER wants
    // modulus-then-exponent. A round trip that got the order wrong would not come back.
    CHECK(roundTrips(makeKey(256, EDNSALG_RSASHA256,
        "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36Bponcw"
        "tkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=")));
    CHECK(roundTrips(makeKey(256, EDNSALG_RSASHA512,
        "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6p"
        "nWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVs"
        "Mu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL")));
}

TEST_CASE("CDnssecKeys: the RSA exponent really is read as 65537") {
    // The round trip above would pass even if the exponent and modulus were consistently
    // swapped in both directions, so this checks the absolute value. RFC 5702's key encodes
    // AQAB -- a three-octet exponent of 0x010001 -- which is 65537.
    const SDnskey key = makeKey(256, EDNSALG_RSASHA256,
        "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36Bponcw"
        "tkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=");

    const uint8_t* raw = key.publicKey.toPtr();
    REQUIRE(key.publicKey.size() > 4);
    CHECK(raw[0] == 3);                         // one-octet exponent length
    CHECK(raw[1] == 0x01);
    CHECK(raw[2] == 0x00);
    CHECK(raw[3] == 0x01);                      // 0x010001 == 65537
    CHECK(key.publicKey.size() == 1 + 3 + 64);  // 512-bit modulus

    crypto::IPublicKeyPtr parsed;
    REQUIRE(CDnssecKeys::toPublicKey(key, parsed));

    // Serialising through the library gives DER SEQUENCE { INTEGER n, INTEGER e }; the exponent
    // is the second integer, and must be 65537 rather than the modulus.
    COctet der;
    REQUIRE(parsed->serialize(der) == ERET_OK);

    TReadOnlySpan<uint8_t> content;
    REQUIRE(asn1::CDer::readOuterSequence(der.toSpan(), content));

    CBigNum n, e;
    REQUIRE(asn1::CDer::readBigInteger(content, n));
    REQUIRE(asn1::CDer::readBigInteger(content, e));
    CHECK(e == CBigNum(uint64_t(65537)));
    CHECK(n.bitLength() == 512);
}

TEST_CASE("CDnssecKeys: key material of the wrong length for its algorithm is rejected") {
    crypto::IPublicKeyPtr parsed;

    // A P-256 key must be exactly 64 octets. A 63-octet value split at 32 would give a
    // different point with no error anywhere, which is why the length is checked rather than
    // inferred.
    SDnskey shortP256 = makeKey(257, EDNSALG_ECDSAP256SHA256,
        "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb"
        "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");
    REQUIRE(shortP256.publicKey.resize(63));
    CHECK_FALSE(CDnssecKeys::toPublicKey(shortP256, parsed));

    // A P-384 key is 96 octets, so a P-256-sized one must not be accepted as P-384.
    SDnskey wrongCurve = makeKey(257, EDNSALG_ECDSAP384SHA384,
        "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb"
        "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");
    CHECK_FALSE(CDnssecKeys::toPublicKey(wrongCurve, parsed));

    // Ed25519 is 32 octets and Ed448 is 57; neither accepts the other's.
    SDnskey ed25519AsEd448 = makeKey(257, EDNSALG_ED448,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");
    CHECK_FALSE(CDnssecKeys::toPublicKey(ed25519AsEd448, parsed));

    // An algorithm this library does not implement is reported, not guessed at.
    SDnskey gost = makeKey(257, EDNSALG_ECC_GOST,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");
    CHECK_FALSE(CDnssecKeys::toPublicKey(gost, parsed));

    SDnskey unknown = makeKey(257, EDnsAlgorithms(99),
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");
    CHECK_FALSE(CDnssecKeys::toPublicKey(unknown, parsed));
}

TEST_CASE("CDnssecKeys: algorithm numbers map to the right key type and hash") {
    crypto::EAsymmetrics which = crypto::EASYM_RSA;
    crypto::EHashers hasher = crypto::EHASH_UNKNOWN;

    REQUIRE(CDnssecKeys::asymmetricOf(EDNSALG_ECDSAP256SHA256, which));
    CHECK(which == crypto::EASYM_P256);
    REQUIRE(CDnssecKeys::hasherOf(EDNSALG_ECDSAP256SHA256, hasher));
    CHECK(hasher == crypto::EHASH_SHA256);

    REQUIRE(CDnssecKeys::asymmetricOf(EDNSALG_ECDSAP384SHA384, which));
    CHECK(which == crypto::EASYM_P384);
    REQUIRE(CDnssecKeys::hasherOf(EDNSALG_ECDSAP384SHA384, hasher));
    CHECK(hasher == crypto::EHASH_SHA384);

    // RFC 5702: the same RSA key type, different hashes. This is why fromPublicKey() has to be
    // told the algorithm number instead of inferring it from the key.
    REQUIRE(CDnssecKeys::asymmetricOf(EDNSALG_RSASHA256, which));
    CHECK(which == crypto::EASYM_RSA);
    REQUIRE(CDnssecKeys::hasherOf(EDNSALG_RSASHA256, hasher));
    CHECK(hasher == crypto::EHASH_SHA256);

    REQUIRE(CDnssecKeys::asymmetricOf(EDNSALG_RSASHA512, which));
    CHECK(which == crypto::EASYM_RSA);
    REQUIRE(CDnssecKeys::hasherOf(EDNSALG_RSASHA512, hasher));
    CHECK(hasher == crypto::EHASH_SHA512);

    // EdDSA hashes internally, so it reports no external hash while still being supported --
    // a true return with EHASH_UNKNOWN, not a false.
    REQUIRE(CDnssecKeys::hasherOf(EDNSALG_ED25519, hasher));
    CHECK(hasher == crypto::EHASH_UNKNOWN);
    REQUIRE(CDnssecKeys::hasherOf(EDNSALG_ED448, hasher));
    CHECK(hasher == crypto::EHASH_UNKNOWN);

    CHECK_FALSE(CDnssecKeys::asymmetricOf(EDNSALG_ECC_GOST, which));
    CHECK_FALSE(CDnssecKeys::hasherOf(EDNSALG_ECC_GOST, hasher));
}

TEST_CASE("CDnssecKeys: an ECDSA signature round-trips between r|s and DER") {
    // A plausible P-256 signature: 64 octets, neither half with a leading zero.
    uint8_t raw[64];
    for (size_t i = 0; i < 64; ++i) {
        raw[i] = uint8_t(0x11 + i);
    }

    TArray<uint8_t> der;
    REQUIRE(CDnssecKeys::signatureToNative(
        EDNSALG_ECDSAP256SHA256, SReadOnlyByteSpan(raw, sizeof(raw)), der));
    CHECK(der[0] == 0x30);                      // SEQUENCE

    TArray<uint8_t> back;
    REQUIRE(CDnssecKeys::signatureFromNative(
        EDNSALG_ECDSAP256SHA256, SReadOnlyByteSpan(der.begin(), der.size()), back));

    CHECK(back.size() == 64);
    CHECK(std::memcmp(back.begin(), raw, 64) == 0);
}

TEST_CASE("CDnssecKeys: an ECDSA signature half with leading zeros is re-padded to full width") {
    // This is the case the conversion exists for. A DER INTEGER carries no leading zero octets,
    // so an r below 2^248 encodes short; written back without left-padding it would shift s
    // left by however many octets r was missing, and RFC 6605 2 requires each half to be
    // exactly 32 octets. Both halves start with zeros here, and s ends in a zero too.
    uint8_t raw[64] = { 0 };
    raw[2] = 0x7F;                              // r = 00 00 7F ... , i.e. two leading zeros
    raw[3] = 0xAB;
    raw[32 + 0] = 0x00;                         // s = 00 00 00 C3 ... , three leading zeros
    raw[32 + 3] = 0xC3;
    raw[32 + 4] = 0x19;
    raw[63] = 0x00;                             // and a trailing zero, which must survive too

    TArray<uint8_t> der;
    REQUIRE(CDnssecKeys::signatureToNative(
        EDNSALG_ECDSAP256SHA256, SReadOnlyByteSpan(raw, sizeof(raw)), der));

    TArray<uint8_t> back;
    REQUIRE(CDnssecKeys::signatureFromNative(
        EDNSALG_ECDSAP256SHA256, SReadOnlyByteSpan(der.begin(), der.size()), back));

    CHECK(back.size() == 64);
    CHECK(std::memcmp(back.begin(), raw, 64) == 0);

    // Spelled out, so a failure says which half moved.
    CHECK(back[0] == 0x00);
    CHECK(back[1] == 0x00);
    CHECK(back[2] == 0x7F);
    CHECK(back[32] == 0x00);
    CHECK(back[35] == 0xC3);
}

TEST_CASE("CDnssecKeys: P-384 signature halves are 48 octets, not 32") {
    uint8_t raw[96];
    for (size_t i = 0; i < 96; ++i) {
        raw[i] = uint8_t(0x21 + i);
    }

    TArray<uint8_t> der;
    REQUIRE(CDnssecKeys::signatureToNative(
        EDNSALG_ECDSAP384SHA384, SReadOnlyByteSpan(raw, sizeof(raw)), der));

    TArray<uint8_t> back;
    REQUIRE(CDnssecKeys::signatureFromNative(
        EDNSALG_ECDSAP384SHA384, SReadOnlyByteSpan(der.begin(), der.size()), back));

    CHECK(back.size() == 96);
    CHECK(std::memcmp(back.begin(), raw, 96) == 0);

    // A P-256-sized signature must not be accepted as P-384.
    TArray<uint8_t> rejected;
    CHECK_FALSE(CDnssecKeys::signatureToNative(
        EDNSALG_ECDSAP384SHA384, SReadOnlyByteSpan(raw, 64), rejected));
}

TEST_CASE("CDnssecKeys: EdDSA and RSA signatures pass through unchanged") {
    uint8_t ed25519[64];
    for (size_t i = 0; i < 64; ++i) {
        ed25519[i] = uint8_t(i);
    }

    TArray<uint8_t> out;
    REQUIRE(CDnssecKeys::signatureToNative(
        EDNSALG_ED25519, SReadOnlyByteSpan(ed25519, sizeof(ed25519)), out));
    CHECK(out.size() == 64);
    CHECK(std::memcmp(out.begin(), ed25519, 64) == 0);

    // Ed448's signature is 114 octets, and a 64-octet one must not be accepted as Ed448.
    TArray<uint8_t> rejected;
    CHECK_FALSE(CDnssecKeys::signatureToNative(
        EDNSALG_ED448, SReadOnlyByteSpan(ed25519, 64), rejected));

    uint8_t ed448[114];
    std::memset(ed448, 0x5A, sizeof(ed448));
    REQUIRE(CDnssecKeys::signatureToNative(
        EDNSALG_ED448, SReadOnlyByteSpan(ed448, sizeof(ed448)), out));
    CHECK(out.size() == 114);

    // An RSA signature is one integer the width of the modulus, which DNS writes as this
    // library does -- so any length passes through.
    uint8_t rsa[64];
    std::memset(rsa, 0xC7, sizeof(rsa));
    REQUIRE(CDnssecKeys::signatureToNative(
        EDNSALG_RSASHA256, SReadOnlyByteSpan(rsa, sizeof(rsa)), out));
    CHECK(out.size() == 64);
    CHECK(std::memcmp(out.begin(), rsa, 64) == 0);

    CHECK_FALSE(CDnssecKeys::signatureToNative(
        EDNSALG_ECC_GOST, SReadOnlyByteSpan(rsa, sizeof(rsa)), rejected));
}

TEST_CASE("CDnssecKeys: a converted DNSKEY verifies a signature made with its own key pair") {
    // End to end, which is what proves the two conversions agree with the crypto underneath:
    // generate a P-256 pair, publish the public half as a DNSKEY, sign, convert the signature
    // to RRSIG form and back, and verify through the key recovered from the DNSKEY.
    crypto::IAsymmetricPtr p256 = crypto::IAsymmetric::builtIn(crypto::EASYM_P256);
    REQUIRE(p256);

    crypto::SKeyPair pair;
    REQUIRE(p256->generateKeyPair(crypto::SKeySize(256), pair) == ERET_OK);

    SDnskey published;
    REQUIRE(CDnssecKeys::fromPublicKey(
        pair.publicKey, EDNSALG_ECDSAP256SHA256, SDnskey::FLAG_ZONE_KEY, published));
    CHECK(published.publicKey.size() == 64);
    CHECK(published.flags == 256);

    uint16_t tag = 0;
    REQUIRE(published.keyTag(tag));

    // Sign a digest, as RFC 6605 has it: SHA-256 over the signed data.
    uint8_t digest[32];
    std::memset(digest, 0x3C, sizeof(digest));

    crypto::IAsymmetricContextPtr signer = p256->createContext();
    REQUIRE(signer);
    signer->keyPair(pair);

    uint8_t signatureBuffer[160];
    SByteSpan nativeSignature(signatureBuffer, sizeof(signatureBuffer));
    REQUIRE(signer->sign(SReadOnlyByteSpan(digest, sizeof(digest)), nativeSignature) == ERET_OK);

    // Out to RRSIG's r|s and back, which is the pair of conversions under test.
    TArray<uint8_t> wireSignature;
    REQUIRE(CDnssecKeys::signatureFromNative(
        EDNSALG_ECDSAP256SHA256,
        SReadOnlyByteSpan(nativeSignature.data, nativeSignature.size), wireSignature));
    CHECK(wireSignature.size() == 64);

    TArray<uint8_t> recovered;
    REQUIRE(CDnssecKeys::signatureToNative(
        EDNSALG_ECDSAP256SHA256,
        SReadOnlyByteSpan(wireSignature.begin(), wireSignature.size()), recovered));

    crypto::IPublicKeyPtr fromDnskey;
    REQUIRE(CDnssecKeys::toPublicKey(published, fromDnskey));

    // Bound with the public half only, so a verify that somehow used the private key would
    // fail here rather than pass for the wrong reason.
    crypto::IAsymmetricContextPtr verifier = p256->createContext();
    REQUIRE(verifier);
    verifier->keyPair(fromDnskey, nullptr);

    CHECK(verifier->verify(
        SReadOnlyByteSpan(digest, sizeof(digest)),
        SReadOnlyByteSpan(recovered.begin(), recovered.size())) == ERET_OK);

    // And a tampered digest must not verify, so the check above is not vacuous.
    uint8_t tampered[32];
    std::memcpy(tampered, digest, sizeof(tampered));
    tampered[0] ^= 0x01;

    CHECK(verifier->verify(
        SReadOnlyByteSpan(tampered, sizeof(tampered)),
        SReadOnlyByteSpan(recovered.begin(), recovered.size())) != ERET_OK);
}
