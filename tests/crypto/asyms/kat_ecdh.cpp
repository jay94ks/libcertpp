// RFC 5903 ("ECP Groups for IKE and IKEv2") section 8 known-answer vectors for prime-curve
// ECDH, exercised through IAsymmetricContext::deriveSharedSecret() on CEcdsa's context.
//
// Source: https://www.rfc-editor.org/rfc/rfc5903.txt, sections 8.1 (256-bit random ECP group,
// i.e. P-256) and 8.2 (384-bit random ECP group, i.e. P-384). Each section gives the initiator's
// private key i and its public key g^i = (gix, giy), the responder's r and g^r = (grx, gry), and
// the Diffie-Hellman common value (girx, giry). RFC 5903 section 7 is explicit that "the
// Diffie-Hellman shared secret value consists of the x value of the Diffie-Hellman common value"
// -- girx alone, with its length "enforced, if necessary, by prepending the value with zeros".
//
// Why these exist: an agreement test between two freshly generated key pairs (the "ECDH agree"
// cases below) only proves the two sides do the *same* thing, which a wrong answer satisfies
// just as well as a right one. These vectors are an external oracle for the answer
// itself -- including the two things easiest to get quietly wrong: returning the y-coordinate
// instead of x, and dropping the left-pad to the field width.
//
// Transcription was cross-checked by recomputing every value below from scratch in Python -- an
// independent affine short-Weierstrass implementation, with the curve constants taken from
// src/crypto/eccurve.cpp and self-checked by confirming G is on the curve and n*G is the point
// at infinity -- and confirming g^i, g^r and the common value all matched the RFC's printed
// digits for both curves before any of this was written.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <string>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    using asn1::CDer;

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

    /* Builds a SEC1 uncompressed point encoding (0x04 || X || Y) from two same-width hex
     * coordinate literals -- the form IAsymmetric::createPublicKey() takes for a prime curve. */
    std::vector<uint8_t> sec1Point(const char* xHex, const char* yHex) {
        std::vector<uint8_t> out;
        out.push_back(0x04);

        std::vector<uint8_t> x = fromHex(xHex);
        std::vector<uint8_t> y = fromHex(yHex);
        REQUIRE(x.size() == y.size());

        out.insert(out.end(), x.begin(), x.end());
        out.insert(out.end(), y.begin(), y.end());
        return out;
    }

    /* Builds the DER private key blob CEcdsa::createPrivateKey() parses --
     * SEQUENCE { version INTEGER (0), d INTEGER, publicKey OCTET STRING } -- for a scalar and
     * its matching public point, so a test can import one of the RFC's fixed private keys rather
     * than only ever using generated ones. */
    COctet privateKeyDer(const char* dHex, const std::vector<uint8_t>& sec1) {
        CBigNum d;
        REQUIRE(CBigNum::fromHex(dHex, d));

        CBuffer inner;
        REQUIRE(CDer::appendBigInteger(inner, CBigNum(uint64_t(0))));
        REQUIRE(CDer::appendBigInteger(inner, d));
        REQUIRE(CDer::appendTlv(inner, asn1::CTag(asn1::EAUTAG_STRING_OCTET, false),
            SReadOnlyByteSpan(sec1.data(), sec1.size())));

        CBuffer der;
        REQUIRE(CDer::appendSequence(der, inner.toSpan()));
        return COctet(der.toSpan());
    }

    /* Runs one direction of an ECDH exchange: binds ownPriv to a fresh context of alg and
     * derives against peerPub, returning the raw shared secret. */
    std::vector<uint8_t> derive(
        const IAsymmetricPtr& alg, const IPrivateKeyPtr& ownPriv, const IPublicKeyPtr& peerPub,
        size_t fieldBytes
    ) {
        IAsymmetricContextPtr ctx = alg->createContext();
        REQUIRE(ctx);
        ctx->keyPair(ownPriv->publicKey(), ownPriv);

        std::vector<uint8_t> out(fieldBytes + 16, 0xCC); // deliberately oversized
        SByteSpan outSpan(out.data(), out.size());
        REQUIRE(ctx->deriveSharedSecret(peerPub, outSpan) == ERET_OK);

        // deriveSharedSecret() must narrow the span to exactly one field element, never leave it
        // at the caller's larger capacity -- that narrowing is what tells the caller how many
        // bytes to feed CHkdf.
        CHECK(outSpan.size == fieldBytes);
        return std::vector<uint8_t>(out.data(), out.data() + outSpan.size);
    }

    /* Renders bytes as uppercase hex, so a CHECK failure prints something comparable to the
     * RFC's own printed digits. */
    std::string toHex(const std::vector<uint8_t>& bytes) {
        static const char* DIGITS = "0123456789ABCDEF";
        std::string out;
        for (uint8_t b : bytes) {
            out.push_back(DIGITS[b >> 4]);
            out.push_back(DIGITS[b & 0x0Fu]);
        }
        return out;
    }

    // --- RFC 5903 8.1, the 256-bit random ECP group (P-256) -------------------------------

    const char* P256_I =
        "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433";
    const char* P256_GIX =
        "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180";
    const char* P256_GIY =
        "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3";
    const char* P256_R =
        "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53";
    const char* P256_GRX =
        "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63";
    const char* P256_GRY =
        "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB";
    const char* P256_GIRX =
        "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE";
    const char* P256_GIRY =
        "522BDE0AF0D8585B8DEF9C183B5AE38F50235206A8674ECB5D98EDB20EB153A2";

    // --- RFC 5903 8.2, the 384-bit random ECP group (P-384) -------------------------------

    const char* P384_I =
        "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655"
        "E35B538041E649EE3FAEF896783AB194";
    const char* P384_GIX =
        "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6"
        "DE3AC808ACB4BDB4C88732AEE95F41AA";
    const char* P384_GIY =
        "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38E"
        "EB9FCFF3C2C947DAE69B4C634573A81C";
    const char* P384_R =
        "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942"
        "E0308312916B8ED2960E4BD55A7448FC";
    const char* P384_GRX =
        "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D"
        "0D1AC43A0336DEF96FDA41D0774A3571";
    const char* P384_GRY =
        "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FF"
        "F83FA40142209DFF5EAAD96DB9E6386C";
    const char* P384_GIRX =
        "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4"
        "D603135569B9E9D09CF5D4A270F59746";
    const char* P384_GIRY =
        "A2A9F38EF5CAFBE2347CF7EC24BDD5E624BC93BFA82771F40D1B65D06256A852"
        "C983135D4669F8792F2C1D55718AFBB4";
}

TEST_CASE("ECDH KAT: RFC 5903 8.1 (P-256), initiator derives the published shared secret") {
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    REQUIRE(p256);

    IPrivateKeyPtr ownPriv = p256->createPrivateKey(
        privateKeyDer(P256_I, sec1Point(P256_GIX, P256_GIY)));
    REQUIRE(ownPriv);

    std::vector<uint8_t> peerSec1 = sec1Point(P256_GRX, P256_GRY);
    IPublicKeyPtr peerPub = p256->createPublicKey(
        SReadOnlyByteSpan(peerSec1.data(), peerSec1.size()));
    REQUIRE(peerPub);

    CHECK(toHex(derive(p256, ownPriv, peerPub, 32)) == std::string(P256_GIRX));
}

TEST_CASE("ECDH KAT: RFC 5903 8.1 (P-256), responder derives the same shared secret") {
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    REQUIRE(p256);

    IPrivateKeyPtr ownPriv = p256->createPrivateKey(
        privateKeyDer(P256_R, sec1Point(P256_GRX, P256_GRY)));
    REQUIRE(ownPriv);

    std::vector<uint8_t> peerSec1 = sec1Point(P256_GIX, P256_GIY);
    IPublicKeyPtr peerPub = p256->createPublicKey(
        SReadOnlyByteSpan(peerSec1.data(), peerSec1.size()));
    REQUIRE(peerPub);

    CHECK(toHex(derive(p256, ownPriv, peerPub, 32)) == std::string(P256_GIRX));
}

TEST_CASE("ECDH KAT: RFC 5903 8.1's shared secret is girx, never giry") {
    // The whole point of RFC 5903 section 7's "the shared secret value consists of the x value":
    // a y-returning implementation agrees with itself perfectly and is still wrong. girx and
    // giry are both 32 bytes here, so a length check cannot distinguish them either.
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    REQUIRE(p256);

    IPrivateKeyPtr ownPriv = p256->createPrivateKey(
        privateKeyDer(P256_I, sec1Point(P256_GIX, P256_GIY)));
    REQUIRE(ownPriv);

    std::vector<uint8_t> peerSec1 = sec1Point(P256_GRX, P256_GRY);
    IPublicKeyPtr peerPub = p256->createPublicKey(
        SReadOnlyByteSpan(peerSec1.data(), peerSec1.size()));
    REQUIRE(peerPub);

    CHECK(toHex(derive(p256, ownPriv, peerPub, 32)) != std::string(P256_GIRY));
}

TEST_CASE("ECDH KAT: RFC 5903 8.2 (P-384), initiator derives the published shared secret") {
    IAsymmetricPtr p384 = IAsymmetric::builtIn(EASYM_P384);
    REQUIRE(p384);

    IPrivateKeyPtr ownPriv = p384->createPrivateKey(
        privateKeyDer(P384_I, sec1Point(P384_GIX, P384_GIY)));
    REQUIRE(ownPriv);

    std::vector<uint8_t> peerSec1 = sec1Point(P384_GRX, P384_GRY);
    IPublicKeyPtr peerPub = p384->createPublicKey(
        SReadOnlyByteSpan(peerSec1.data(), peerSec1.size()));
    REQUIRE(peerPub);

    CHECK(toHex(derive(p384, ownPriv, peerPub, 48)) == std::string(P384_GIRX));
}

TEST_CASE("ECDH KAT: RFC 5903 8.2 (P-384), responder derives the same shared secret") {
    IAsymmetricPtr p384 = IAsymmetric::builtIn(EASYM_P384);
    REQUIRE(p384);

    IPrivateKeyPtr ownPriv = p384->createPrivateKey(
        privateKeyDer(P384_R, sec1Point(P384_GRX, P384_GRY)));
    REQUIRE(ownPriv);

    std::vector<uint8_t> peerSec1 = sec1Point(P384_GIX, P384_GIY);
    IPublicKeyPtr peerPub = p384->createPublicKey(
        SReadOnlyByteSpan(peerSec1.data(), peerSec1.size()));
    REQUIRE(peerPub);

    CHECK(toHex(derive(p384, ownPriv, peerPub, 48)) == std::string(P384_GIRX));
}

TEST_CASE("ECDH KAT: RFC 5903 8.2's shared secret is girx, never giry") {
    IAsymmetricPtr p384 = IAsymmetric::builtIn(EASYM_P384);
    REQUIRE(p384);

    IPrivateKeyPtr ownPriv = p384->createPrivateKey(
        privateKeyDer(P384_I, sec1Point(P384_GIX, P384_GIY)));
    REQUIRE(ownPriv);

    std::vector<uint8_t> peerSec1 = sec1Point(P384_GRX, P384_GRY);
    IPublicKeyPtr peerPub = p384->createPublicKey(
        SReadOnlyByteSpan(peerSec1.data(), peerSec1.size()));
    REQUIRE(peerPub);

    CHECK(toHex(derive(p384, ownPriv, peerPub, 48)) != std::string(P384_GIRY));
}

TEST_CASE("ECDH KAT: a shared secret whose x starts with a zero byte keeps its leading zero") {
    // RFC 5903 section 7: the component length "is enforced, if necessary, by prepending the
    // value with zeros". Neither published vector exercises that -- girx begins 0xD6 for P-256
    // and 0x11 for P-384 -- so an implementation that emitted CBigNum's own minimal big-endian
    // form would pass both and still disagree with every other peer roughly one exchange in 256.
    //
    // This case was constructed for it: searching d = 1.. against RFC 5903 8.1's g^r as the
    // fixed peer key, d = 196 is the first scalar whose d*(g^r) has an x-coordinate below
    // 2^248. Both the scalar's public point and the expected secret were computed in the same
    // independent Python implementation that reproduced the RFC's own vectors.
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    REQUIRE(p256);

    IPrivateKeyPtr ownPriv = p256->createPrivateKey(privateKeyDer("C4", sec1Point(
        "AFEC84D94A58B0F648225C3C4AB612C64E684806EF09C1327208DD0DA0B4D1A1",
        "F88A2E2ADC846350313F631F83D010FB54B2F4DFF24FB09D6161FBD1B1E8BA60")));
    REQUIRE(ownPriv);

    std::vector<uint8_t> peerSec1 = sec1Point(P256_GRX, P256_GRY);
    IPublicKeyPtr peerPub = p256->createPublicKey(
        SReadOnlyByteSpan(peerSec1.data(), peerSec1.size()));
    REQUIRE(peerPub);

    std::vector<uint8_t> secret = derive(p256, ownPriv, peerPub, 32);
    REQUIRE(secret.size() == 32);
    CHECK(secret[0] == 0x00);
    CHECK(toHex(secret) ==
        std::string("0095A7AACAD904297245FEF3033ECFCDD3B717B1157B433A6A1756A269980E97"));
}

TEST_CASE("ECDH agree: two freshly generated P-256 key pairs derive the same secret") {
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    REQUIRE(p256);

    SKeyPair alice, bob;
    REQUIRE(p256->generateKeyPair(256, alice) == ERET_OK);
    REQUIRE(p256->generateKeyPair(256, bob) == ERET_OK);
    REQUIRE(alice);
    REQUIRE(bob);

    std::vector<uint8_t> fromAlice = derive(p256, alice.privateKey, bob.publicKey, 32);
    std::vector<uint8_t> fromBob = derive(p256, bob.privateKey, alice.publicKey, 32);

    CHECK(toHex(fromAlice) == toHex(fromBob));

    // A secret that came out all-zero would compare equal to itself and tell us nothing.
    bool anyNonZero = false;
    for (uint8_t b : fromAlice) {
        anyNonZero = anyNonZero || b != 0;
    }
    CHECK(anyNonZero);
}

TEST_CASE("ECDH agree: two freshly generated P-384 key pairs derive the same secret") {
    IAsymmetricPtr p384 = IAsymmetric::builtIn(EASYM_P384);
    REQUIRE(p384);

    SKeyPair alice, bob;
    REQUIRE(p384->generateKeyPair(384, alice) == ERET_OK);
    REQUIRE(p384->generateKeyPair(384, bob) == ERET_OK);
    REQUIRE(alice);
    REQUIRE(bob);

    std::vector<uint8_t> fromAlice = derive(p384, alice.privateKey, bob.publicKey, 48);
    std::vector<uint8_t> fromBob = derive(p384, bob.privateKey, alice.publicKey, 48);

    CHECK(toHex(fromAlice) == toHex(fromBob));

    bool anyNonZero = false;
    for (uint8_t b : fromAlice) {
        anyNonZero = anyNonZero || b != 0;
    }
    CHECK(anyNonZero);
}

TEST_CASE("ECDH agree: the operation covers every prime curve CEcCurve ships, not just P-256/384") {
    // Nothing in deriveSharedSecret() is specific to P-256/P-384 -- it reads p, n and
    // fieldByteLen() off whichever CEcCurve the bound private key carries -- so the Brainpool
    // and secp256k1 curves get it for free. Spot-checked here so that stays true.
    struct { EAsymmetrics alg; SKeySize bits; size_t fieldBytes; } CASES[] = {
        { EASYM_P192, 192, 24 },
        { EASYM_P521, 521, 66 },
        { EASYM_SECP256K1, 256, 32 },
        { EASYM_BPOOL256R1, 256, 32 },
        { EASYM_BPOOL320T1, 320, 40 },
    };

    for (const auto& c : CASES) {
        IAsymmetricPtr alg = IAsymmetric::builtIn(c.alg);
        REQUIRE(alg);

        SKeyPair alice, bob;
        REQUIRE(alg->generateKeyPair(c.bits, alice) == ERET_OK);
        REQUIRE(alg->generateKeyPair(c.bits, bob) == ERET_OK);

        std::vector<uint8_t> fromAlice = derive(alg, alice.privateKey, bob.publicKey, c.fieldBytes);
        std::vector<uint8_t> fromBob = derive(alg, bob.privateKey, alice.publicKey, c.fieldBytes);
        CHECK(toHex(fromAlice) == toHex(fromBob));
    }
}

TEST_CASE("ECDH reject: a peer point from a different curve of the same field width") {
    // The invalid-curve attack, in its hardest-to-catch form. A secp256k1 public key is a
    // genuine, on-its-own-curve point whose coordinates are (almost always) below P-256's p, so
    // only the curve-equation check separates it from a legitimate P-256 key -- secp256k1 and
    // P-256 differ in a and b, not in field width. Accepting it would put d*Q on a curve of
    // different (and in the general attack, deliberately smooth) order, from which d is
    // recoverable piece by piece.
    //
    // Note that this reaches deriveSharedSecret()'s own checks rather than being filtered at
    // parse time: both algorithms build the same concrete EcPublicKey class, so the
    // dynamic_pointer_cast on the peer key succeeds and only the point validation stands in the
    // way.
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    IAsymmetricPtr k1 = IAsymmetric::builtIn(EASYM_SECP256K1);
    REQUIRE(p256);
    REQUIRE(k1);

    SKeyPair mine, foreign;
    REQUIRE(p256->generateKeyPair(256, mine) == ERET_OK);
    REQUIRE(k1->generateKeyPair(256, foreign) == ERET_OK);

    IAsymmetricContextPtr ctx = p256->createContext();
    REQUIRE(ctx);
    ctx->keyPair(mine.publicKey, mine.privateKey);

    std::vector<uint8_t> out(64, 0xCC);
    SByteSpan outSpan(out.data(), out.size());
    CHECK(ctx->deriveSharedSecret(foreign.publicKey, outSpan) == ERET_KEY_PARAM);
}

TEST_CASE("ECDH reject: a peer point whose coordinates exceed the curve's p") {
    // Same attack, cruder shape: a P-384 public key offered to a P-256 context. Its 384-bit
    // coordinates trip the 0 <= x, y < p range check before the curve equation is reached.
    //
    // Honest caveat: this case does not *isolate* that range check -- disabling it leaves this
    // test passing, because a point whose coordinates exceed p also fails the curve equation mod
    // p. Nothing reachable through the public API isolates it, since createPublicKey() refuses an
    // out-of-range coordinate on decode and a SEC1 encoding is only wide enough for one. The
    // check stays because deriveSharedSecret() takes an IPublicKeyPtr, not bytes, and should not
    // depend on where that pointer came from.
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    IAsymmetricPtr p384 = IAsymmetric::builtIn(EASYM_P384);
    REQUIRE(p256);
    REQUIRE(p384);

    SKeyPair mine, foreign;
    REQUIRE(p256->generateKeyPair(256, mine) == ERET_OK);
    REQUIRE(p384->generateKeyPair(384, foreign) == ERET_OK);

    IAsymmetricContextPtr ctx = p256->createContext();
    REQUIRE(ctx);
    ctx->keyPair(mine.publicKey, mine.privateKey);

    std::vector<uint8_t> out(64, 0xCC);
    SByteSpan outSpan(out.data(), out.size());
    CHECK(ctx->deriveSharedSecret(foreign.publicKey, outSpan) == ERET_KEY_PARAM);
}

TEST_CASE("ECDH reject: an off-curve, infinite, or out-of-range peer encoding never becomes a key") {
    // deriveSharedSecret() re-checks all three of these itself, but a peer value arriving over
    // the wire is parsed first, and createPublicKey() already refuses to build a key from any of
    // them -- so for the on-the-wire path the rejection happens one layer earlier. Asserted here
    // so that layer can't quietly stop rejecting them and leave deriveSharedSecret() as the only
    // guard.
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    REQUIRE(p256);

    // (a) A point not on the curve: RFC 5903 8.1's g^r with one bit flipped in x.
    std::vector<uint8_t> offCurve = sec1Point(
        "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF62",
        P256_GRY);
    CHECK(!p256->createPublicKey(SReadOnlyByteSpan(offCurve.data(), offCurve.size())));

    // (b) The point at infinity, in its SEC1 single-zero-byte encoding. There is no way to build
    // an EcPublicKey holding it, which is why deriveSharedSecret()'s own infinity check is
    // defence in depth rather than the only line.
    const uint8_t infinity[1] = { 0x00 };
    CHECK(!p256->createPublicKey(SReadOnlyByteSpan(infinity, sizeof(infinity))));

    // (c) A coordinate >= p: x = p itself (which is congruent to 0, so a mod-p curve-equation
    // test alone would not catch it), paired with g's own y.
    std::vector<uint8_t> xEqualsP = sec1Point(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    CHECK(!p256->createPublicKey(SReadOnlyByteSpan(xEqualsP.data(), xEqualsP.size())));
}

TEST_CASE("ECDH reject: a missing private key, a missing peer key, and too small an output span") {
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    REQUIRE(p256);

    SKeyPair mine, theirs;
    REQUIRE(p256->generateKeyPair(256, mine) == ERET_OK);
    REQUIRE(p256->generateKeyPair(256, theirs) == ERET_OK);

    std::vector<uint8_t> out(64, 0xCC);

    // No bound private key at all.
    IAsymmetricContextPtr bare = p256->createContext();
    REQUIRE(bare);
    SByteSpan bareSpan(out.data(), out.size());
    CHECK(bare->deriveSharedSecret(theirs.publicKey, bareSpan) == ERET_KEY_EMPTY);

    // Public key bound, private key absent -- the verify()-only shape.
    IAsymmetricContextPtr pubOnly = p256->createContext();
    REQUIRE(pubOnly);
    pubOnly->keyPair(mine.publicKey, nullptr);
    SByteSpan pubOnlySpan(out.data(), out.size());
    CHECK(pubOnly->deriveSharedSecret(theirs.publicKey, pubOnlySpan) == ERET_KEY_EMPTY);

    IAsymmetricContextPtr ctx = p256->createContext();
    REQUIRE(ctx);
    ctx->keyPair(mine.publicKey, mine.privateKey);

    // Null peer key.
    SByteSpan nullPeerSpan(out.data(), out.size());
    CHECK(ctx->deriveSharedSecret(nullptr, nullPeerSpan) == ERET_KEY_EMPTY);

    // A peer key from a different algorithm family entirely (X25519, not an EcPublicKey).
    IAsymmetricPtr x25519 = IAsymmetric::builtIn(EASYM_X25519);
    REQUIRE(x25519);
    SKeyPair montgomery;
    REQUIRE(x25519->generateKeyPair(256, montgomery) == ERET_OK);
    SByteSpan wrongFamilySpan(out.data(), out.size());
    CHECK(ctx->deriveSharedSecret(montgomery.publicKey, wrongFamilySpan) == ERET_KEY_FORMAT);

    // One byte short of a field element.
    SByteSpan tooSmall(out.data(), 31);
    CHECK(ctx->deriveSharedSecret(theirs.publicKey, tooSmall) == ERET_NOSPC);
}

TEST_CASE("ECDH: the derived secret feeds CHkdf, which is how a caller turns it into keys") {
    // RFC 5903's shared secret is raw x, not key material -- SP 800-56A leaves the KDF to the
    // protocol. This is the end-to-end shape an IKEv2 consumer actually uses, asserted here so
    // the span deriveSharedSecret() hands back is known to be directly usable as HKDF input.
    IAsymmetricPtr p256 = IAsymmetric::builtIn(EASYM_P256);
    REQUIRE(p256);

    SKeyPair alice, bob;
    REQUIRE(p256->generateKeyPair(256, alice) == ERET_OK);
    REQUIRE(p256->generateKeyPair(256, bob) == ERET_OK);

    std::vector<uint8_t> fromAlice = derive(p256, alice.privateKey, bob.publicKey, 32);
    std::vector<uint8_t> fromBob = derive(p256, bob.privateKey, alice.publicKey, 32);

    const uint8_t salt[4] = { 'I', 'K', 'E', 'v' };
    const uint8_t info[5] = { 's', 'k', '_', 'a', 'i' };

    std::vector<uint8_t> aliceKeys(32, 0), bobKeys(32, 0xFF);
    REQUIRE(CHkdf::derive(
        EHASH_SHA256, SReadOnlyByteSpan(salt, sizeof(salt)),
        SReadOnlyByteSpan(fromAlice.data(), fromAlice.size()),
        SReadOnlyByteSpan(info, sizeof(info)),
        SByteSpan(aliceKeys.data(), aliceKeys.size())) == ERET_OK);
    REQUIRE(CHkdf::derive(
        EHASH_SHA256, SReadOnlyByteSpan(salt, sizeof(salt)),
        SReadOnlyByteSpan(fromBob.data(), fromBob.size()),
        SReadOnlyByteSpan(info, sizeof(info)),
        SByteSpan(bobKeys.data(), bobKeys.size())) == ERET_OK);

    CHECK(toHex(aliceKeys) == toHex(bobKeys));
}
