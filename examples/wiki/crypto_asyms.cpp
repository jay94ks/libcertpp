#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;

// Each example is one function, preceded by a `// === <TypeName> ===` marker. The function body
// is what gets published as that type's example, dedented, so write it as the code a caller
// would write -- not as a test. See the brief for the rules.

// === DSA ===
// Generates a 2048-bit DSA key pair, stores the private half, and reloads it. generateKeyPair()
// produces fresh domain parameters too, and the serialized private key carries p, q and g with
// it, so nothing else has to be kept alongside it.
void exampleDSA() {
    DSA dsa;

    SKeyPair pair;
    if (dsa.generateKeyPair(SKeySize(2048), pair) != ERET_OK) {
        return;         // ERET_AGAIN here means only "call it again"
    }

    COctet stored;
    if (pair.privateKey->serialize(stored) != ERET_OK) {
        return;
    }

    // .toSpan() is needed here: IAsymmetric's COctet overload is hidden by DSA's own
    // override of the span one, so it is reachable only through an IAsymmetricPtr.
    IPrivateKeyPtr reloaded = dsa.createPrivateKey(stored.toSpan());
    if (!reloaded) {
        return;
    }

    // createPrivateKey() only parses. checkPrivateKey() is what says the domain parameters and
    // the key material agree, and -- unlike generateKeyPair() -- it reports why when they do
    // not, since retrying a deserialized key is not a coherent response.
    if (dsa.checkPrivateKey(reloaded) != ERET_OK) {
        return;
    }
}

// === CEcdsa ===
// Agrees an RFC 5903 shared secret over P-256 and turns it into a session key. Key agreement
// lives on the ECDSA class because a prime-curve ECDH key pair *is* an ECDSA key pair -- the
// same context would sign with this key too -- and the x-coordinate it yields is not a key
// until HKDF has run over it. The scalar multiplication is not constant-time; prefer X25519
// where the protocol lets you choose.
void exampleCEcdsa(const IPublicKeyPtr& peerKey, const SReadOnlyByteSpan& info) {
    CEcdsa ecdsa(ECURVE_P256);      // one instance per curve; keySizes() accepts only 256
    SKeyPair mine;
    if (ecdsa.generateKeyPair(SKeySize(256), mine) != ERET_OK) {
        return;
    }

    IAsymmetricContextPtr ctx = ecdsa.createContext();
    ctx->keyPair(mine);

    uint8_t secret[66];
    SByteSpan shared(secret, sizeof(secret));
    if (ctx->deriveSharedSecret(peerKey, shared) != ERET_OK) {
        return;
    }

    // shared.size is the curve's field width, not sizeof(secret).
    uint8_t sessionKey[32];
    ERetCode eRet = CHkdf::derive(EHASH_SHA256, SReadOnlyByteSpan(),
        SReadOnlyByteSpan(shared.data, shared.size), info,
        SByteSpan(sessionKey, sizeof(sessionKey)));
    CSecure::zero(shared);
    if (eRet != ERET_OK) {
        return;
    }
}

// === CEcdsa2 ===
// Signs a SHA-256 digest over the binary curve B-233 and verifies it from the public half
// alone. Unlike Ed25519/ML-DSA this really is a digest, and the output span comes back narrowed
// to the DER signature's real length -- passing sizeof(buf) onward would hash trailing garbage.
void exampleCEcdsa2(const SReadOnlyByteSpan& sha256Digest) {
    CEcdsa2 ecdsa(ECURVE2_B233);    // keySizes() accepts only the field degree, 233
    SKeyPair pair;
    if (ecdsa.generateKeyPair(SKeySize(233), pair) != ERET_OK) {
        return;
    }

    IAsymmetricContextPtr ctx = ecdsa.createContext();
    ctx->keyPair(pair);

    uint8_t buf[128];
    SByteSpan signature(buf, sizeof(buf));
    if (ctx->sign(sha256Digest, signature) != ERET_OK) {
        return;
    }

    // SEQUENCE { r, s } is shorter than the buffer, so carry signature.size forward.
    IAsymmetricContextPtr verifier = ecdsa.createContext();
    verifier->keyPair(pair.publicKey, nullptr);
    if (verifier->verify(sha256Digest, SReadOnlyByteSpan(signature.data, signature.size))
        != ERET_OK) {
        return;
    }
}

// === Ed25519 ===
// Signs a message with Ed25519. The parameter named `digest` takes the message itself, not a
// hash of it -- `sizeOfDigest() == 0` is how the context says so -- because pure EdDSA hashes
// internally; feeding it a SHA-256 value signs those 32 bytes as the message instead.
void exampleEd25519(const SReadOnlyByteSpan& message) {
    Ed25519 ed;

    SKeyPair pair;
    if (ed.generateKeyPair(SKeySize(256), pair) != ERET_OK) {
        return;
    }

    IAsymmetricContextPtr ctx = ed.createContext();
    ctx->keyPair(pair);

    if (ctx->sizeOfDigest() != 0) {
        return;         // zero means "no digest to compute, pass the message"
    }

    uint8_t sig[64];    // the raw R || S of RFC 8032 5.1.6
    SByteSpan signature(sig, sizeof(sig));
    if (ctx->sign(message, signature) != ERET_OK) {
        return;
    }

    if (ctx->verify(message, SReadOnlyByteSpan(signature.data, signature.size)) != ERET_OK) {
        return;
    }
}

// === Ed448 ===
// Generates an Ed448 key pair and signs a message with it. The size is 456 bits, not 448 -- an
// Ed448 key is 57 bytes -- and a wrong size is reported as ERET_KEY_SIZE rather than rounded to
// the nearest one the algorithm accepts.
void exampleEd448(const SReadOnlyByteSpan& message) {
    Ed448 ed;

    SKeyPair pair;
    if (ed.generateKeyPair(SKeySize(456), pair) != ERET_OK) {
        return;
    }

    IAsymmetricContextPtr ctx = ed.createContext();
    ctx->keyPair(pair);

    // Like Ed25519, the "digest" parameter carries the message; Ed448 hashes it internally
    // with SHAKE256 under RFC 8032's dom4 prefix.
    uint8_t sig[114];
    SByteSpan signature(sig, sizeof(sig));
    if (ctx->sign(message, signature) != ERET_OK) {
        return;
    }

    if (ctx->verify(message, SReadOnlyByteSpan(signature.data, signature.size)) != ERET_OK) {
        return;
    }
}

// === CGost3410 ===
// Verifies a GOST R 34.10-2012 signature made by someone else. Every byte order here is a trap:
// the public key is x || y with each half *little*-endian, while the signature is s || r -- s
// first -- with each half *big*-endian and no DER SEQUENCE wrapper. This is not ECDSA with a
// different curve, and the digest must come from Streebog.
void exampleCGost3410(const SReadOnlyByteSpan& peerKey, const SReadOnlyByteSpan& signature,
    const SReadOnlyByteSpan& streebog256Digest)
{
    CGost3410 gost(ECURVE_GOST256B);

    // 64 bytes for a 256-bit parameter set: two 32-byte little-endian coordinates (RFC 9215
    // 2.4), not a SEC1 uncompressed point.
    IPublicKeyPtr peer = gost.createPublicKey(peerKey);
    if (!peer) {
        return;
    }

    // Verification needs the public half only, so bind it with no private key beside it.
    IAsymmetricContextPtr ctx = gost.createContext();
    ctx->keyPair(peer, nullptr);

    // 64 bytes of s || r, each big-endian. deriveSharedSecret() reports ERET_NOTSUP here --
    // VKO key agreement is not implemented.
    if (ctx->verify(streebog256Digest, signature) != ERET_OK) {
        return;
    }
}

// === CMlDsa ===
// Signs a message with ML-DSA-65. As with Ed25519/Ed448 the `digest` parameter is the message
// -- `sizeOfDigest()` stays 0 -- and signing is hedged, so two signatures over the same message
// differ and both verify. What gets signed is FIPS 204's external form, `0x00 || 0x00 ||
// message`, which is what RFC 9881 requires of an X.509 signature.
void exampleCMlDsa(const SReadOnlyByteSpan& message) {
    CMlDsa mldsa(EASYM_MLDSA65);    // the size is the set's name, 65, not a modulus width
    SKeyPair pair;
    if (mldsa.generateKeyPair(SKeySize(65), pair) != ERET_OK) {
        return;
    }

    IAsymmetricContextPtr ctx = mldsa.createContext();
    ctx->keyPair(pair);

    uint8_t buf[3309];              // ML-DSA-65's signature size
    if (ctx->sizeOfSign() > sizeof(buf) || ctx->sizeOfDigest() != 0) {
        return;
    }

    SByteSpan signature(buf, sizeof(buf));
    if (ctx->sign(message, signature) != ERET_OK) {
        return;
    }

    if (ctx->verify(message, SReadOnlyByteSpan(signature.data, signature.size)) != ERET_OK) {
        return;
    }
}

// === RSA ===
// Signs a SHA-256 digest with EMSA-PKCS1-v1_5. The hash identifier that goes into the
// DigestInfo is inferred from the digest's *length*, never passed in, so only the five lengths
// this library ships hashers for are accepted -- a truncated or non-standard digest is rejected
// rather than signed under the wrong AlgorithmIdentifier.
void exampleRSA(const SReadOnlyByteSpan& sha256Digest) {
    RSA rsa;

    SKeyPair pair;
    if (rsa.generateKeyPair(SKeySize(2048), pair) != ERET_OK) {
        return;         // keySizes() runs 512-8192 in 8-bit steps
    }

    IAsymmetricContextPtr ctx = rsa.createContext();
    ctx->keyPair(pair);

    uint8_t buf[1024];
    SByteSpan signature(buf, sizeof(buf));
    if (ctx->sign(sha256Digest, signature) != ERET_OK) {
        return;
    }

    // signature.size is the modulus width, 256 bytes here -- not sizeof(buf).
    IAsymmetricContextPtr verifier = rsa.createContext();
    verifier->keyPair(pair.publicKey, nullptr);
    if (verifier->verify(sha256Digest, SReadOnlyByteSpan(signature.data, signature.size))
        != ERET_OK) {
        return;
    }
}

// === X25519 ===
// Agrees a shared secret with a peer and derives a session key from it. deriveSharedSecret() is
// the only operation this algorithm has -- sign()/verify() report ERET_NOTSUP -- and the raw
// secret is never a key, so it goes through HKDF and is then wiped. Unlike the prime-curve
// agreement on CEcdsa, this ladder is constant-time.
void exampleX25519(const SReadOnlyByteSpan& peerU, const SReadOnlyByteSpan& info) {
    X25519 x;

    SKeyPair mine;
    if (x.generateKeyPair(SKeySize(256), mine) != ERET_OK) {
        return;
    }

    IPublicKeyPtr peer = x.createPublicKey(peerU);  // the raw 32-byte u-coordinate
    if (!peer) {
        return;
    }

    IAsymmetricContextPtr ctx = x.createContext();
    ctx->keyPair(mine);

    uint8_t secret[32];
    SByteSpan shared(secret, sizeof(secret));
    if (ctx->deriveSharedSecret(peer, shared) != ERET_OK) {
        return;
    }

    uint8_t sessionKey[32];
    ERetCode eRet = CHkdf::derive(EHASH_SHA256, SReadOnlyByteSpan(),
        SReadOnlyByteSpan(shared.data, shared.size), info,
        SByteSpan(sessionKey, sizeof(sessionKey)));
    CSecure::zero(shared);
    if (eRet != ERET_OK) {
        return;
    }
}

// === CMlKem ===
// Decapsulates a received ciphertext through the raw-span algorithm. decapsulate() returning
// true says only that the spans were the right size: a corrupted ciphertext yields a
// well-formed but unrelated shared secret rather than an error, which is the Fujisaki-Okamoto
// implicit rejection ML-KEM's security rests on. Whether the peer holds the same secret is
// settled by the transcript MAC that follows, never here.
void exampleCMlKem(const SReadOnlyByteSpan& dk, const SReadOnlyByteSpan& ciphertext) {
    static constexpr SMlKemParams params = SMlKemParams::mlKem768();

    // A decapsulation key that arrived from elsewhere is checked first: this verifies its
    // length and that the H(ek) it embeds matches the encapsulation key it carries.
    if (!CMlKem::checkDecapsulationKey(params, dk)) {
        return;
    }

    uint8_t ss[params.sharedSecretBytes()];
    if (!CMlKem::decapsulate(params, dk, ciphertext, SByteSpan(ss, sizeof(ss)))) {
        return;         // only a wrong-sized span or a non-FIPS-203 parameter set gets here
    }

    // Bind ss to the handshake transcript via a KDF; do not compare it against anything to
    // decide whether the ciphertext was genuine, and wipe it when the session ends.
    CSecure::zero(SByteSpan(ss, sizeof(ss)));
}

// === CMlKemSampler ===
// Expands one entry of ML-KEM's public matrix A. The index order is the whole point: FIPS 203
// computes A[i][j] as SampleNTT(rho || j || i), transposed relative to the natural loop order,
// and this function appends exactly the two bytes it is handed, in the order it is handed them.
void exampleCMlKemSampler(const SReadOnlyByteSpan& rho, size_t i, size_t j) {
    // rho is the 32-byte seed out of G(d || k), and j goes in ahead of i.
    SMlKemPoly aHat;
    if (!CMlKemSampler::sampleNtt(rho, static_cast<uint8_t>(j), static_cast<uint8_t>(i), aHat)) {
        return;         // rho was not 32 bytes, or the SHAKE128 XOF failed
    }

    // How much of the XOF stream that consumed is not knowable in advance -- it rejection-
    // samples until 256 coefficients are accepted -- which is why SHAKE128::squeeze() exists.
    // What comes back is an NTT-domain value, 128 degree-1 blocks rather than a polynomial,
    // even though the type is the same SMlKemPoly a polynomial uses; nothing in it records
    // which, so tracking that is the caller's job, as it is in FIPS 203 itself.
}

// === SMlKemParams ===
// Encapsulates under whichever parameter set an EKems names, taking every length off the
// parameter set instead of writing it down -- a mistyped key or ciphertext length stays
// internally consistent and is caught only by an external test vector. isValid() guards a set
// that came from anywhere but these accessors, since a larger k would overflow the
// fixed-capacity buffers inside. The message must be fresh CSPRNG output.
void exampleSMlKemParams(EKems which, const SReadOnlyByteSpan& ek,
    const SReadOnlyByteSpan& message)
{
    SMlKemParams params{};
    if (!MLKEM::paramsOf(which, params) || !params.isValid()) {
        return;         // which named no ML-KEM parameter set
    }

    // ekBytes() is 384*k + 32: 800, 1184 or 1568. checkEncapsulationKey() applies the same
    // figure, and also rejects an encoding whose t-hat segments are not all below q.
    if (!CMlKem::checkEncapsulationKey(params, ek)) {
        return;
    }

    // Two buffers wide enough for any set, each narrowed to the width this one needs --
    // CMlKem refuses a span of any other length rather than writing a prefix of it.
    uint8_t ctBuf[SMlKemParams::maxCiphertextBytes()], ssBuf[32];
    SByteSpan ciphertext(ctBuf, params.ciphertextBytes());
    SByteSpan sharedSecret(ssBuf, params.sharedSecretBytes());
    if (!CMlKem::encapsulate(params, ek, message, ciphertext, sharedSecret)) {
        return;
    }

    CSecure::zero(sharedSecret);
}

// === SMlKemPoly ===
// Samples one noise polynomial and measures how small its coefficients are. They come back
// reduced into [0, MODULUS), so a CBD sample of -1 reads as 3328 rather than as a negative
// int16_t -- centre them before measuring or comparing anything.
void exampleSMlKemPoly(const SReadOnlyByteSpan& prfOutput) {
    SMlKemPoly noise;
    if (!CMlKemSampler::samplePolyCbd(2, prfOutput, noise)) {
        return;         // eta out of range, or prfOutput was not 64*eta = 128 bytes
    }

    int32_t norm = 0;
    for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS; ++i) {
        int32_t coeff = noise.coeffs[i];
        if (coeff > SMlKemPoly::MODULUS / 2) {
            coeff -= SMlKemPoly::MODULUS;       // the representative in (-q/2, q/2]
        }

        coeff = coeff < 0 ? -coeff : coeff;
        norm = coeff > norm ? coeff : norm;
    }

    // norm is at most eta, which is what makes these the "small" error terms Module-LWE
    // needs. The same 256-coefficient layout also carries NTT-domain values -- 128 degree-1
    // blocks -- and nothing in the struct says which one an instance holds.
    if (norm > 2) {
        return;
    }
}

// === MLKEM ===
// Encapsulates a fresh shared secret to a peer's ML-KEM-768 public key. encapsulate() chooses
// the secret itself -- there is no plaintext to supply -- and both output spans come back
// narrowed, so the ciphertext to transmit is ciphertext.size bytes long, not sizeof(ct).
void exampleMLKEM(const SReadOnlyByteSpan& info) {
    MLKEM kem(EKEM_MLKEM768);
    SKemKeyPair pair;
    if (kem.generateKeyPair(SKeySize(768), pair) != ERET_OK) {
        return;         // 768 is the set's name, and the only size keySizes() accepts
    }

    IKemContextPtr ctx = kem.createContext();
    ctx->keyPair(pair.publicKey, nullptr);  // encapsulating needs the public half alone

    uint8_t ct[SMlKemParams::maxCiphertextBytes()], ss[32];
    SByteSpan ciphertext(ct, sizeof(ct));
    SByteSpan sharedSecret(ss, sizeof(ss));
    if (ctx->encapsulate(ciphertext, sharedSecret) != ERET_OK) {
        return;
    }

    // The secret is not a key, and decapsulate() succeeding on the far side proves nothing
    // about the ciphertext -- bind both to the transcript through the KDF.
    uint8_t key[32];
    ERetCode eRet = CHkdf::derive(EHASH_SHA256, SReadOnlyByteSpan(),
        SReadOnlyByteSpan(sharedSecret.data, sharedSecret.size), info,
        SByteSpan(key, sizeof(key)));
    CSecure::zero(sharedSecret);
    if (eRet != ERET_OK) {
        return;
    }
}
