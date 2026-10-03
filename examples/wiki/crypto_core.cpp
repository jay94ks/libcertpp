#include <certpp.hpp>
#include <cstring>

using namespace certpp;

// Each example is one function, preceded by a `// === <TypeName> ===` marker. The function body
// is what gets published as that type's example, dedented, so write it as the code a caller
// would write -- not as a test. See the brief for the rules.

// === EHashers ===
// Selects which hasher IHasher::create() builds. Store the algorithm's OID or name if you need
// to persist the choice -- never the enumerator's integer value, which is a build-time detail
// that crosses an ABI boundary as new hashers are appended.
void exampleEHashers(crypto::EHashers which, const SReadOnlyByteSpan& message) {
    crypto::IHasherPtr hasher;
    if (crypto::IHasher::create(which, hasher) != ERET_OK) {
        return; // EHASH_UNKNOWN, EHASH_MAX and anything unimplemented land here
    }

    TArray<uint8_t> digest;
    digest.resize(hasher->byteWidth());

    hasher->push(message);
    if (!hasher->finish(SByteSpan(digest.begin(), digest.size()))) {
        return;
    }
}

// === IHasher ===
// Streams a message through a built-in hasher, obtained from the create() factory rather than
// constructed. byteWidth() is the digest length to allocate, and push() may be called as often
// as the data arrives before a single finish().
void exampleIHasher(const SReadOnlyByteSpan& header, const SReadOnlyByteSpan& body) {
    crypto::IHasherPtr hasher;
    if (crypto::IHasher::create(crypto::EHASH_SHA256, hasher) != ERET_OK) {
        return;
    }

    if (hasher->push(header) != header.size || hasher->push(body) != body.size) {
        return;
    }

    uint8_t digest[64];
    SByteSpan out(digest, hasher->byteWidth());
    if (!hasher->finish(out)) {
        return;
    }

    // reset() starts a fresh message on the same instance; no reallocation.
    hasher->reset();
}

// === CHmac ===
// Checks a received tag with verify(), which compares in time that depends only on the tag's
// length. finish() plus memcmp is a forgery oracle: it leaks how long a prefix the attacker
// guessed right, which is enough to build a valid tag one byte at a time.
void exampleCHmac(
    const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message,
    const SReadOnlyByteSpan& receivedTag
) {
    if (!crypto::CHmac::verify(crypto::EHASH_SHA256, key, message, receivedTag)) {
        return; // forged, truncated to a length you did not expect, or the wrong key
    }

    // Producing a tag of our own: reset() keys it, push() per chunk, finish() for the tag.
    crypto::CHmac hmac;
    if (hmac.reset(crypto::EHASH_SHA256, key) != ERET_OK) {
        return; // ERET_NOTSUP for SHAKE128/SHAKE256, which RFC 2104 is not defined over
    }

    hmac.push(message);

    uint8_t tag[crypto::CHmac::MAX_BLOCK_BYTES];
    SByteSpan out(tag, hmac.byteWidth());
    if (!hmac.finish(out)) {
        return;
    }
}

// === CHkdf ===
// Derives two independent directional keys from one shared secret. Mind the argument order --
// the salt comes *before* the input keying material -- and give each use a different `info`
// label, or both directions derive the same bytes and a record can be replayed at its sender.
void exampleCHkdf(const SReadOnlyByteSpan& sharedSecret, const SReadOnlyByteSpan& salt) {
    const uint8_t clientLabel[] = "certpp client write";
    const uint8_t serverLabel[] = "certpp server write";
    SReadOnlyByteSpan clientInfo(clientLabel, sizeof(clientLabel) - 1);
    SReadOnlyByteSpan serverInfo(serverLabel, sizeof(serverLabel) - 1);

    uint8_t clientKey[32];
    uint8_t serverKey[32];
    SByteSpan clientOut(clientKey, sizeof(clientKey));
    SByteSpan serverOut(serverKey, sizeof(serverKey));

    // One secret and one salt, two different info labels -- so two unrelated keys.
    if (crypto::CHkdf::derive(
            crypto::EHASH_SHA256, salt, sharedSecret, clientInfo, clientOut) == ERET_OK &&
        crypto::CHkdf::derive(
            crypto::EHASH_SHA256, salt, sharedSecret, serverInfo, serverOut) == ERET_OK) {
        // ... key the two transport directions.
    }

    CSecure::zero(clientOut);
    CSecure::zero(serverOut);
}

// === CRng ===
// Fills a nonce and a PKCS#1 v1.5 padding string from the OS CSPRNG. fillNonZero() is the
// variant that padding needs, where a zero byte would terminate the padding string early.
void exampleCRng() {
    uint8_t nonce[12];
    SByteSpan nonceSpan(nonce, sizeof(nonce));
    if (crypto::CRng::fill(nonceSpan) != ERET_OK) {
        return; // there is no safe degraded mode -- do not fall back to rand()
    }

    uint8_t padding[64];
    SByteSpan paddingSpan(padding, sizeof(padding));
    if (crypto::CRng::fillNonZero(paddingSpan) != ERET_OK) {
        return;
    }

    // ... build the encoded message, then clear the padding.
    CSecure::zero(paddingSpan);
}

// === CPoly1305 ===
// Authenticates one message under a key that must never be used again: two messages under one
// Poly1305 key let an attacker solve for r and forge at will. Reach for CChaCha20Poly1305
// instead unless you already guarantee key uniqueness yourself.
void exampleCPoly1305(const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& ciphertext) {
    uint8_t key[crypto::CPoly1305::KEY_BYTES];
    SByteSpan keySpan(key, sizeof(key));
    if (crypto::CRng::fill(keySpan) != ERET_OK) {
        return;
    }

    crypto::CPoly1305 mac;
    if (!mac.reset(keySpan)) {
        return;
    }

    // padToBlock() closes the current block with zeros rather than extending the message, which
    // is what RFC 8439's pad16 between fields does -- pushing zero bytes is not the same thing.
    mac.push(aad);
    mac.padToBlock();
    mac.push(ciphertext);
    mac.padToBlock();

    uint8_t tag[crypto::CPoly1305::TAG_BYTES];
    if (!mac.finish(SByteSpan(tag, sizeof(tag)))) {
        return;
    }

    CSecure::zero(keySpan);
}

// === CSipHash ===
// Computes a DNS server cookie (RFC 9018 2.2). Unlike CPoly1305 the key is long-lived: finish()
// leaves it in place, and the no-argument reset() starts the next message under the same key.
void exampleCSipHash(
    const SReadOnlyByteSpan& serverSecret, const SReadOnlyByteSpan& clientCookie,
    const SReadOnlyByteSpan& clientIp
) {
    crypto::CSipHash prf;
    if (!prf.reset(serverSecret)) {
        return; // the key is exactly KEY_BYTES, which is 16
    }

    prf.push(clientCookie);
    prf.push(clientIp);

    uint8_t cookieHash[crypto::CSipHash::TAG_BYTES];
    SByteSpan out(cookieHash, sizeof(cookieHash));
    if (!prf.finish(out)) {
        return;
    }

    // The same instance serves the next query without re-supplying the key.
    if (!prf.reset()) {
        return;
    }
}

// === CBlake2sMac ===
// Verifies a tag from BLAKE2s's *native* keyed mode, which is what WireGuard's MAC() is. This is
// not HMAC-BLAKE2s: for the generic RFC 2104 construction over the same hash use CHmac with
// EHASH_BLAKE2S, which produces a completely different tag from the same key and message.
void exampleCBlake2sMac(
    const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message,
    const SReadOnlyByteSpan& receivedTag
) {
    if (!crypto::CBlake2sMac::verify(key, message, receivedTag)) {
        return; // constant-time -- never check a tag with memcmp
    }

    // A 16-byte tag is its own function, not the first 16 bytes of the 32-byte one: the length is
    // bound into the parameter block.
    crypto::CBlake2sMac mac;
    if (!mac.reset(key, 16)) {
        return;
    }

    mac.push(message);

    uint8_t tag[16];
    if (!mac.finish(SByteSpan(tag, sizeof(tag)))) {
        return;
    }
}

// === CChaCha20Poly1305 ===
// Opens a received record in place. The tag is verified before a single plaintext byte is
// written, so a false return leaves the buffer holding the ciphertext exactly as it arrived --
// and the comparison is already constant-time, so do not add a memcmp of your own.
void exampleCChaCha20Poly1305(
    const SReadOnlyByteSpan& key, uint64_t recordNumber, const SReadOnlyByteSpan& aad,
    const SByteSpan& record, const SReadOnlyByteSpan& tag
) {
    crypto::CChaCha20Poly1305 aead;
    if (!aead.reset(key)) {
        return; // the key is exactly KEY_BYTES
    }

    // 96 bits is too short to pick at random; a per-record counter is the usual answer.
    uint8_t nonce[crypto::CChaCha20Poly1305::NONCE_BYTES] = { 0 };
    memcpy(nonce + 4, &recordNumber, sizeof(recordNumber));

    SReadOnlyByteSpan nonceSpan(nonce, sizeof(nonce));
    if (!aead.open(nonceSpan, aad, record, tag, record)) {
        return; // record still holds the ciphertext, untouched
    }

    // record now holds the plaintext, exactly as many bytes as the ciphertext was.
}

// === CXChaCha20Poly1305 ===
// Seals a record under a freshly drawn 192-bit nonce. This is the AEAD to pick when nonces
// cannot be counted: 24 bytes is wide enough to choose at random, which is exactly what
// CChaCha20Poly1305's 96-bit nonce cannot promise.
void exampleCXChaCha20Poly1305(
    const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& aad,
    const SReadOnlyByteSpan& plaintext, const SByteSpan& ciphertext
) {
    crypto::CXChaCha20Poly1305 aead;
    if (!aead.reset(key)) {
        return;
    }

    uint8_t nonce[crypto::CXChaCha20Poly1305::NONCE_BYTES];
    SByteSpan nonceSpan(nonce, sizeof(nonce));
    if (crypto::CRng::fill(nonceSpan) != ERET_OK) {
        return;
    }

    uint8_t tag[crypto::CXChaCha20Poly1305::TAG_BYTES];
    SByteSpan tagSpan(tag, sizeof(tag));

    // seal() is (nonce, aad, in, out, tag); open() swaps those last two round.
    if (!aead.seal(nonceSpan, aad, plaintext, ciphertext, tagSpan)) {
        return; // ciphertext must be exactly plaintext.size bytes
    }

    // Transmit the nonce and the tag alongside the ciphertext.
}

// === CAesGcm ===
// Keys one context per key and seals a record in place. Watch the argument order: seal() takes
// (iv, aad, in, out, tag) while open() takes (iv, aad, in, tag, out) -- the tag and the output
// trade places, and both calls compile either way round.
void exampleCAesGcm(
    const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& aad, const SByteSpan& record
) {
    crypto::CAesGcm gcm;
    if (!gcm.reset(key)) {
        return; // the key must be 16, 24 or 32 bytes
    }

    uint8_t iv[crypto::CAesGcm::IV_BYTES];
    SByteSpan ivSpan(iv, sizeof(iv));
    if (crypto::CRng::fill(ivSpan) != ERET_OK) {
        return;
    }

    uint8_t tag[crypto::CAesGcm::TAG_BYTES];
    SByteSpan tagSpan(tag, sizeof(tag));

    // out may alias in exactly, which is what lets a record be encrypted where it already sits.
    if (!gcm.seal(ivSpan, aad, record, record, tagSpan)) {
        return;
    }

    // record now holds the ciphertext; send iv, record and tag together.
}

// === EAsymmetrics ===
// Selects the algorithm builtIn() hands back, and names the key size generateKeyPair() demands.
// That size is in bits and is checked exactly: Ed448 wants 456, not 448, because its keys are 57
// bytes -- a wrong size is ERET_KEY_SIZE, never rounded to the nearest supported one.
void exampleEAsymmetrics() {
    crypto::IAsymmetricPtr ed448 = crypto::IAsymmetric::builtIn(crypto::EASYM_ED448);
    if (!ed448) {
        return;
    }

    crypto::SKeyPair pair;
    if (ed448->generateKeyPair(456, pair) != ERET_OK) {
        return;
    }

    // The key remembers which algorithm made it, so a certificate builder can pick the matching
    // SubjectPublicKeyInfo OID without being told separately.
    if (pair.privateKey->algorithm() != crypto::EASYM_ED448) {
        return;
    }
}

// === SKeySizeSpec ===
// Checks a caller-supplied key size against what the algorithm actually accepts, before
// generateKeyPair() rejects it. A spec built from one size has step 0 and includes() only that
// size; RSA's is a range with a step, so 2048 passes and 2049 does not.
void exampleSKeySizeSpec(const crypto::IAsymmetricPtr& algo, crypto::SKeySize requested) {
    bool accepted = false;
    for (const crypto::SKeySizeSpec& spec : algo->keySizes()) {
        if (spec.includes(requested)) {
            accepted = true;
            break;
        }
    }

    if (!accepted) {
        return; // generateKeyPair() would answer ERET_KEY_SIZE
    }

    crypto::SKeyPair pair;
    if (algo->generateKeyPair(requested, pair) != ERET_OK) {
        return;
    }
}

// === IAsymmetric ===
// Obtains a built-in algorithm from the factory and generates a key pair at one of its advertised
// sizes. ERET_AGAIN is not a failure: the fresh candidate flunked its own validation, and the
// documented response is to call generateKeyPair() again.
void exampleIAsymmetric() {
    crypto::IAsymmetricPtr algo = crypto::IAsymmetric::builtIn(crypto::EASYM_P256);
    if (!algo) {
        return;
    }

    crypto::SKeyPair pair;
    ERetCode ret = ERET_AGAIN;
    for (size_t i = 0; i < 8 && ret == ERET_AGAIN; ++i) {
        ret = algo->generateKeyPair(256, pair);
    }

    if (ret != ERET_OK) {
        return;
    }

    // A key that came in from the wire instead would want checkPrivateKey() run on it by hand;
    // generateKeyPair() has already done that here.
}

// === IAsymmetricContext ===
// Binds a key pair to a context and signs a digest. sizeOfSign() is the capacity to allocate and
// the signature's real length is the output span's narrowed .size afterwards; a sizeOfDigest() of
// 0 means the algorithm hashes internally and wants the message, not a digest.
void exampleIAsymmetricContext(
    const crypto::IAsymmetricPtr& algo, const crypto::SKeyPair& pair,
    const SReadOnlyByteSpan& digest
) {
    crypto::IAsymmetricContextPtr ctx = algo->createContext();
    ctx->keyPair(pair);

    if (ctx->sizeOfSign() == 0) {
        return; // nothing usable was bound
    }

    TArray<uint8_t> signature;
    signature.resize(ctx->sizeOfSign());

    SByteSpan out(signature.begin(), signature.size());
    if (ctx->sign(digest, out) != ERET_OK) {
        return; // ERET_NOTSUP for an agreement-only algorithm such as X25519
    }

    signature.resize(out.size);
    if (ctx->verify(digest, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK) {
        return;
    }
}

// === IAsymmetricTransformer ===
// Encrypts with the context's bound public key. Asymmetric encryption works a block at a time, so
// it is a transform()-then-transformFinal() session; both narrow the span they wrote into, so
// advance by .size rather than by the capacity you handed over.
void exampleIAsymmetricTransformer(
    const crypto::IAsymmetricContextPtr& ctx, const SReadOnlyByteSpan& message
) {
    crypto::IAsymmetricTransformerPtr encrypter;
    if (ctx->createEncrypter(encrypter) != ERET_OK) {
        return; // ERET_NOTSUP for an algorithm that only signs
    }

    TArray<uint8_t> ciphertext;
    ciphertext.resize(encrypter->blockSize() * 2);

    SByteSpan step(ciphertext.begin(), ciphertext.size());
    if (encrypter->transform(message, step) != ERET_OK) {
        return;
    }

    SByteSpan rest(ciphertext.begin() + step.size, ciphertext.size() - step.size);
    if (encrypter->transformFinal(rest) != ERET_OK) {
        return;
    }

    ciphertext.resize(step.size + rest.size);
}

// === IKeyBase ===
// Serializes a key and compares it with another through the base both key families share.
// compare() answers "the same bytes", which is a different question from "do these two form a
// pair" -- that one needs a signature, as CCertCollection::checkKeyPairing() does.
void exampleIKeyBase(const crypto::IKeyBasePtr& key, const crypto::IKeyBasePtr& other) {
    COctet encoded;
    if (key->serialize(encoded) != ERET_OK || encoded.empty()) {
        return;
    }

    if (key->compare(other) != 0) {
        return; // different key material
    }

    // encoded is the algorithm-defined encoding, ready to go into a SubjectPublicKeyInfo or a
    // private-key file.
}

// === IAsymmetricKeyBase ===
// Reads the algorithm and size an asymmetric key carries with it, which is what lets an encoder
// pick the right OID without the caller tracking which IAsymmetric produced the key. keySize()
// is in bits here.
void exampleIAsymmetricKeyBase(const crypto::IAsymmetricKeyBasePtr& key) {
    if (key->algorithm() == crypto::EASYM_UNKNOWN) {
        return; // a key that never came out of an IAsymmetric factory
    }

    if (key->algorithm() == crypto::EASYM_RSA && key->keySize() < 2048) {
        return; // too short for this deployment to accept
    }

    COctet encoded;
    if (key->serialize(encoded) != ERET_OK) {
        return;
    }
}

// === IPublicKey ===
// Parses a peer's public key material and binds it on its own. keyPair(publicKey, nullptr) is how
// you verify someone else's signature: there is no private half to supply, and the two-argument
// overload exists precisely so you do not have to fake one.
void exampleIPublicKey(
    const crypto::IAsymmetricPtr& algo, const SReadOnlyByteSpan& keyData,
    const SReadOnlyByteSpan& digest, const SReadOnlyByteSpan& signature
) {
    crypto::IPublicKeyPtr peer = algo->createPublicKey(keyData);
    if (!peer) {
        return; // keyData was not a valid encoding for this algorithm
    }

    crypto::IAsymmetricContextPtr ctx = algo->createContext();
    ctx->keyPair(peer, nullptr);

    if (ctx->verify(digest, signature) != ERET_OK) {
        return; // the signature does not match, or verification is unsupported
    }
}

// === IPrivateKey ===
// Imports a private key, validates it, and derives its public half. checkPrivateKey() is worth
// calling on anything deserialized: generateKeyPair() runs it for you, createPrivateKey() does
// not, and it reports *why* it failed rather than ERET_AGAIN.
void exampleIPrivateKey(const crypto::IAsymmetricPtr& algo, const SReadOnlyByteSpan& keyData) {
    crypto::IPrivateKeyPtr key = algo->createPrivateKey(keyData);
    if (!key) {
        return; // not a valid encoding
    }

    if (algo->checkPrivateKey(key) != ERET_OK) {
        return; // ERET_KEY_PARAM for an off-curve or wrong-subgroup point, and so on
    }

    crypto::IPublicKeyPtr pub = key->publicKey();
    if (!pub) {
        return;
    }

    crypto::IAsymmetricContextPtr ctx = algo->createContext();
    ctx->keyPair(pub, key);
}

// === SKeyPair ===
// Checks what generateKeyPair() produced before binding it: empty() is true if *either* half is
// null, which is what a failed generation leaves behind. The private half knows its own public
// half, so the two never need pairing by hand.
void exampleSKeyPair(const crypto::IAsymmetricPtr& algo, crypto::SKeySize keySize) {
    crypto::SKeyPair pair;
    if (algo->generateKeyPair(keySize, pair) != ERET_OK || pair.empty()) {
        return;
    }

    crypto::IPublicKeyPtr derived = pair.privateKey->publicKey();
    if (!derived || derived->compare(pair.publicKey) != 0) {
        return;
    }

    crypto::IAsymmetricContextPtr ctx = algo->createContext();
    ctx->keyPair(pair);
}

// === EKems ===
// Selects the ML-KEM parameter set. The three values are *names*, not scalable sizes: the
// SKeySize generateKeyPair() wants is that same number, and an instance built for one set rejects
// the other two outright.
void exampleEKems(crypto::EKems which, crypto::SKeySize label) {
    crypto::IKemPtr kem = crypto::IKem::builtIn(which);
    if (!kem) {
        return; // EKEM_MAX and EKEM_UNKNOWN land here
    }

    crypto::SKemKeyPair pair;
    if (kem->generateKeyPair(label, pair) != ERET_OK) {
        return; // ERET_KEY_SIZE unless label is this instance's own parameter-set label
    }

    if (pair.publicKey->algorithm() != which) {
        return;
    }
}

// === IKem ===
// Obtains a built-in KEM from the factory and generates a decapsulation key pair. ML-KEM's "key
// size" is its parameter-set label -- 768 means ML-KEM-768, not a modulus width -- and nothing
// between the three names is accepted.
void exampleIKem() {
    crypto::IKemPtr kem = crypto::IKem::builtIn(crypto::EKEM_MLKEM768);
    if (!kem) {
        return;
    }

    crypto::SKemKeyPair pair;
    if (kem->generateKeyPair(768, pair) != ERET_OK) {
        return; // ERET_AGAIN means retry; ERET_KEY_SIZE means the wrong label
    }

    if (kem->checkPrivateKey(pair.privateKey) != ERET_OK) {
        return;
    }

    crypto::IKemContextPtr ctx = kem->createContext();
    ctx->keyPair(pair);
}

// === IKemContext ===
// Encapsulates a fresh secret to a peer's public key. The secret is produced by the call, not
// chosen by you, and the sizes are reported only once a key is bound -- so bind first, then
// allocate.
void exampleIKemContext(const crypto::IKemPtr& kem, const crypto::IKemPublicKeyPtr& peer) {
    crypto::IKemContextPtr ctx = kem->createContext();
    ctx->keyPair(peer, nullptr);

    if (ctx->sizeOfCiphertext() == 0) {
        return; // nothing bound; encapsulate() would answer ERET_KEY_EMPTY
    }

    TArray<uint8_t> ciphertext;
    TArray<uint8_t> secret;
    ciphertext.resize(ctx->sizeOfCiphertext());
    secret.resize(ctx->sizeOfSharedSecret());

    SByteSpan ciphertextOut(ciphertext.begin(), ciphertext.size());
    SByteSpan secretOut(secret.begin(), secret.size());
    if (ctx->encapsulate(ciphertextOut, secretOut) != ERET_OK) {
        return;
    }

    // Both spans are narrowed to what was written. Feed secretOut to a KDF, send ciphertextOut.
    CSecure::zero(secretOut);
}

// === IKemKeyBase ===
// Reads what a KEM key is, through the base both halves share. The algorithm travels with the key
// so an encoder can pick the right OID, and keySize() reports the parameter-set label
// (512/768/1024) rather than a bit count.
void exampleIKemKeyBase(const crypto::IKemKeyBasePtr& key) {
    if (key->algorithm() == crypto::EKEM_UNKNOWN) {
        return; // never came out of an IKem factory
    }

    if (key->keySize() < 768) {
        return; // ML-KEM-512 is below this deployment's floor
    }

    COctet encoded;
    if (key->serialize(encoded) != ERET_OK) {
        return;
    }
}

// === IKemPublicKey ===
// Serializes an encapsulation key to hand to a peer, and parses the one they sent back.
// createPublicKey() returns null rather than a half-built key when the encoding is wrong, so the
// null check is the whole error report you get.
void exampleIKemPublicKey(
    const crypto::IKemPtr& kem, const crypto::IKemPublicKeyPtr& own,
    const SReadOnlyByteSpan& peerKeyData
) {
    COctet encoded;
    if (own->serialize(encoded) != ERET_OK) {
        return;
    }

    // ... send encoded, receive theirs.
    crypto::IKemPublicKeyPtr peer = kem->createPublicKey(peerKeyData);
    if (!peer || peer->algorithm() != own->algorithm()) {
        return; // a mismatched parameter set is not interoperable
    }

    crypto::IKemContextPtr ctx = kem->createContext();
    ctx->keyPair(peer, nullptr);
}

// === IKemPrivateKey ===
// Recovers the shared secret from a peer's ciphertext. A corrupted ciphertext is not reported:
// implicit rejection means it decapsulates to a *different* secret instead, so the problem
// surfaces later, when the key derived from it fails to authenticate anything.
void exampleIKemPrivateKey(
    const crypto::IKemPtr& kem, const crypto::IKemPrivateKeyPtr& key,
    const SReadOnlyByteSpan& ciphertext
) {
    crypto::IKemContextPtr ctx = kem->createContext();
    ctx->keyPair(key->publicKey(), key);

    if (ctx->sizeOfSharedSecret() == 0) {
        return;
    }

    TArray<uint8_t> secret;
    secret.resize(ctx->sizeOfSharedSecret());

    SByteSpan secretOut(secret.begin(), secret.size());
    if (ctx->decapsulate(ciphertext, secretOut) != ERET_OK) {
        return; // ERET_KEY_EMPTY, or a ciphertext of the wrong length
    }

    // ... derive transport keys from secretOut, then clear it.
    CSecure::zero(secretOut);
}

// === SKemKeyPair ===
// Checks what generateKeyPair() produced before using it: empty() is true if either half is null.
// Mirrors SKeyPair for the KEM key family, which is deliberately separate -- a KEM has no
// sign()/verify() and no two-sided key agreement.
void exampleSKemKeyPair(const crypto::IKemPtr& kem, crypto::SKeySize label) {
    crypto::SKemKeyPair pair;
    if (kem->generateKeyPair(label, pair) != ERET_OK || pair.empty()) {
        return;
    }

    crypto::IKemPublicKeyPtr derived = pair.privateKey->publicKey();
    if (!derived || derived->compare(pair.publicKey) != 0) {
        return;
    }

    // Binding both halves lets this side encapsulate to itself and decapsulate.
    crypto::IKemContextPtr ctx = kem->createContext();
    ctx->keyPair(pair);
}

// === ESymmetrics ===
// Selects which built-in symmetric algorithm builtIn() returns, and travels on every key that
// algorithm produces so a caller does not have to track it separately.
void exampleESymmetrics(crypto::ESymmetrics which) {
    crypto::ISymmetricPtr algo = crypto::ISymmetric::builtIn(which);
    if (!algo) {
        return; // ESYM_MAX, ESYM_UNKNOWN and anything not built in
    }

    crypto::ISymmetricKeyPtr key;
    if (algo->generateKey(key, crypto::SKeySizeSpec(256)) != ERET_OK) {
        return; // 256 bits is legal for AES and ChaCha20, but not for DES (64) or 3DES (up to 192)
    }

    if (key->algorithm() != which) {
        return;
    }
}

// === ISymmetricKey ===
// Imports raw key material -- from a KDF, say -- and reads back what the algorithm made of it.
// keySize() here is in *bytes*, unlike the bit counts SKeySizeSpec and generateKey() deal in.
void exampleISymmetricKey(const crypto::ISymmetricPtr& algo, const SReadOnlyByteSpan& derived) {
    crypto::ISymmetricKeyPtr key = algo->createKey(derived);
    if (!key) {
        return; // derived.size is not a legal length for this algorithm
    }

    if (key->keySize() != derived.size) {
        return;
    }

    // keyData() is the material itself -- secret, and not something to log.
    SReadOnlyByteSpan raw = key->keyData().toSpan();
    if (raw.size != key->keySize()) {
        return;
    }
}

// === ISymmetric ===
// Obtains the built-in AES implementation from the factory, generates a key and an IV from it,
// and opens a context. generateIV() asks the algorithm for the right IV length rather than
// assuming it equals the block size.
void exampleISymmetric() {
    crypto::ISymmetricPtr aes = crypto::ISymmetric::builtIn(crypto::ESYM_AES);
    if (!aes) {
        return;
    }

    crypto::ISymmetricKeyPtr key;
    if (aes->generateKey(key, crypto::SKeySizeSpec(256)) != ERET_OK) {
        return;
    }

    CBuffer iv;
    if (aes->generateIV(key, iv) != ERET_OK) {
        return;
    }

    crypto::ISymmetricContextPtr ctx = aes->createContext(key);
    if (!ctx) {
        return;
    }

    ctx->key(key, iv);
}

// === ESymPaddings ===
// Selects ESYMPAD_NONE for a protocol that pads its own payload: IKEv2 (RFC 7296 3.14) builds a
// pad-length-terminated padding into the payload before encrypting, so a PKCS#7 block underneath
// it would be a second, unexpected padding the peer rejects.
void exampleESymPaddings(
    const crypto::ISymmetricPtr& algo, const crypto::ISymmetricKeyPtr& key, const CBuffer& iv
) {
    crypto::ISymmetricContextPtr ctx = algo->createContext(key);
    if (!ctx) {
        return;
    }

    // ESYMPAD_PKCS7 is the default; the choice is read when a transformer is built.
    ctx->padding(crypto::ESYMPAD_NONE);
    ctx->key(key, iv);

    crypto::ISymmetricTransformerPtr encrypter;
    if (ctx->createEncrypter(encrypter) != ERET_OK) {
        return;
    }

    // key() deliberately does not clear the padding mode, so this still holds.
    if (ctx->padding() != crypto::ESYMPAD_NONE) {
        return;
    }
}

// === ISymmetricContext ===
// Keys a context and reads back the block size the algorithm settled on. padding() is consulted
// when createEncrypter() builds a transformer, so set it before that call -- and it survives
// key() and reset() on purpose, so re-keying will not quietly revert it to PKCS#7.
void exampleISymmetricContext(
    const crypto::ISymmetricPtr& algo, const crypto::ISymmetricKeyPtr& key, const CBuffer& iv
) {
    crypto::ISymmetricContextPtr ctx = algo->createContext(key);
    if (!ctx) {
        return;
    }

    ctx->key(key, iv);
    if (ctx->sizeOfBlock() == 0) {
        return; // nothing usable was bound
    }

    crypto::ISymmetricTransformerPtr encrypter;
    if (ctx->createEncrypter(encrypter) != ERET_OK) {
        return; // ERET_KEY_EMPTY with no key bound, or a wrongly sized IV
    }

    // A second transformer for the other direction shares this context's key and IV.
    crypto::ISymmetricTransformerPtr decrypter;
    if (ctx->createDecrypter(decrypter) != ERET_OK) {
        return;
    }
}

// === ISymmetricTransformer ===
// Encrypts a message in one transform() plus one transformFinal(). PKCS#7's padding block appears
// in that final call, so the ciphertext is longer than the plaintext: leave a block of slack and
// take the real length from the two narrowed spans, not from the capacity you passed.
void exampleISymmetricTransformer(
    const crypto::ISymmetricContextPtr& ctx, const SReadOnlyByteSpan& plaintext
) {
    crypto::ISymmetricTransformerPtr encrypter;
    if (ctx->createEncrypter(encrypter) != ERET_OK) {
        return;
    }

    TArray<uint8_t> ciphertext;
    ciphertext.resize(plaintext.size + encrypter->blockSize());

    SByteSpan step(ciphertext.begin(), ciphertext.size());
    if (encrypter->transform(plaintext, step) != ERET_OK) {
        return;
    }

    SByteSpan rest(ciphertext.begin() + step.size, ciphertext.size() - step.size);
    if (encrypter->transformFinal(rest) != ERET_OK) {
        return;
    }

    ciphertext.resize(step.size + rest.size);

    // The transformer is spent now; context() gets back the context that can build another.
    crypto::ISymmetricContextPtr owner = encrypter->context();
}

// === ITransformer ===
// Drives any transformer -- symmetric or asymmetric -- to completion through the base interface:
// transform() per input chunk, then exactly one transformFinal(). Each call narrows the span it
// wrote into, so advance by .size rather than by the capacity handed over.
void exampleITransformer(
    const crypto::ITransformerPtr& transformer, const SReadOnlyByteSpan& input,
    const SByteSpan& output
) {
    SByteSpan step(output.data, output.size);
    if (transformer->transform(input, step) != ERET_OK) {
        return;
    }

    size_t written = step.size;
    SByteSpan rest(output.data + written, output.size - written);
    if (transformer->transformFinal(rest) != ERET_OK) {
        return;
    }

    written += rest.size;

    // written is the total output length; the transformer is not usable again.
}

// === EEcKnownCurves ===
// Picks which prime curve's domain parameters knownCurves() copies out. Its numbering is its own
// and does not line up with EAsymmetrics -- use CEcCurve::identify() to cross between them rather
// than casting.
void exampleEEcKnownCurves(crypto::EEcKnownCurves which) {
    crypto::CEcCurve curve;
    if (!crypto::CEcCurve::knownCurves(which, curve)) {
        return; // ECURVE_UNKNOWN and ECURVE_MAX are both rejected, and curve is left untouched
    }

    crypto::IAsymmetricPtr algo = crypto::IAsymmetric::builtIn(crypto::CEcCurve::identify(which));
    if (!algo) {
        return;
    }

    // curve.p is the field prime, for coordinates; curve.n is the subgroup order, for scalars.
    // They are different numbers and are never interchangeable.
    if (curve.p.isZero() || curve.n.isZero()) {
        return;
    }
}

// === CEcCurve ===
// Copies out a named curve's parameters and validates a peer's SEC1 point against them --
// decodePoint() rejects anything off the curve or outside the subgroup. The arithmetic here is
// not constant-time, so prefer X25519 for an online handshake wherever the protocol lets you.
void exampleCEcCurve(const SReadOnlyByteSpan& sec1Point) {
    crypto::CEcCurve curve;
    if (!crypto::CEcCurve::knownCurves(crypto::ECURVE_P256, curve)) {
        return;
    }

    crypto::SEcPoint peer;
    if (!curve.decodePoint(sec1Point, peer)) {
        return; // malformed, off-curve, or in the wrong subgroup
    }

    TArray<uint8_t> encoded;
    if (!curve.encodePoint(peer, encoded)) {
        return;
    }

    // Each coordinate is padded to fieldByteLen(), so an uncompressed point is a fixed width.
    if (encoded.size() != 1 + curve.fieldByteLen() * 2) {
        return;
    }
}

// === SEcPoint ===
// A default-constructed SEcPoint is the point at infinity -- the group identity -- not (0, 0),
// and its x/y are meaningless while infinity is true. equals() knows that, so an identity only
// ever matches another identity.
void exampleSEcPoint(const crypto::CEcCurve& curve) {
    crypto::SEcPoint identity;
    if (!identity.infinity) {
        return;
    }

    crypto::SEcPoint doubled = curve.doublePoint(curve.g);
    if (!doubled.equals(curve.add(curve.g, curve.g))) {
        return;
    }

    // Adding the identity is a no-op, as the group law requires.
    if (!curve.add(doubled, identity).equals(doubled)) {
        return;
    }

    if (!curve.isOnCurve(doubled)) {
        return;
    }
}

// === EEc2KnownCurves ===
// Picks which binary curve knownCurves() copies out. A "B" and a "K" curve of the same bit size
// share one GF(2^m) field singleton, so between ECURVE2_B163 and ECURVE2_K163 only a, b, g and n
// differ -- the field pointer is literally the same object.
void exampleEEc2KnownCurves() {
    crypto::CEc2Curve random;
    crypto::CEc2Curve koblitz;
    if (!crypto::CEc2Curve::knownCurves(crypto::ECURVE2_B163, random) ||
        !crypto::CEc2Curve::knownCurves(crypto::ECURVE2_K163, koblitz)) {
        return;
    }

    if (random.field != koblitz.field) {
        return; // cannot happen: the field is a program-lifetime singleton shared by both
    }

    crypto::IAsymmetricPtr algo =
        crypto::IAsymmetric::builtIn(crypto::CEc2Curve::identify(crypto::ECURVE2_K163));
    if (!algo) {
        return;
    }
}

// === CEc2Curve ===
// Copies out a binary curve's parameters and multiplies its base point by a scalar.
// scalarMulBase() caches a table of small multiples of g inside the instance, so keep one curve
// around and reuse it instead of fetching a fresh copy per operation.
void exampleCEc2Curve(const CBigNum& scalar) {
    crypto::CEc2Curve curve;
    if (!crypto::CEc2Curve::knownCurves(crypto::ECURVE2_B163, curve)) {
        return;
    }

    crypto::SEc2Point point = curve.scalarMulBase(scalar);
    if (point.infinity || !curve.isOnCurve(point)) {
        return;
    }

    TArray<uint8_t> encoded;
    if (!curve.encodePoint(point, encoded)) {
        return;
    }

    // encoded is 0x04 || X || Y, each coordinate padded out to curve.fieldByteLen() bytes.
    if (encoded.size() != 1 + curve.fieldByteLen() * 2) {
        return;
    }
}

// === SEc2Point ===
// A default-constructed SEc2Point is the point at infinity, with x/y meaningless until infinity
// is false. The coordinates are CGf2m field elements, not CBigNum: a binary curve's group law
// shares no formula with a prime curve's, and the two coordinate types do not convert.
void exampleSEc2Point(const crypto::CEc2Curve& curve) {
    crypto::SEc2Point identity;
    if (!identity.infinity) {
        return;
    }

    crypto::SEc2Point doubled = curve.doublePoint(curve.g);
    if (!doubled.equals(curve.add(curve.g, curve.g))) {
        return;
    }

    if (!curve.add(doubled, identity).equals(doubled)) {
        return;
    }

    // CGf2m's arithmetic mutates in place, so copy a coordinate before reusing the original.
    CGf2m sum = doubled.x;
    sum.add(doubled.y);
    if (sum.isZero()) {
        return;
    }
}

// === CPbkdf2 ===
// Derives a key from a password. Unlike CHkdf, whose input is already a high-entropy secret,
// PBKDF2's whole purpose is the iteration count: it makes each guess of a low-entropy password
// expensive. Pick the count from how long you can afford to spend, not from a standard's
// decade-old floor -- RFC 8018 suggests 1000 and OWASP's 2023 figure for HMAC-SHA256 is 600,000.
void exampleCPbkdf2(const SReadOnlyByteSpan& password) {
    // The salt is per-password and need not be secret; it stops one precomputed table from
    // covering every user. Never reuse one, and never omit it.
    uint8_t saltBytes[16];
    SByteSpan salt(saltBytes, sizeof(saltBytes));
    if (crypto::CRng::fill(salt) != ERET_OK) {
        return;
    }

    uint8_t keyBytes[32];
    SByteSpan key(keyBytes, sizeof(keyBytes));

    ERetCode rc = crypto::CPbkdf2::derive(
        crypto::EHASH_SHA256, password, SReadOnlyByteSpan(salt.data, salt.size), 600000, key);
    if (rc != ERET_OK) {
        return;         // ERET_BADREQ for zero iterations, or an output past maxDeriveBytes()
    }

    // Store the salt and the iteration count alongside the result: verifying a password later
    // means repeating this derivation exactly, and neither value is a secret.
    CSecure::zero(key);
}
