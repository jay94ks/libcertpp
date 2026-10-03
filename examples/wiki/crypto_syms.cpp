#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;

// Each example is one function, preceded by a `// === <TypeName> ===` marker. The function body
// is what gets published as that type's example, dedented, so write it as the code a caller
// would write -- not as a test. See the brief for the rules.

// === AES ===
// Encrypts one message with AES-256-CBC and hands back the fresh per-message IV: transform()
// emits whole blocks as they complete, transformFinal() appends the PKCS#7 pad block, and the
// ciphertext's real length is the sum of those two narrowed output spans rather than the
// capacity passed in. CBC is confidentiality and nothing else -- no part of this detects a
// modified ciphertext, so anything that crosses a wire wants CAesGcm instead.
void exampleAES(const SReadOnlyByteSpan& plaintext, CBuffer& iv, TArray<uint8_t>& ciphertext) {
    ISymmetricPtr aes = ISymmetric::builtIn(ESYM_AES);

    ISymmetricKeyPtr key;
    if (aes->generateKey(key, SKeySizeSpec(256)) != ERET_OK ||
        aes->generateIV(key, iv) != ERET_OK) {
        return;
    }

    ISymmetricContextPtr ctx = aes->createContext(key);
    ctx->key(key, iv); // --> binds both: a context with no IV refuses to make a transformer.

    ISymmetricTransformerPtr enc;
    if (ctx->createEncrypter(enc) != ERET_OK) {
        return; // --> ERET_KEY_PARAM unless the IV is exactly sizeOfBlock() == 16 bytes.
    }

    ciphertext.resize(plaintext.size + 16); // --> PKCS#7 adds 1..16 bytes, never 0.
    SByteSpan body(ciphertext.begin(), ciphertext.size());
    if (enc->transform(plaintext, body) != ERET_OK) {
        return;
    }

    SByteSpan pad(ciphertext.begin() + body.size, ciphertext.size() - body.size);
    if (enc->transformFinal(pad) != ERET_OK) {
        return;
    }

    ciphertext.resize(body.size + pad.size);
}

// === ChaCha20 ===
// Encrypts record number `record` under one long-lived key, deriving the 12-byte nonce from a
// counter: a 96-bit nonce is too short to pick at random, and repeating one under the same key
// XORs two plaintexts together and loses both. Raw ChaCha20 is a keystream and nothing more --
// it detects no tampering (CChaCha20Poly1305 is the authenticated form), and because the nonce
// is bound by key(), each record re-keys the context instead of reusing one transformer.
void exampleChaCha20(
    const SReadOnlyByteSpan& keyBytes, uint64_t record,
    const SReadOnlyByteSpan& plaintext, TArray<uint8_t>& ciphertext
) {
    ISymmetricPtr cc = ISymmetric::builtIn(ESYM_CHACHA20);

    ISymmetricKeyPtr key = cc->createKey(keyBytes);
    if (!key) {
        return; // --> keyBytes was not exactly 32 bytes; that is the only failure it reports.
    }

    // Bytes 0..3 are left zero here, where a protocol would put a direction or sender label;
    // the counter fills the remaining eight, little-endian as RFC 8439 numbers them.
    uint8_t nonce[12] = { 0 };
    for (size_t i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<uint8_t>(record >> (8 * i));
    }

    ISymmetricContextPtr ctx = cc->createContext(key);
    ctx->key(key, CBuffer(nonce, sizeof(nonce)));

    ISymmetricTransformerPtr enc;
    if (ctx->createEncrypter(enc) != ERET_OK) {
        return; // --> ERET_KEY_PARAM unless the nonce is exactly 12 bytes.
    }

    // No padding and no block alignment: the output is exactly as long as the input,
    // transformFinal() would have nothing left to emit, and decrypting is this same code with
    // createDecrypter() -- the XOR is its own inverse.
    ciphertext.resize(plaintext.size);
    SByteSpan out(ciphertext.begin(), ciphertext.size());
    if (enc->transform(plaintext, out) != ERET_OK) {
        return;
    }

    ciphertext.resize(out.size);
}

// === DES ===
// Decrypts a CBC blob from a legacy system, which is the only reason to reach for DES at all:
// 56 effective key bits is not a security level any more, and new work uses AES. Its block and
// IV are 8 bytes rather than AES's 16, and a wrong-length IV is refused by createDecrypter()
// rather than quietly truncated.
void exampleDES(
    const SReadOnlyByteSpan& keyBytes, const SReadOnlyByteSpan& iv,
    const SReadOnlyByteSpan& ciphertext, TArray<uint8_t>& plaintext
) {
    ISymmetricPtr des = ISymmetric::builtIn(ESYM_DES);

    ISymmetricKeyPtr key = des->createKey(keyBytes);
    if (!key) {
        return; // --> keyBytes must be exactly 8 bytes; its parity bits are never checked.
    }

    ISymmetricContextPtr ctx = des->createContext(key);
    ctx->key(key, CBuffer(iv.data, iv.size));

    ISymmetricTransformerPtr dec;
    if (ctx->createDecrypter(dec) != ERET_OK) {
        return; // --> ERET_KEY_PARAM unless the IV is exactly 8 bytes.
    }

    plaintext.resize(ciphertext.size); // --> stripping padding only ever shortens it.
    SByteSpan body(plaintext.begin(), plaintext.size());
    if (dec->transform(ciphertext, body) != ERET_OK) {
        return;
    }

    // transformFinal() is where the PKCS#7 padding is checked and stripped, so it is where a
    // wrong key usually first shows up. "Usually" is the point: CBC carries no integrity check,
    // and a padding failure is not one.
    SByteSpan tail(plaintext.begin() + body.size, plaintext.size() - body.size);
    if (dec->transformFinal(tail) != ERET_OK) {
        return;
    }

    plaintext.resize(body.size + tail.size);
}

// === TripleDES ===
// Encrypts with a two-key EDE key spelled out in the three-key form a peer may insist on --
// K1|K2|K1, 24 bytes -- and clears the assembled copy once the key object owns it; passing the
// same material as a 128-bit key is the identical cipher. Note the 8-byte IV: EDE chains DES
// blocks, it does not widen them, and a 64-bit block is why a key here should be retired long
// before it has encrypted 2^32 blocks.
void exampleTripleDES(
    const SReadOnlyByteSpan& twoKey, const CBuffer& iv,
    const SReadOnlyByteSpan& plaintext, TArray<uint8_t>& ciphertext
) {
    if (twoKey.size != 16) {
        return;
    }

    uint8_t keyBytes[24];
    std::memcpy(keyBytes, twoKey.data, 16);
    std::memcpy(keyBytes + 16, twoKey.data, 8); // --> K3 == K1.

    ISymmetricPtr des3 = ISymmetric::builtIn(ESYM_3DES);
    ISymmetricKeyPtr key = des3->createKey(SReadOnlyByteSpan(keyBytes, sizeof(keyBytes)));
    CSecure::zero(SByteSpan(keyBytes, sizeof(keyBytes))); // --> the key object owns it now.
    if (!key) {
        return;
    }

    ISymmetricContextPtr ctx = des3->createContext(key);
    ctx->key(key, iv);

    ISymmetricTransformerPtr enc;
    if (ctx->createEncrypter(enc) != ERET_OK) {
        return; // --> ERET_KEY_PARAM unless the IV is exactly 8 bytes.
    }

    ciphertext.resize(plaintext.size + 8);
    SByteSpan out(ciphertext.begin(), ciphertext.size());
    if (enc->transform(plaintext, out) != ERET_OK) {
        return;
    }

    size_t written = out.size;
    out = SByteSpan(ciphertext.begin() + written, ciphertext.size() - written);
    if (enc->transformFinal(out) != ERET_OK) {
        return;
    }

    ciphertext.resize(written + out.size);
}
