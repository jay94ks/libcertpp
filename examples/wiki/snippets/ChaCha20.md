Encrypts record number `record` under one long-lived key, deriving the 12-byte nonce from a counter: a 96-bit nonce is too short to pick at random, and repeating one under the same key XORs two plaintexts together and loses both. Raw ChaCha20 is a keystream and nothing more -- it detects no tampering (CChaCha20Poly1305 is the authenticated form), and because the nonce is bound by key(), each record re-keys the context instead of reusing one transformer.

```cpp
// given: const SReadOnlyByteSpan& keyBytes, uint64_t record, const SReadOnlyByteSpan& plaintext, TArray<uint8_t>& ciphertext
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
```
