Encrypts one message with AES-256-CBC and hands back the fresh per-message IV: transform() emits whole blocks as they complete, transformFinal() appends the PKCS#7 pad block, and the ciphertext's real length is the sum of those two narrowed output spans rather than the capacity passed in. CBC is confidentiality and nothing else -- no part of this detects a modified ciphertext, so anything that crosses a wire wants CAesGcm instead.

```cpp
// given: const SReadOnlyByteSpan& plaintext, CBuffer& iv, TArray<uint8_t>& ciphertext
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
```
