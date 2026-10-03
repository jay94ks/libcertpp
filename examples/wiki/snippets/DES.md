Decrypts a CBC blob from a legacy system, which is the only reason to reach for DES at all: 56 effective key bits is not a security level any more, and new work uses AES. Its block and IV are 8 bytes rather than AES's 16, and a wrong-length IV is refused by createDecrypter() rather than quietly truncated.

```cpp
// given: const SReadOnlyByteSpan& keyBytes, const SReadOnlyByteSpan& iv, const SReadOnlyByteSpan& ciphertext, TArray<uint8_t>& plaintext
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
```
