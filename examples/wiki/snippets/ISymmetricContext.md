Keys a context and reads back the block size the algorithm settled on. padding() is consulted when createEncrypter() builds a transformer, so set it before that call -- and it survives key() and reset() on purpose, so re-keying will not quietly revert it to PKCS#7.

```cpp
// given: const crypto::ISymmetricPtr& algo, const crypto::ISymmetricKeyPtr& key, const CBuffer& iv
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
```
