Imports a private key, validates it, and derives its public half. checkPrivateKey() is worth calling on anything deserialized: generateKeyPair() runs it for you, createPrivateKey() does not, and it reports *why* it failed rather than ERET_AGAIN.

```cpp
// given: const crypto::IAsymmetricPtr& algo, const SReadOnlyByteSpan& keyData
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
```
