Checks what generateKeyPair() produced before binding it: empty() is true if *either* half is null, which is what a failed generation leaves behind. The private half knows its own public half, so the two never need pairing by hand.

```cpp
// given: const crypto::IAsymmetricPtr& algo, crypto::SKeySize keySize
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
```
