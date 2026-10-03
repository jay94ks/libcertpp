Checks what generateKeyPair() produced before using it: empty() is true if either half is null. Mirrors SKeyPair for the KEM key family, which is deliberately separate -- a KEM has no sign()/verify() and no two-sided key agreement.

```cpp
// given: const crypto::IKemPtr& kem, crypto::SKeySize label
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
```
