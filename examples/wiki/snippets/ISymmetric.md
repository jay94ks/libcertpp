Obtains the built-in AES implementation from the factory, generates a key and an IV from it, and opens a context. generateIV() asks the algorithm for the right IV length rather than assuming it equals the block size.

```cpp
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
```
