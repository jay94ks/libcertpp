Recovers the shared secret from a peer's ciphertext. A corrupted ciphertext is not reported: implicit rejection means it decapsulates to a *different* secret instead, so the problem surfaces later, when the key derived from it fails to authenticate anything.

```cpp
// given: const crypto::IKemPtr& kem, const crypto::IKemPrivateKeyPtr& key, const SReadOnlyByteSpan& ciphertext
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
```
