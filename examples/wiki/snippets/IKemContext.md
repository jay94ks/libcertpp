Encapsulates a fresh secret to a peer's public key. The secret is produced by the call, not chosen by you, and the sizes are reported only once a key is bound -- so bind first, then allocate.

```cpp
// given: const crypto::IKemPtr& kem, const crypto::IKemPublicKeyPtr& peer
crypto::IKemContextPtr ctx = kem->createContext();
ctx->keyPair(peer, nullptr);

if (ctx->sizeOfCiphertext() == 0) {
    return; // nothing bound; encapsulate() would answer ERET_KEY_EMPTY
}

TArray<uint8_t> ciphertext;
TArray<uint8_t> secret;
ciphertext.resize(ctx->sizeOfCiphertext());
secret.resize(ctx->sizeOfSharedSecret());

SByteSpan ciphertextOut(ciphertext.begin(), ciphertext.size());
SByteSpan secretOut(secret.begin(), secret.size());
if (ctx->encapsulate(ciphertextOut, secretOut) != ERET_OK) {
    return;
}

// Both spans are narrowed to what was written. Feed secretOut to a KDF, send ciphertextOut.
CSecure::zero(secretOut);
```
