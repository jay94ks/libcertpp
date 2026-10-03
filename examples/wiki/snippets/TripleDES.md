Encrypts with a two-key EDE key spelled out in the three-key form a peer may insist on -- K1|K2|K1, 24 bytes -- and clears the assembled copy once the key object owns it; passing the same material as a 128-bit key is the identical cipher. Note the 8-byte IV: EDE chains DES blocks, it does not widen them, and a 64-bit block is why a key here should be retired long before it has encrypted 2^32 blocks.

```cpp
// given: const SReadOnlyByteSpan& twoKey, const CBuffer& iv, const SReadOnlyByteSpan& plaintext, TArray<uint8_t>& ciphertext
if (twoKey.size != 16) {
    return;
}

uint8_t keyBytes[24];
std::memcpy(keyBytes, twoKey.data, 16);
std::memcpy(keyBytes + 16, twoKey.data, 8); // --> K3 == K1.

ISymmetricPtr des3 = ISymmetric::builtIn(ESYM_3DES);
ISymmetricKeyPtr key = des3->createKey(SReadOnlyByteSpan(keyBytes, sizeof(keyBytes)));
CSecure::zero(SByteSpan(keyBytes, sizeof(keyBytes))); // --> the key object owns it now.
if (!key) {
    return;
}

ISymmetricContextPtr ctx = des3->createContext(key);
ctx->key(key, iv);

ISymmetricTransformerPtr enc;
if (ctx->createEncrypter(enc) != ERET_OK) {
    return; // --> ERET_KEY_PARAM unless the IV is exactly 8 bytes.
}

ciphertext.resize(plaintext.size + 8);
SByteSpan out(ciphertext.begin(), ciphertext.size());
if (enc->transform(plaintext, out) != ERET_OK) {
    return;
}

size_t written = out.size;
out = SByteSpan(ciphertext.begin() + written, ciphertext.size() - written);
if (enc->transformFinal(out) != ERET_OK) {
    return;
}

ciphertext.resize(written + out.size);
```
