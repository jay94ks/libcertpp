Seals a record under a freshly drawn 192-bit nonce. This is the AEAD to pick when nonces cannot be counted: 24 bytes is wide enough to choose at random, which is exactly what CChaCha20Poly1305's 96-bit nonce cannot promise.

```cpp
// given: const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& plaintext, const SByteSpan& ciphertext
crypto::CXChaCha20Poly1305 aead;
if (!aead.reset(key)) {
    return;
}

uint8_t nonce[crypto::CXChaCha20Poly1305::NONCE_BYTES];
SByteSpan nonceSpan(nonce, sizeof(nonce));
if (crypto::CRng::fill(nonceSpan) != ERET_OK) {
    return;
}

uint8_t tag[crypto::CXChaCha20Poly1305::TAG_BYTES];
SByteSpan tagSpan(tag, sizeof(tag));

// seal() is (nonce, aad, in, out, tag); open() swaps those last two round.
if (!aead.seal(nonceSpan, aad, plaintext, ciphertext, tagSpan)) {
    return; // ciphertext must be exactly plaintext.size bytes
}

// Transmit the nonce and the tag alongside the ciphertext.
```
