Opens a received record in place. The tag is verified before a single plaintext byte is written, so a false return leaves the buffer holding the ciphertext exactly as it arrived -- and the comparison is already constant-time, so do not add a memcmp of your own.

```cpp
// given: const SReadOnlyByteSpan& key, uint64_t recordNumber, const SReadOnlyByteSpan& aad, const SByteSpan& record, const SReadOnlyByteSpan& tag
crypto::CChaCha20Poly1305 aead;
if (!aead.reset(key)) {
    return; // the key is exactly KEY_BYTES
}

// 96 bits is too short to pick at random; a per-record counter is the usual answer.
uint8_t nonce[crypto::CChaCha20Poly1305::NONCE_BYTES] = { 0 };
memcpy(nonce + 4, &recordNumber, sizeof(recordNumber));

SReadOnlyByteSpan nonceSpan(nonce, sizeof(nonce));
if (!aead.open(nonceSpan, aad, record, tag, record)) {
    return; // record still holds the ciphertext, untouched
}

// record now holds the plaintext, exactly as many bytes as the ciphertext was.
```
