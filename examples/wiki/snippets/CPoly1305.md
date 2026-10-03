Authenticates one message under a key that must never be used again: two messages under one Poly1305 key let an attacker solve for r and forge at will. Reach for CChaCha20Poly1305 instead unless you already guarantee key uniqueness yourself.

```cpp
// given: const SReadOnlyByteSpan& aad, const SReadOnlyByteSpan& ciphertext
uint8_t key[crypto::CPoly1305::KEY_BYTES];
SByteSpan keySpan(key, sizeof(key));
if (crypto::CRng::fill(keySpan) != ERET_OK) {
    return;
}

crypto::CPoly1305 mac;
if (!mac.reset(keySpan)) {
    return;
}

// padToBlock() closes the current block with zeros rather than extending the message, which
// is what RFC 8439's pad16 between fields does -- pushing zero bytes is not the same thing.
mac.push(aad);
mac.padToBlock();
mac.push(ciphertext);
mac.padToBlock();

uint8_t tag[crypto::CPoly1305::TAG_BYTES];
if (!mac.finish(SByteSpan(tag, sizeof(tag)))) {
    return;
}

CSecure::zero(keySpan);
```
