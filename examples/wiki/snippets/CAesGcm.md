Keys one context per key and seals a record in place. Watch the argument order: seal() takes (iv, aad, in, out, tag) while open() takes (iv, aad, in, tag, out) -- the tag and the output trade places, and both calls compile either way round.

```cpp
// given: const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& aad, const SByteSpan& record
crypto::CAesGcm gcm;
if (!gcm.reset(key)) {
    return; // the key must be 16, 24 or 32 bytes
}

uint8_t iv[crypto::CAesGcm::IV_BYTES];
SByteSpan ivSpan(iv, sizeof(iv));
if (crypto::CRng::fill(ivSpan) != ERET_OK) {
    return;
}

uint8_t tag[crypto::CAesGcm::TAG_BYTES];
SByteSpan tagSpan(tag, sizeof(tag));

// out may alias in exactly, which is what lets a record be encrypted where it already sits.
if (!gcm.seal(ivSpan, aad, record, record, tagSpan)) {
    return;
}

// record now holds the ciphertext; send iv, record and tag together.
```
