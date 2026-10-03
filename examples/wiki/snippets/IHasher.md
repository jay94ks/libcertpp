Streams a message through a built-in hasher, obtained from the create() factory rather than constructed. byteWidth() is the digest length to allocate, and push() may be called as often as the data arrives before a single finish().

```cpp
// given: const SReadOnlyByteSpan& header, const SReadOnlyByteSpan& body
crypto::IHasherPtr hasher;
if (crypto::IHasher::create(crypto::EHASH_SHA256, hasher) != ERET_OK) {
    return;
}

if (hasher->push(header) != header.size || hasher->push(body) != body.size) {
    return;
}

uint8_t digest[64];
SByteSpan out(digest, hasher->byteWidth());
if (!hasher->finish(out)) {
    return;
}

// reset() starts a fresh message on the same instance; no reallocation.
hasher->reset();
```
