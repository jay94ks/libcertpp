Selects which hasher IHasher::create() builds. Store the algorithm's OID or name if you need to persist the choice -- never the enumerator's integer value, which is a build-time detail that crosses an ABI boundary as new hashers are appended.

```cpp
// given: crypto::EHashers which, const SReadOnlyByteSpan& message
crypto::IHasherPtr hasher;
if (crypto::IHasher::create(which, hasher) != ERET_OK) {
    return; // EHASH_UNKNOWN, EHASH_MAX and anything unimplemented land here
}

TArray<uint8_t> digest;
digest.resize(hasher->byteWidth());

hasher->push(message);
if (!hasher->finish(SByteSpan(digest.begin(), digest.size()))) {
    return;
}
```
