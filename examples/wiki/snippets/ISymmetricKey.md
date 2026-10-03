Imports raw key material -- from a KDF, say -- and reads back what the algorithm made of it. keySize() here is in *bytes*, unlike the bit counts SKeySizeSpec and generateKey() deal in.

```cpp
// given: const crypto::ISymmetricPtr& algo, const SReadOnlyByteSpan& derived
crypto::ISymmetricKeyPtr key = algo->createKey(derived);
if (!key) {
    return; // derived.size is not a legal length for this algorithm
}

if (key->keySize() != derived.size) {
    return;
}

// keyData() is the material itself -- secret, and not something to log.
SReadOnlyByteSpan raw = key->keyData().toSpan();
if (raw.size != key->keySize()) {
    return;
}
```
