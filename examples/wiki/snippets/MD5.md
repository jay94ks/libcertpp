Checks a legacy fingerprint whose algorithm the data named, so the hasher comes from IHasher::create() rather than from writing `MD5` into the caller's own code.

```cpp
// given: EHashers namedByTheData, const SReadOnlyByteSpan& content, const SReadOnlyByteSpan& recordedDigest
IHasherPtr hasher;
if (IHasher::create(namedByTheData, hasher) != ERET_OK) {
    return;
}

hasher->push(content);

uint8_t digest[64];
if (hasher->byteWidth() > sizeof(digest)) {
    return;
}

SByteSpan out(digest, hasher->byteWidth());
if (!hasher->finish(out)) {
    return;
}

if (CSecure::equals(out, recordedDigest)) {
    // The fingerprint matches, which is all it says. An MD5 match is evidence that two
    // files are the same file, never that either one is authentic: colliding pairs are
    // constructible to order, so EHASH_MD5 belongs on the reading side only.
}
```
