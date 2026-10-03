Builds the `SEQUENCE { INTEGER r, INTEGER s }` that DSA/ECDSA signatures use, then reads it back. Every append*() appends to what the destination already holds rather than replacing it, which is how the inner members are concatenated before appendSequence() wraps them.

```cpp
// given: const CBigNum& r, const CBigNum& s
TArray<uint8_t> inner;
if (!CDer::appendBigInteger(inner, r) || !CDer::appendBigInteger(inner, s)) {
    return;
}

TArray<uint8_t> signature;
if (!CDer::appendSequence(signature, SReadOnlyByteSpan(inner.begin(), inner.size()))) {
    return;
}

SReadOnlyByteSpan content;
if (!CDer::readOuterSequence(SReadOnlyByteSpan(signature.begin(), signature.size()), content)) {
    return;
}

// readBigInteger() advances the cursor past the element it read, so the two calls take the
// members in order and an empty cursor afterwards means there was nothing trailing.
CBigNum readR, readS;
if (CDer::readBigInteger(content, readR) && CDer::readBigInteger(content, readS) && content.empty()) {
    // readR == r and readS == s
}
```
