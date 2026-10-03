Zeroizes and compares secret bytes. zero() survives the dead-store elimination a plain memset() does not, and equalsMask() reads both inputs in full and yields a 0xFF/0x00 mask, so neither the matching-prefix length nor the outcome itself has to be branched on.

```cpp
// given: SReadOnlyByteSpan candidate, SReadOnlyByteSpan expected, SReadOnlyByteSpan fallback
uint8_t chosen[32];
SByteSpan out(chosen, sizeof(chosen));

const uint8_t mask = CSecure::equalsMask(candidate, expected);
if (!CSecure::select(mask, expected, fallback, out)) {
    CSecure::zero(out);
    return;   // a null span, or the three sizes did not all match
}

// Where the outcome is not itself sensitive, equals() is the same comparison with a bool.
if (!CSecure::equals(candidate, expected)) {
    // a mismatch, reported anyway -- a differing length also lands here
}

CSecure::zero(out);
```
