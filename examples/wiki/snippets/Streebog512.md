Compares a Streebog-512 digest against a test vector copied out of RFC 6986, which prints its vectors in the reverse of the byte order every implementation emits.

```cpp
// given: const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& digestAsPrintedInRfc
if (digestAsPrintedInRfc.size != 64) {
    return;
}

Streebog512 hasher;
hasher.push(message);

uint8_t digest[64];
SByteSpan out(digest, sizeof(digest));
if (!hasher.finish(out)) {
    return;
}

// finish() writes RFC 6986's byte position 0 first, which is what every published
// Streebog digest and every GOST signature expects -- and the reverse of the order the
// RFC's own text prints. One side has to be turned around before comparing.
uint8_t expected[64];
for (size_t i = 0; i < sizeof(expected); ++i) {
    expected[i] = digestAsPrintedInRfc[sizeof(expected) - 1 - i];
}

if (CSecure::equals(out, SReadOnlyByteSpan(expected, sizeof(expected)))) {
    // matches the published vector
}
```
