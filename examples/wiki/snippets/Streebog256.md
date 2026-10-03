Hashes a message for a 256-bit GOST R 34.10-2012 signature. The 256-bit Streebog is its own function, not the 512-bit one cut short.

```cpp
// given: const SReadOnlyByteSpan& message, SByteSpan digestToSign
if (digestToSign.size < 32) {
    return;
}

Streebog256 hasher;
if (hasher.push(message) != message.size) {
    return;
}

if (!hasher.finish(digestToSign)) {
    return;
}

// RFC 6986 6.1 gives this function the initializing value (00000001)^64 where the 512-bit
// one starts from 0^512, so the two states diverge at the first block. Feeding a GOST
// 256-bit key the leading 32 bytes of a Streebog-512 digest instead produces a signature
// that verifies against nothing.
```
