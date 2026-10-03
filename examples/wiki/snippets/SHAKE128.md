Runs a rejection sampler off SHAKE128's output stream with squeeze(), the call that makes this a genuine XOF: it continues where the last call stopped and byteWidth() does not cap it.

```cpp
// given: const SReadOnlyByteSpan& seed, SByteSpan samples
SHAKE128 xof;
if (xof.push(seed) != seed.size) {
    return;
}

size_t filled = 0;
while (filled < samples.size) {
    uint8_t candidate = 0;
    if (!xof.squeeze(SByteSpan(&candidate, 1))) {
        return;
    }

    // Draw a uniform 0..239 by discarding the 16 values that would bias it, rather than
    // reducing them -- which is the shape FIPS 203's and FIPS 204's samplers need, and
    // the reason squeeze() exists: how many bytes that takes is not known in advance.
    if (candidate < 240) {
        samples.data[filled++] = candidate;
    }
}

// Do not call finish() on this instance now. It reports the stream's first byteWidth()
// bytes and deliberately ignores squeeze()'s cursor, so the two interleaved give output
// that overlaps itself. Pick one of them per instance.
```
