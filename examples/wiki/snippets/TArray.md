Collects bytes into a growable TArray<uint8_t>, the array type the library's own byte-producing calls fill. Every growing call reports failure with a bool rather than throwing, and reserve() up front turns one reallocation per add() into one in total.

```cpp
// given: SReadOnlyByteSpan source
TArray<uint8_t> bytes;
if (!bytes.reserve(source.size)) {
    return;
}

for (size_t i = 0; i < source.size; ++i) {
    if (!bytes.add(source.data[i])) {
        return;
    }
}

// A leading zero byte is not part of an unsigned magnitude; remove() shifts the tail down
// and reports false only for an out-of-range index.
while (bytes.size() > 1 && bytes[0] == 0x00) {
    if (!bytes.remove(0)) {
        return;
    }
}
```
