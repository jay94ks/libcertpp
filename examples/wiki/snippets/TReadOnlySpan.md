SReadOnlyByteSpan is the alias a caller names for an immutable, non-owning view. Its operator== compares the pointer and the size, not the bytes -- comparing contents is sequencialEqual(), and for anything secret it is CSecure::equals().

```cpp
// given: SReadOnlyByteSpan first, SReadOnlyByteSpan second
if (first.empty() || second.empty()) {
    return;
}

if (first == second) {
    // the very same buffer, not merely equal bytes
}

if (first.sequencialEqual(second)) {
    // equal contents, wherever they live
}

// slice() clamps to what is there instead of running off the end, so an over-long length or
// an offset past the end yields a shorter or empty span rather than a wild read.
SReadOnlyByteSpan body = first.slice(2);
if (body.size >= 4 && body.slice(0, 4).sequencialEqual(second.slice(0, 4))) {
    // the two share a 4-byte prefix after the first's first two bytes
}
```
