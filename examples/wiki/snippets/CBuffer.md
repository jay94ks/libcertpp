Allocates a resizable byte buffer and hands its storage to a callee as a span. resize() keeps the bytes already there but leaves the bytes it adds uninitialized, so fill() is what makes a grown buffer defined.

```cpp
// given: SReadOnlyByteSpan source
CBuffer work;
if (!work.resize(source.size + 16)) {
    return;
}

if (!work.fill(0x00)) {
    return;
}

SByteSpan out = work.toSpan();
const size_t copied = source.copyTo(out);

// work.size() is still source.size + 16 here: a buffer's size is the capacity it was given,
// never what a callee actually wrote into it.
if (copied != source.size) {
    work.clear();
}
```
