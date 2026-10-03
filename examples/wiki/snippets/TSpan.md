SByteSpan is the mutable alias a caller names, and it carries capacity, not length: the span over a 64-byte buffer keeps reporting 64 until something narrows it. Track what was written and slice() down to that.

```cpp
// given: SReadOnlyByteSpan source
uint8_t buf[64];
SByteSpan out(buf, sizeof(buf));
out.clear();

const size_t written = source.copyTo(out);
if (written == 0) {
    return;
}

// out.size is still 64 -- copyTo() reports a length, it does not narrow the span. Pass the
// narrowed span onward, not `out`, or everything downstream reads the padding too.
SByteSpan used = out.slice(0, written);
const SDjbValue tag = CDjb::compute(used);
if (tag == 0) {
    return;
}

CSecure::zero(out);   // the whole buffer, padding included
```
