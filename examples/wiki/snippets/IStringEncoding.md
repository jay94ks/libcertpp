Obtained from an encoding's get() factory, never constructed directly. Call measure() first: the number of bytes an encoding needs is not the number of characters it was handed, for anything outside ASCII.

```cpp
// given: const CString& text
IStringEncoding<char>& enc = TUtf8Encoding<char>::get();

TReadOnlySpan<char> src = text.toSpan();
const size_t needed = enc.measure(src);
if (needed == 0) {
    return;
}

CBuffer out;
if (!out.resize(needed)) {
    return;
}

const size_t written = enc.encodeTo(out.toSpan(), src);
if (written == 0) {
    return;   // 0 is the failure report; there is no error code here
}

// written, not needed, is the length to carry forward.
COctet encoded;
if (!encoded.store(out.toPtr(), written)) {
    return;
}
```
