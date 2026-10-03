The UTF-8 codec X.509's UTF8String fields go through. measure() is what sizes the destination: for wchar_t the byte count and the character count differ, so sizing from the source's own length truncates every string with a non-ASCII character in it.

```cpp
// given: const CWideString& text
IStringEncoding<wchar_t>& enc = TUtf8Encoding<wchar_t>::get();
TReadOnlySpan<wchar_t> src = text.toSpan();

CBuffer utf8;
const size_t bytes = enc.measure(src);
if (bytes == 0 || !utf8.resize(bytes)) {
    return;
}

if (enc.encodeTo(utf8.toSpan(), src) != bytes) {
    return;
}

// Going back the other way, decodeFrom() reports characters written, not bytes consumed --
// and it takes its destination by non-const reference, so it needs a named span.
CWideString back;
if (!back.resize(src.size)) {
    return;
}

TSpan<wchar_t> dst = back.toSpan();
if (enc.decodeFrom(dst, utf8.toSpan()) != src.size) {
    back.clear();
}
```
