The 1:1 encoding for the ASCII-only X.509 string types (PrintableString, IA5String). It sanitizes instead of failing -- any character above 127 is written out as a space -- so if "not representable" has to be an error, check the input yourself before encoding it.

```cpp
// given: const CString& text
IStringEncoding<char>& enc = TAsciiEncoding<char>::get();

TReadOnlySpan<char> src = text.toSpan();
if (src.empty()) {
    return;
}

for (size_t i = 0; i < src.size; ++i) {
    if (static_cast<unsigned char>(src[i]) > 127) {
        return;   // would silently become ' '
    }
}

uint8_t bytes[CName::MAX_LEN];
SByteSpan dst(bytes, sizeof(bytes));
const size_t written = enc.encodeTo(dst, src);
if (written != src.size) {
    return;   // input longer than dst: encodeTo() clamps rather than reporting overflow
}
```
