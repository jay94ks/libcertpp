Transcodes between char and wchar_t one span at a time -- what TString::convertTo() uses underneath. The template arguments are <destination, source> in that order, and measure() has to run before convert() because the destination length is not the source length.

```cpp
// given: const CString& narrow
TStringConverter<wchar_t, char> conv;

TReadOnlySpan<char> src = narrow.toSpan();
const size_t units = conv.measure(src);
if (units == 0) {
    return;
}

CWideString wide;
if (!wide.resize(units)) {
    return;
}

// An instance carries an mbstate_t, so one converter belongs to one conversion: reuse it
// for a second, unrelated string and it resumes mid-sequence.
TSpan<wchar_t> dst = wide.toSpan();
const size_t converted = conv.convert(dst, src);
if (converted != units) {
    wide.clear();
}
```
