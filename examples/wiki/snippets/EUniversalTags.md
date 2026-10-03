Picks the string type a name is written as. The kind selects which character set gets validated, so a text containing anything outside PrintableString's restricted set is refused rather than written under a tag that lies about it -- fall back to UTF8String on that refusal.

```cpp
// given: const IStreamPtr& out, const CWideString& text
CWriter writer(out, EAENC_DER);

if (writer.writeString(EAUTAG_STRING_P, text)) {
    return;
}

if (!writer.writeString(EAUTAG_STRING_UTF8, text)) {
    return;
}
```
