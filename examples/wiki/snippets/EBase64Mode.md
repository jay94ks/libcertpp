Picks what a CBase64 object does, and for encoding it also picks whether the output wraps. A PEM body needs the 64-column breaks EB64M_ENCODE_BR inserts; EB64M_ENCODE emits one unbroken line, which is right for a URL or an HTTP header and wrong inside a PEM block.

```cpp
// given: SReadOnlyByteSpan der, bool forPem
CString body;
if (!CBase64::encode(body, der, forPem)) {
    return;
}

// The streaming form takes the same choice as a mode, and reset(mode) switches an existing
// object over instead of building a second one.
CBase64 codec(forPem ? EB64M_ENCODE_BR : EB64M_ENCODE);
if (codec.mode() != EB64M_DECODE) {
    codec.reset(EB64M_DECODE);
}

// Decoding ignores line breaks either way, so the wrap choice above costs nothing here.
CBuffer raw;
if (!CBase64::decode(raw, body)) {
    return;
}
```
