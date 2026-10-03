Encodes an INTEGER in two steps, because that is how the class is split: encodeInteger() writes only the content octets, and writeEncodedValue() wraps content in its tag and length. Each reports its own bytesWritten, and that -- not the buffer's sizeof -- is the encoded length.

```cpp
// given: int64_t serial
uint8_t content[8];
size_t contentLength = 0;

if (!CEncoder::encodeInteger(TSpan<uint8_t>(content, sizeof(content)), serial, contentLength)) {
    return;
}

const CTag tag(EAUTAG_INTEGER, false);
SReadOnlyByteSpan body(content, contentLength);

uint8_t element[16];
size_t elementLength = 0;

if (CEncoder::encodedValueSize(tag, body) > sizeof(element)) {
    return;
}

if (!CEncoder::writeEncodedValue(TSpan<uint8_t>(element, sizeof(element)), EAENC_DER, tag, body, elementLength)) {
    return;
}

// element[0 .. elementLength) is the complete DER tag-length-value
```
