The rule set is not decoration -- it decides which encodings are legal. These bytes are a valid (if wasteful) BER OCTET STRING whose length uses the long form below 128, and an invalid DER one; read X.509 input with EAENC_DER or a hand-crafted non-canonical length slips past.

```cpp
const uint8_t data[] = { 0x04, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
SReadOnlyByteSpan source(data, sizeof(data));

CTag tag;
SReadOnlyByteSpan content;
size_t bytesRead = 0;

if (CDecoder::readEncodedValue(source, EAENC_BER, tag, content, bytesRead)) {
    // accepted: BER permits any well-formed length form
}

if (!CDecoder::readEncodedValue(source, EAENC_DER, tag, content, bytesRead)) {
    // rejected: DER and CER both require the minimal length form
}
```
