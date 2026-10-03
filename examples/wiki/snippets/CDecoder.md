Reads a DER document's outer SEQUENCE and walks its members. The output span is the value's *content* octets, while bytesRead counts the tag and length too -- so iterating with the span is what descends into a constructed value, and iterating with bytesRead is what steps over it.

```cpp
// given: SReadOnlyByteSpan der
CTag tag;
SReadOnlyByteSpan content;
size_t bytesRead = 0;

if (!CDecoder::readEncodedValue(der, EAENC_DER, tag, content, bytesRead)) {
    return;
}

if (tag != CTag(CTag::SEQ)) {
    return;
}

SReadOnlyByteSpan cursor = content;
CTag childTag;
SReadOnlyByteSpan childContent;

while (CDecoder::readNextElement(cursor, EAENC_DER, childTag, childContent)) {
    int64_t number = 0;
    if (childTag == CTag(CTag::INTEGER) && CDecoder::decodeInteger(childContent, number)) {
        // number holds this member's value
    }
}
```
