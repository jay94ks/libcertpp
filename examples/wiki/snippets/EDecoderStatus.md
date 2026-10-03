Classifies why a header would not decode, in the decoder's own vocabulary. CDecoder's public entry points report only a bool, so a caller feeding in a document a chunk at a time has to tell EDEC_NEED_MORE -- the one status worth retrying with more bytes -- from the final ones.

```cpp
// given: SReadOnlyByteSpan sofar
if (!sofar.data) {
    return EDEC_BAD_ARGS;
}

CTag tag;
SReadOnlyByteSpan content;
size_t bytesRead = 0;

if (CDecoder::readEncodedValue(sofar, EAENC_DER, tag, content, bytesRead)) {
    return EDEC_OK;
}

// The length octet does not sit at a fixed offset: a high-tag-number form spends several
// octets on the tag alone, so ask CTag how many it consumed.
size_t tagBytes = 0;
if (!CTag::decode(sofar, tagBytes) || sofar.size <= tagBytes) {
    return EDEC_NEED_MORE;
}

const uint8_t lengthOctet = sofar[tagBytes];
if (lengthOctet == 0xFF) {
    return EDEC_RESERVED;                   // X.690 8.1.3.5 (c): reserved, never legal
}

if (lengthOctet == 0x80) {
    return EDEC_INDEFINITE;                 // legal BER, prohibited under DER/CER
}

if ((lengthOctet & 0x80) != 0 && size_t(lengthOctet & 0x7F) > sizeof(size_t)) {
    return EDEC_TOO_BIG;                    // a length no size_t could hold
}

return EDEC_NEED_MORE;
```
