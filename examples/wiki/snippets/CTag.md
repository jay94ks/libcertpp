Decodes the tag at the front of an encoded element and re-encodes it. Compare whole tags, not just value(): equals() takes the class and the constructed bit into account and deliberately ignores the raw low bits decode() keeps, so a decoded SEQUENCE tag does compare equal here.

```cpp
// given: SReadOnlyByteSpan element
size_t bytesRead = 0;
CTag tag = CTag::decode(element, bytesRead);

if (!tag) {
    return;
}

if (tag == CTag(CTag::SEQ)) {
    // universal, constructed, number 16
}

uint8_t buf[6];
size_t written = 0;

if (!tag.encode(TSpan<uint8_t>(buf, sizeof(buf)), written)) {
    return;
}

if (written != bytesRead || std::memcmp(buf, element.data, written) != 0) {
    return;     // only reachable on a non-minimal (BER) tag encoding
}
```
