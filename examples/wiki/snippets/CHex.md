Decodes a hex string into bytes. The "0x" prefix is optional and an odd digit count is treated as left-padded with one '0', so "abc" and "0abc" decode identically -- meaning a string that lost a digit decodes successfully with every byte shifted. Check the length you expected.

```cpp
// given: const char* digits, SReadOnlyByteSpan expectedKeyId
TArray<uint8_t> bytes;
if (!CHex::decode(digits, bytes)) {
    return;   // a character outside [0-9a-fA-F]; bytes is left untouched
}

if (bytes.size() != 20) {
    return;   // a SHA-1 key identifier: an odd-length input would not have failed above
}

SReadOnlyByteSpan keyId(bytes.begin(), bytes.size());
if (!keyId.sequencialEqual(expectedKeyId)) {
    return;   // content comparison; operator== here would compare pointers instead
}
```
