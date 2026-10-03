Parses DNSKEY RDATA and derives the key tag an RRSIG refers to it by. The key tag is a checksum over the whole RDATA rather than a stored field, so it is computed on demand and can never disagree with the key it names; the public key stays in its DNS encoding until CDnssecKeys converts it.

```cpp
// given: const SReadOnlyByteSpan& rdata
SDnskey key;
if (!key.fromRdata(rdata)) {
    return;                     // too short, or a protocol field that is not 3
}

if (!key.isZoneKey() || key.isRevoked()) {
    return;                     // not a key that signs zone data (RFC 4034, RFC 5011)
}

uint16_t tag = 0;
if (!key.keyTag(tag)) {
    return;
}

// The flags field is 16 bits big-endian. 257 -- a zone key that is also a secure entry
// point, i.e. the conventional KSK -- is 0x0101 and reads the same either way round, so it
// is 256 that catches a byte-swapped field.
const bool keySigningKey = key.isSecureEntryPoint();

TArray<uint8_t> reencoded;
if (!key.toRdata(reencoded)) {
    return;
}
```
