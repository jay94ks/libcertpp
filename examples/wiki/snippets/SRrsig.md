Parses RRSIG RDATA, checks its validity window, and assembles the data the signature covers. toSignedPrefix() writes the eighteen fixed octets followed by the signer's name in canonical wire form -- the RDATA with the signature field omitted -- and the canonical RRset, which this library does not model, is appended to it by the caller.

```cpp
// given: const SReadOnlyByteSpan& rdata, const SReadOnlyByteSpan& canonicalRrset, uint32_t nowUnixSeconds
SRrsig sig;
if (!sig.fromRdata(rdata)) {
    return;                     // too short, or a malformed signer's name
}

if (nowUnixSeconds < sig.inception || nowUnixSeconds > sig.expiration) {
    return;                     // outside the signature's validity window
}

TArray<uint8_t> signedData;
if (!sig.toSignedPrefix(signedData)) {
    return;
}

const size_t prefixBytes = signedData.size();
if (!signedData.resize(prefixBytes + canonicalRrset.size)) {
    return;
}

std::memcpy(signedData.begin() + prefixBytes, canonicalRrset.data, canonicalRrset.size);

// signedData is now what the hash runs over. sig.signature is still in RRSIG's own
// encoding, so it goes through CDnssecKeys::signatureToNative() before verify().
```
