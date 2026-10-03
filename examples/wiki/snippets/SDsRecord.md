Checks a DS record published by the parent zone against the DNSKEY it should vouch for, then builds the DS the child zone would submit. matches() recomputes the digest and compares it in constant time, so never pull .digest out and memcmp it; the owner name has to be passed in because the digest covers the canonical owner name followed by the DNSKEY RDATA, and the RDATA alone does not carry it.

```cpp
// given: const CString& owner, const SDnskey& key, const SReadOnlyByteSpan& dsRdata
SDsRecord published;
if (!published.fromRdata(dsRdata)) {
    return false;               // too short, or a digest length its digest type disallows
}

if (!published.matches(owner, key)) {
    return false;               // key tag, algorithm, digest type or digest disagrees
}

SDsRecord mine;
if (!SDsRecord::fromDnskey(owner, key, EDNSDIG_SHA256, mine)) {
    return false;
}

TArray<uint8_t> rdata;
if (!mine.toRdata(rdata)) {
    return false;
}

return true;                    // rdata holds the DS RDATA to hand to the parent zone
```
