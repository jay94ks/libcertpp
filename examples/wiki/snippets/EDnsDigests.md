Picks the digest a DS record is built with. The enumerator fixes the digest length, so a parent zone that wants both SHA-256 and SHA-384 publishes two DS records over the one DNSKEY; EDNSDIG_GOST is listed only so a DS carrying it can be named, and fromDnskey() reports failure for it rather than producing a digest of the wrong kind.

```cpp
// given: const CString& owner, const SDnskey& key
SDsRecord sha256;
if (!SDsRecord::fromDnskey(owner, key, EDNSDIG_SHA256, sha256)) {
    return;
}

SDsRecord sha384;
if (!SDsRecord::fromDnskey(owner, key, EDNSDIG_SHA384, sha384)) {
    return;
}

// 32 and 48 bytes respectively, and fromRdata() rejects any other length for these two.
const size_t shortDigest = sha256.digest.size();
const size_t longDigest = sha384.digest.size();

SDsRecord gost;
if (!SDsRecord::fromDnskey(owner, key, EDNSDIG_GOST, gost)) {
    // The expected outcome: there is no GOST R 34.11-94 hash here, and RFC 8624 forbids the
    // algorithm anyway, so nothing is produced instead of something unverifiable.
}
```
