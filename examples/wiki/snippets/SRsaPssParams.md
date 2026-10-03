Reads the RSASSA-PSS parameters a certificate's signature was actually made with. All four fields are DEFAULTed, so a default-constructed SRsaPssParams already means SHA-1/MGF1-SHA-1/ salt 20 -- almost never what a real certificate uses, which is why these must be read.

```cpp
// given: const CCert& cert
SRsaPssParams pss;
if (!cert.rsaPssParams(pss)) {
    return; // not an id-RSASSA-PSS signature, or its parameters did not parse
}

// A SHA-256 PSS certificate reports EHASH_SHA256 with saltLength 32, not the 20-byte default.
IHasherPtr hasher;
if (IHasher::create(pss.hashAlgo, hasher) != ERET_OK) {
    return;
}

if (pss.mgfHashAlgo != pss.hashAlgo || pss.trailerField != 1) {
    return; // legal to encode, but not a shape this library's own verifyPss() expresses
}
// verifyBy() applies all of this itself; this is the route for verifying by hand
```
