Produces a responder's answer. status() defaults to EOCSP_INTERNAL rather than EOCSP_OK, so a successful response has to say so explicitly, and build() signs with the responder certificate's attached private key.

```cpp
// given: const CCert& responderCert, const CCert& cert, const CCert& issuer, const COctet& requestNonce, COctet& out
SDateTime thisUpdate = SDateTime::now(true);
SDateTime nextUpdate = thisUpdate;
nextUpdate.year += 1;

COcspResponseBuilder builder;
builder.status(EOCSP_OK)
       .producedAt(thisUpdate)
       .nonceBytes(requestNonce);    // echoed back from the request, unchanged

if (builder.add(cert, issuer, EOCSPENT_GOOD, thisUpdate, nextUpdate) != ERET_OK) {
    return;
}

if (builder.build(responderCert, out) != ERET_OK) {
    return; // ERET_KEY_EMPTY when responderCert has no private key attached
}
// out is a DER OCSPResponse a COcspResponse can decode and verifySignature(responderCert)
```
