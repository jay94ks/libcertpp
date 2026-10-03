The responder side. decode() takes a CBuffer, not a COctet, and an unsigned request is both legal and the common case -- requestorName() being present is a claim and not evidence, so verifySignature() is what settles it, reporting ERET_INVAL for a request carrying no signature.

```cpp
// given: const CBuffer& requestDer, const CCert& requestorCert, const CCert& cert
COcspRequest request;
if (request.decode(requestDer) != ERET_OK) {
    return;
}

if (!request.requestorName().empty()) {
    if (request.verifySignature(requestorCert) != ERET_OK) {
        return; // unsigned, or not signed by the key requestorCert carries
    }
}

if (!request.contains(cert)) {
    return; // no CertID in this request matches cert
}

if (request.nonceBytes().empty()) {
    return; // no RFC 8954 nonce was sent, so there is nothing to echo back
}
// pass request.nonceBytes() to COcspResponseBuilder::nonceBytes() unchanged
```
