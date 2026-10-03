The client side. status() is the top-level responseStatus and has to be checked first: any value but EOCSP_OK carries no entries, no responder and no signature at all, so skipping it makes an EOCSP_TRY_LATER read as "this responder knows nothing about my certificate".

```cpp
// given: const COctet& responseDer, const CCert& responderCert, const CCert& cert, const COctet& sentNonce
COcspResponse response;
if (response.decode(responseDer) != ERET_OK) {
    return;
}

if (response.status() != EOCSP_OK) {
    return; // nothing beyond the status: retry, or treat the service as unavailable
}

if (response.verifySignature(responderCert) != ERET_OK) {
    return; // whether responderCert may answer for cert at all is a separate check
}

if (!CSecure::equals(response.nonceBytes().toSpan(), sentNonce.toSpan())) {
    return; // a replay, or an answer to somebody else's request
}

ERetCode rc = response.check(cert);
if (rc == ERET_ALREADY) {
    // cert is revoked
} else if (rc != ERET_OK) {
    return; // ERET_NOTSUP for an unknown certificate, ERET_INVAL for no entry at all
}
```
