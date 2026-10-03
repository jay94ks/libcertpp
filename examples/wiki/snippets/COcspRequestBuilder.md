Builds a client's status request. Setting requestorCert() is taken as an instruction to sign, so that certificate must carry a private key; leave it unset for the ordinary unsigned request. Keep the generated nonce -- it is what rules out a replayed response later.

```cpp
// given: const CCert& cert, const CCert& issuer, COctet& outRequest, COctet& outNonce
COcspRequestBuilder builder;
if (builder.add(cert, issuer, EHASH_SHA1) != ERET_OK) {
    return;
}

if (builder.generateNonce(16) != ERET_OK) {
    return; // the CSPRNG failed; sending an un-nonced request is a separate decision
}
outNonce = builder.nonceBytes();

if (builder.build(outRequest) != ERET_OK) {
    return; // ERET_INVAL when no certificate ID was added
}
// outRequest is the DER OCSPRequest to POST; the response's nonce must equal outNonce
```
