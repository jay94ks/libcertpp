Decodes a CRL and asks whether it revokes a certificate. check() only looks the serial up: verifyBy() and the issuer-name comparison are separate and both necessary, since a CRL from an unrelated CA with a colliding serial would otherwise produce a verdict of its own.

```cpp
// given: const COctet& crlDer, const CCert& issuerCert, const CCert& cert
CCrlReader crl;
if (crl.decode(crlDer) != ERET_OK) {
    return;
}

if (crl.verifyBy(issuerCert) != ERET_OK) {
    return; // one signature check, and nothing else -- not thisUpdate()/nextUpdate()
}

if (crl.issuer() != cert.issuer()) {
    return; // a real CRL about some other CA's certificates
}

ERetCode rc = crl.check(cert);
if (rc == ERET_ALREADY) {
    // cert is listed: revoked
} else if (rc != ERET_OK) {
    return; // a genuine error, not a revocation verdict either way
}
```
