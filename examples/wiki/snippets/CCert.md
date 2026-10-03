Parses a DER certificate and reads the fields callers reach for first. importDer() also succeeds for an algorithm this library cannot resolve -- keyAlgo()/signAlgo() then hold the raw OID text and publicKey() is null, so check the key before using it rather than after.

```cpp
// given: const COctet& der
CCert cert;
if (cert.importDer(der) != ERET_OK) {
    return;
}

CName cn;
if (cert.subject().tryGet(ENAME_CN, cn)) {
    // cn holds the subject common name
}

if (!cert.publicKey()) {
    // An algorithm this library does not implement: keyAlgo() is its dotted-decimal OID,
    // every other parsed field is still good, and no signature work is possible.
    return;
}

// notBefore()/notAfter() are just data -- nothing in CCert compares them against a clock.
if (cert.keyUsages() & EKUSE_KEY_CERT_SIGN) {
    // this certificate's key is allowed to sign other certificates
}
```
