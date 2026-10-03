Issues a CRL. build() signs with the issuer certificate's attached private key, so that certificate must be one privateKey(IPrivateKeyPtr&) was called on; issuer() is optional and, when set, must equal that certificate's own subject() rather than naming anything else.

```cpp
// given: const CCert& caCert, const CCert& revokedCert, COctet& out
CCrlWriter writer;
writer.version(1)                     // v2, the version a CRL with extensions needs
      .issuer(caCert.subject())
      .thisUpdate(SDateTime::now(true));

SDateTime nextUpdate = writer.thisUpdate();
nextUpdate.year += 1;
writer.nextUpdate(nextUpdate);

if (writer.add(revokedCert, SDateTime::now(true), ECRLR_KEY_COMPROMISE) != ERET_OK) {
    return;
}

if (writer.build(caCert, out) != ERET_OK) {
    return; // ERET_KEY_EMPTY when caCert carries no private key to sign with
}
// out is a DER CertificateList a CCrlReader can decode and verifyBy(caCert)
```
