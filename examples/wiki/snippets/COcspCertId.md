Identifies a certificate to a responder by hashes of its issuer's name and key. The one- argument make() lifts the issuerKeyHash out of the certificate's own AuthorityKeyIdentifier and is SHA-1 only; the general form hashes the issuer certificate itself and always works.

```cpp
// given: const CCert& cert, const CCert& issuer
COcspCertId id;
if (COcspCertId::make(cert, id) != ERET_OK) {
    // ERET_NOTSUP: no AuthorityKeyIdentifier keyIdentifier to reuse, so hash the issuer's
    // own Name and SubjectPublicKeyInfo.subjectPublicKey directly (RFC 6960 4.1.1).
    if (COcspCertId::make(cert, issuer, EHASH_SHA256, id) != ERET_OK) {
        return;
    }
}

if (!id.isFor(cert)) {
    return;
}

COctet der;
if (id.encode(der) != ERET_OK) {
    return;
}
// der is a complete CertID SEQUENCE TLV, the exact inverse of COcspCertId::decode()
```
