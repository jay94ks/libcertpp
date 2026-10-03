Points a certificate being issued at the key that signed it, by copying the issuer's own SubjectKeyIdentifier bytes verbatim. Copy them rather than recomputing a hash of the issuer's public key: the CA chose those bytes, and only a value that matches its CSkiExtension exactly lets a path builder pair the two.

```cpp
// given: CCertBuilder& builder, const CCert& issuerCert
COctet issuerSki;
if (issuerCert.subjectKeyIdentifier(issuerSki) != ERET_OK) {
    return; // the issuer carries no SubjectKeyIdentifier, so there is nothing to point at
}

CAkiExtensionBuilder aki;
aki.setKeyIdentifier(issuerSki);

// Deliberately no addAuthorityCertIssuer()/setAuthorityCertSerialNumber(): that pair pins
// this certificate to one exact issuing certificate, which stops resolving the moment the
// CA re-issues or gets cross-signed. The key identifier survives both.

IExtensionPtr ext = aki.build();
if (!ext) {
    return;
}

builder.extensions.add(ext);
```
