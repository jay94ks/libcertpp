Publishes the single CRL URL covering every revocation reason, which is what almost every CA wants. CDistributionPoint has no setters, so its fields are passed to the constructor at once: hasReasons false (one unpartitioned CRL), and an empty crlIssuer meaning the certificate's own issuer also issues its CRL.

```cpp
// given: CCertBuilder& builder
TArray<CGeneralName> fullName;
fullName.add(CGeneralName(EGNAME_URI, CString("http://crl.example.com/issuing-ca.crl")));

CCdpExtensionBuilder cdp;
cdp.addPoint(CDistributionPoint(
    fullName,
    COctet(),               // nameRelativeToCrlIssuer: unused when fullName is given
    false,                  // hasReasons: this CRL covers every reason
    ECRLR_NONE,
    TArray<CGeneralName>()  // crlIssuer: same as the certificate's own issuer
));

IExtensionPtr ext = cdp.build();
if (!ext) {
    return;
}

builder.extensions.add(ext);
```
