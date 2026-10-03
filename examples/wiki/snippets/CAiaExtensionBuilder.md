Attaches the two access descriptions a public CA normally publishes: an OCSP responder, and a URL serving this CA's own certificate so a relying party that received an incomplete chain can complete it. RFC 5280 4.2.2.1 requires AIA to be non-critical, so nothing here sets the critical flag.

```cpp
// given: CCertBuilder& builder
CAiaExtensionBuilder aia;
aia.addDescription(CAccessDescription(
    CAiaExtension::OID_OCSP_METHOD,
    CGeneralName(EGNAME_URI, CString("http://ocsp.example.com/"))
));
aia.addDescription(CAccessDescription(
    CAiaExtension::OID_CA_ISSUERS_METHOD,
    CGeneralName(EGNAME_URI, CString("http://crt.example.com/issuing-ca.cer"))
));

IExtensionPtr ext = aia.build();
if (!ext) {
    return; // a malformed method OID, or non-ASCII text in a URI, encodes to nothing
}

builder.extensions.add(ext);
```
