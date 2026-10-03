Picks the OCSP responder out of a certificate's AuthorityInformationAccess extension. accessMethod() is an OID in dotted-decimal text, so match it against the id-ad-ocsp constant rather than guessing the service from the location's URL scheme.

```cpp
// given: const CCert& cert
auto aia = cert.extension<CAiaExtension>();
if (!aia) {
    return;
}

CString ocspUrl;
for (const CAccessDescription& desc : aia->descriptions()) {
    if (desc.accessMethod() == CString(CAiaExtension::OID_OCSP_METHOD)
        && desc.accessLocation().type() == EGNAME_URI)
    {
        ocspUrl = desc.accessLocation().text();
        break;
    }
}
// ocspUrl stays empty when this certificate names no OCSP responder at all
```
