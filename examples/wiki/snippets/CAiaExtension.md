Finds the OCSP responder to ask about this certificate. AuthorityInformationAccess holds several kinds of location at once, so the accessMethod OID has to be matched before the accessLocation means anything -- and what comes back is a URI this process still has to fetch itself; the extension only says where to look.

```cpp
// given: const CCert& cert
auto aia = cert.extension<CAiaExtension>();
if (!aia) {
    return; // no AIA: there is no OCSP responder to ask, and no issuer URL to chase
}

CString ocspUri;
CString caIssuersUri;
for (const CAccessDescription& ad : aia->descriptions()) {
    if (ad.accessLocation().type() != EGNAME_URI) {
        continue; // a directoryName accessLocation is legal but not fetchable as a URL
    }
    if (ad.accessMethod().compare(CAiaExtension::OID_OCSP_METHOD) == 0) {
        ocspUri = ad.accessLocation().text();
    } else if (ad.accessMethod().compare(CAiaExtension::OID_CA_ISSUERS_METHOD) == 0) {
        caIssuersUri = ad.accessLocation().text();
    }
}

if (!ocspUri.empty()) {
    // POST a COcspRequest to ocspUri from here; caIssuersUri serves the issuing CA's own
    // certificate, for a peer that sent an incomplete chain
}
```
