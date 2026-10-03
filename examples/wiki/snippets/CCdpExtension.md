Collects the URL of a CRL that covers the revocation reason being checked. A distribution point with no reasons field covers every reason; one that names reasons is a partition, and skipping the partition that carries the reason you care about looks exactly like "not revoked".

```cpp
// given: const CCert& cert
auto cdp = cert.extension<CCdpExtension>();
if (!cdp) {
    return; // no CRL distribution point published; revocation has to come from OCSP
}

CString crlUri;
for (const CDistributionPoint& point : cdp->points()) {
    if (point.hasReasons() && (point.reasons() & ECRLR_KEY_COMPROMISE) == 0) {
        continue; // this partition does not cover keyCompromise
    }

    for (const CGeneralName& name : point.fullName()) {
        if (name.type() == EGNAME_URI) {
            crlUri = name.text();
        }
    }
}

if (!crlUri.empty()) {
    // fetch crlUri, parse it with CCrlReader, and verifyBy() the issuer before trusting it
}
```
