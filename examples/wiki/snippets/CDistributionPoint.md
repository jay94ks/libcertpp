Reads the CRL locations out of a CRLDistributionPoints extension. hasReasons() being false is not "no reasons" -- it means the CRL at this point covers every revocation reason, which is the case to handle rather than skip.

```cpp
// given: const CCert& cert
auto cdp = cert.extension<CCdpExtension>();
if (!cdp) {
    return;
}

for (const CDistributionPoint& point : cdp->points()) {
    if (point.hasReasons() && (point.reasons() & ECRLR_KEY_COMPROMISE) == 0) {
        continue; // this point's CRL would not list a key-compromise revocation
    }

    if (!point.crlIssuer().empty()) {
        continue; // issued by a different CA than the certificate's own issuer
    }

    for (const CGeneralName& name : point.fullName()) {
        if (name.type() == EGNAME_URI) {
            // name.text() is a CRL to fetch and hand to CCrlReader::decode()
        }
    }
}
```
