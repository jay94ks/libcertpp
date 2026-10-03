Finds a certificate's own entry in a CRL, which is what carries the revocation time and reason. reason() is ECRLR_NONE for an entry with no cRLReason extension: that is an absent reason code, not a weaker revocation.

```cpp
// given: const CCrlReader& crl, const CCert& cert
CCrlRevokationInfo info;
if (crl.find(cert, info) != ERET_OK) {
    return; // not listed in this CRL
}

if (info.timestamp().isZero()) {
    return; // no revocationDate to act on
}

if (info.reason() == ECRLR_KEY_COMPROMISE) {
    // the key itself is compromised, so signatures made before revocationDate are suspect
    // too -- unlike ECRLR_SUPERSEDED, where only the certificate was replaced
}
// info.rawData() is the entry's own DER, as CCrlWriter would re-embed it verbatim
```
