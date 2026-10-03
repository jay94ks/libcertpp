One SingleResponse out of a response. status() is the only field always meaningful: revocationTime()/reason() say nothing unless status() is EOCSPENT_REVOKED, and nextUpdate() is optional, reporting SDateTime::isZero() when the responder offered no caching guidance.

```cpp
// given: const COcspResponse& response, const CCert& cert
COcspEntry entry;
if (response.find(cert, entry) != ERET_OK) {
    return; // this response carries no entry for cert
}

if (entry.status() == EOCSPENT_REVOKED) {
    if (entry.revocationTime().isZero()) {
        return; // a revoked entry with no revocationTime is malformed
    }
    // entry.reason() is ECRLR_NONE when the responder gave no reason code
    return;
}

if (entry.status() != EOCSPENT_GOOD) {
    return; // EOCSPENT_UNKNOWN: this responder does not answer for cert
}

if (entry.nextUpdate().isZero()) {
    return; // good, but with no stated horizon -- do not cache the answer
}
// entry.thisUpdate() is when the status was known correct, and is always present
```
