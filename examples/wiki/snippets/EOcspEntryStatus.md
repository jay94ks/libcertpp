Selects what a responder asserts about one certificate. EOCSPENT_GOOD and EOCSPENT_REVOKED are both positive statements; EOCSPENT_UNKNOWN means this responder does not answer for the certificate at all and is not a synonym for "not revoked".

```cpp
// given: COcspResponseBuilder& builder, const CCert& cert, const CCert& issuer, bool isRevoked, const SDateTime& revokedAt
SDateTime thisUpdate = SDateTime::now(true);

if (!isRevoked) {
    if (builder.add(cert, issuer, EOCSPENT_GOOD, thisUpdate) != ERET_OK) {
        return;
    }
    return;
}

// revocationTime is required for EOCSPENT_REVOKED -- the trailing argument, after the
// optional nextUpdate and reason, so count the positions rather than copying from above.
ERetCode rc = builder.add(
    cert, issuer, EOCSPENT_REVOKED, thisUpdate, SDateTime(), ECRLR_KEY_COMPROMISE, revokedAt
);
if (rc != ERET_OK) {
    return;
}
```
