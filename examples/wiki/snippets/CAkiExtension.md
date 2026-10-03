Uses the AuthorityKeyIdentifier to pick the right key out of a CA that holds several -- a CA that has re-keyed keeps the same subject name, so the name alone no longer identifies which of its certificates signed this one. The identifier is only a hint for choosing a candidate: verifyBy() is what decides.

```cpp
// given: const CCert& cert, const CCert& candidateIssuer
auto aki = cert.extension<CAkiExtension>();
if (!aki || !aki->hasKeyIdentifier()) {
    // Every field of AuthorityKeyIdentifier is OPTIONAL, so an AKI that is present can
    // still carry no keyIdentifier at all -- fall back to matching by issuer name.
    return;
}

COctet issuerSki;
if (candidateIssuer.subjectKeyIdentifier(issuerSki) != ERET_OK) {
    return;
}

const COctet& wanted = aki->keyIdentifier();
if (wanted.size() != issuerSki.size()
    || std::memcmp(wanted.toPtr(), issuerSki.toPtr(), wanted.size()) != 0) {
    return; // a different key of the same CA, or a different CA altogether
}

if (cert.verifyBy(candidateIssuer) == ERET_OK) {
    // this one link holds -- dates, basicConstraints and revocation are still unchecked
}
```
