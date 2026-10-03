Checks a certificate against a policy OID a relying party insists on. anyPolicy satisfies any requirement, which is the subtlety here: a CA that asserts it has asserted nothing specific, so treating anyPolicy as a match is a policy decision and not a free one.

```cpp
// given: const CCert& cert, const char* requiredPolicyOid
auto cp = cert.extension<CPoliciesExtension>();
if (!cp) {
    return; // no CertificatePolicies: the certificate asserts no policy to match against
}

for (const CPolicyInformation& policy : cp->policies()) {
    if (policy.policyIdentifier().compare(requiredPolicyOid) == 0) {
        // the exact policy was asserted; policyQualifiersRaw() holds the CPS pointer and
        // user notices, still DER-encoded, if this caller ever needs them
        return;
    }

    if (policy.policyIdentifier().compare(CPoliciesExtension::OID_ANY_POLICY) == 0) {
        return; // accepted only because this caller chose to honour anyPolicy
    }
}

// no policy matched: reject
```
