One certificate policy OID out of (or into) a CertificatePolicies extension. The qualifiers stay as raw DER rather than parsed, because what a caller checks is the identifier itself -- a specific CA/Browser Forum policy, or anyPolicy.

```cpp
// given: const CCert& cert, CCertBuilder& issuing
auto policies = cert.extension<CPoliciesExtension>();
if (policies) {
    for (const CPolicyInformation& policy : policies->policies()) {
        if (policy.policyIdentifier() == CString(CPoliciesExtension::OID_ANY_POLICY)) {
            // anyPolicy: this certificate asserts no named policy at all
        }
    }
}

// Asserting one on a certificate being issued; the qualifiers may simply be left empty.
CPoliciesExtensionBuilder builder;
builder.addPolicy(CPolicyInformation(CString("2.23.140.1.2.1"), COctet()));

IExtensionPtr ext = builder.build();
if (!ext) {
    return; // a policyIdentifier that is not well-formed dotted-decimal
}
issuing.extensions.add(ext);
```
