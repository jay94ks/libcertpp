Asserts one CA-specific policy OID on a certificate being issued. The empty COctet is the policyQualifiers field: PolicyInformation keeps qualifiers as raw DER rather than modelling CPSuri/UserNotice, so passing nothing is how a certificate asserts a bare policy identifier -- which is what the overwhelming majority do.

```cpp
// given: CCertBuilder& builder
CPoliciesExtensionBuilder cp;
cp.addPolicy(CPolicyInformation(CString("1.3.6.1.4.1.99999.1.2"), COctet()));

IExtensionPtr ext = cp.build();
if (!ext) {
    return; // the policy identifier wasn't well-formed dotted-decimal
}

builder.extensions.add(ext);
```
