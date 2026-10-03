Decides whether a certificate may be used for TLS server authentication. The two failure modes run opposite ways: no ExtendedKeyUsage at all means the key is unrestricted and the use is permitted, while an ExtendedKeyUsage that exists and omits serverAuth forbids it outright.

```cpp
// given: const CCert& cert
auto eku = cert.extension<CEkuExtension>();
if (!eku) {
    return; // unrestricted: a certificate with no EKU may be used for anything
}

if (eku->has(CEkuExtension::OID_SERVER_AUTH)) {
    return; // explicitly permitted
}

if (eku->has(CEkuExtension::OID_ANY_EXTENDED_KEY_USAGE)) {
    return; // anyExtendedKeyUsage waives the restriction the extension otherwise imposes
}

// Present, and serverAuth is not among its purposes: refuse this certificate for TLS,
// however valid the rest of it is. A code-signing certificate lands here.
```
