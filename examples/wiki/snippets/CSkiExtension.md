Reads the bytes a store indexes CA certificates by: a child's CAkiExtension names the issuer it wants by exactly this value. The bytes are opaque -- usually the SHA-1 of the public key, but nothing requires that -- so they are compared, never recomputed and checked.

```cpp
// given: const CCert& caCert
auto ski = caCert.extension<CSkiExtension>();
if (!ski) {
    return; // no SubjectKeyIdentifier: children of this CA can only name it by issuer DN
}

const COctet& keyId = ski->keyIdentifier();
if (keyId.empty()) {
    return; // present, but its extnValue didn't decode as an OCTET STRING
}

// keyId.toPtr()/keyId.size() is the key to store caCert under in the issuer store that
// CAkiExtension lookups go through. 20 bytes is RFC 5280 4.2.1.2's method-1 length, but a
// CA may choose any other, so nothing here may assume a length.
```
