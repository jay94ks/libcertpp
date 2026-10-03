create() is the factory: it dispatches on the OID to a concrete type under x509/exts/ and falls back to a generic oid()/value()-only instance for anything this library does not model, so it never returns null -- and a critical extension nobody recognizes invalidates a certificate rather than being ignorable (RFC 5280 4.2).

```cpp
// given: const CString& oid, const COctet& extnValue, bool wasCritical
IExtensionPtr ext = IExtension::create(oid, extnValue);
ext->critical(wasCritical);

auto bc = std::dynamic_pointer_cast<CBasicConstraintsExtension>(ext);
if (bc) {
    if (bc->isCa() && bc->hasPathLenConstraint()) {
        // bc->pathLenConstraint() bounds how many intermediates may follow
    }
    return;
}

if (ext->critical()) {
    return; // unrecognized and critical: refuse the certificate
}

CBuffer der;
if (!ext->encode(der)) {
    return;
}
// der holds value()'s bytes, ready to splice back into an Extension SEQUENCE
```
