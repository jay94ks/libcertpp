Matches a peer's hostname against the certificate. SubjectAltName is the field identity is matched against -- a hostname that only appears in the subject DN's common name is not a match, and a certificate with no SAN at all fails rather than falling back to the CN.

```cpp
// given: const CCert& cert, const CString& expectedHost
auto san = cert.extension<CSanExtension>();
if (!san) {
    return; // no SubjectAltName: reject, rather than reading cert.subject()'s CN instead
}

for (const CGeneralName& name : san->names()) {
    if (name.type() != EGNAME_DNS) {
        continue; // an iPAddress entry carries 4 or 16 bytes in raw(), not text()
    }

    if (name.text().compare(expectedHost.toPtr()) == 0) {
        return; // this certificate is bound to the host being connected to
    }
}

// No SAN entry matched: reject, even if cert.subject()'s CN happens to equal expectedHost.
```
