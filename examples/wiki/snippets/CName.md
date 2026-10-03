Builds one DN attribute and renders it. A CName stores non-ASCII bytes escaped internally; toString(out, false) undoes that and gives the original bytes back, while toString(out, true) shows the stored form -- so the default is what you want for display.

```cpp
// given: const CString& value
CName cn(ENAME_CN, value.toPtr(), value.size());
if (!cn) {
    return;   // a null or empty input yields an empty CName, not a reported failure
}

CString plain;
cn.toString(plain, false);

// equals() short-circuits on the precomputed DJB hash before comparing bytes, so it is the
// cheap comparison; compare() is the ordering one.
CName other(ENAME_CN, "example.com");
if (cn.equals(other)) {
    // same type and same value
}

if (CName::typeOf(CName::keyOf(cn.type())) != cn.type()) {
    return;   // key <-> type is a round trip for every recognized attribute
}
```
