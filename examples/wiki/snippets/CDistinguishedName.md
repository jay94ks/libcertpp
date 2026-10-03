Parses a "CN=..., O=..., C=..." distinguished name and reads one component back. tryParse() fails outright on an attribute type it does not recognize rather than dropping it: a dropped attribute would make two genuinely different names compare equal, and DN equality is what matches an issuer to a subject.

```cpp
// given: const CString& text
CDistinguishedName dn;
if (!CDistinguishedName::tryParse(dn, text)) {
    return;
}

CName cn;
if (!dn.tryGet(ENAME_CN, cn)) {
    return;
}

// trySet() refuses to replace a component that is already present unless told to overwrite,
// so the second argument is not optional once the name came from somewhere else.
if (!dn.trySet(CName(ENAME_O, "Example Corp"), true)) {
    return;
}

CString rendered;
dn.toString(rendered);
```
