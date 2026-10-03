Constrains an intermediate to one DNS namespace, minus a sub-domain carved out of it: on overlap, the excluded subtree wins. The 0/false/0 tail of each CGeneralSubtree is minimum, hasMaximum and maximum -- RFC 5280 permits no other values, so those are the only ones to pass. NameConstraints only has meaning on a CA certificate, and must be critical.

```cpp
// given: CCertBuilder& builder
CNameConstraintsExtensionBuilder nc;
nc.addPermittedSubtree(CGeneralSubtree(
    CGeneralName(EGNAME_DNS, CString("example.com")), 0, false, 0
));
nc.addExcludedSubtree(CGeneralSubtree(
    CGeneralName(EGNAME_DNS, CString("internal.example.com")), 0, false, 0
));

IExtensionPtr ext = nc.build();
if (!ext) {
    return;
}

ext->critical(true);
builder.extensions.add(ext);
```
