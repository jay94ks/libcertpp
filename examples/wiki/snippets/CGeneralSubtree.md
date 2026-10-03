One permitted or excluded name for a NameConstraints extension. minimum()/maximum() are essentially never used in practice -- pass 0 and false -- and a DNS subtree is written with a leading dot, which is what makes the constraint cover everything below the name.

```cpp
// given: CCertBuilder& issuing
CNameConstraintsExtensionBuilder nc;
nc.addPermittedSubtree(
    CGeneralSubtree(CGeneralName(EGNAME_DNS, CString(".example.com")), 0, false, 0)
);
nc.addExcludedSubtree(
    CGeneralSubtree(CGeneralName(EGNAME_DNS, CString(".internal.example.com")), 0, false, 0)
);

IExtensionPtr ext = nc.build();
if (!ext) {
    return;
}

// RFC 5280 4.2.1.10 requires NameConstraints to be marked critical.
ext->critical(true);
issuing.extensions.add(ext);
```
