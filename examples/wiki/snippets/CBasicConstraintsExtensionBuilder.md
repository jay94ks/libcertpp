Issues an intermediate that may sign end-entity certificates and nothing else: setPathLenConstraint(0) means zero further CAs may follow it, which is a real restriction, not the default. The flag has to be set explicitly -- RFC 5280 4.2.1.9 requires BasicConstraints to be critical on a CA certificate.

```cpp
// given: CCertBuilder& builder
CBasicConstraintsExtensionBuilder bc;
bc.setIsCa(true).setPathLenConstraint(0);

IExtensionPtr ext = bc.build();
if (!ext) {
    return;
}

ext->critical(true);
builder.extensions.add(ext);
```
