Restricts a leaf to the two TLS roles it actually fills. Every addPurpose() widens what the certificate may do, so the restriction is in what is left out -- and adding OID_ANY_EXTENDED_KEY_USAGE alongside them would cancel the whole extension's effect.

```cpp
// given: CCertBuilder& builder
CEkuExtensionBuilder eku;
eku.addPurpose(CEkuExtension::OID_SERVER_AUTH);
eku.addPurpose(CEkuExtension::OID_CLIENT_AUTH);

IExtensionPtr ext = eku.build();
if (!ext) {
    return; // a purpose string that isn't well-formed dotted-decimal encodes to nothing
}

builder.extensions.add(ext);
```
