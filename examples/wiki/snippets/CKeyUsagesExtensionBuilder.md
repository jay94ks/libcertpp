Gives a CA certificate the only two usages a CA key should hold. setBits() replaces the whole set rather than OR-ing into it, so the combination goes in one call -- two calls would leave only the second. RFC 5280 4.2.1.3 says KeyUsage SHOULD be critical, which is a separate step on the built extension.

```cpp
// given: CCertBuilder& builder
CKeyUsagesExtensionBuilder ku;
ku.setBits(EKUSE_KEY_CERT_SIGN | EKUSE_CRL_SIGN);

IExtensionPtr ext = ku.build();
if (!ext) {
    return;
}

ext->critical(true);
builder.extensions.add(ext);
```
