Checks that a CA's key is actually permitted to sign certificates before a path is built through it. Reading the extension rather than CCert::keyUsages() is the point: that shortcut returns EKUSE_NONE both for an absent extension (no restriction) and for one that permits nothing, and those two mean opposite things.

```cpp
// given: const CCert& caCert
auto ku = caCert.extension<CKeyUsagesExtension>();
if (!ku) {
    return; // no KeyUsage extension at all: the key is unrestricted
}

if ((ku->bits() & EKUSE_KEY_CERT_SIGN) == 0) {
    return; // present, and this key may not verify certificate signatures -- whatever
            // BasicConstraints claims about it being a CA
}

if ((ku->bits() & EKUSE_CRL_SIGN) != 0) {
    // the same CA key may also sign the CRL this certificate's CDP points at
}
```
