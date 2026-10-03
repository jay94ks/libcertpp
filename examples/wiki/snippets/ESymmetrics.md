Selects which built-in symmetric algorithm builtIn() returns, and travels on every key that algorithm produces so a caller does not have to track it separately.

```cpp
// given: crypto::ESymmetrics which
crypto::ISymmetricPtr algo = crypto::ISymmetric::builtIn(which);
if (!algo) {
    return; // ESYM_MAX, ESYM_UNKNOWN and anything not built in
}

crypto::ISymmetricKeyPtr key;
if (algo->generateKey(key, crypto::SKeySizeSpec(256)) != ERET_OK) {
    return; // 256 bits is legal for AES and ChaCha20, but not for DES (64) or 3DES (up to 192)
}

if (key->algorithm() != which) {
    return;
}
```
