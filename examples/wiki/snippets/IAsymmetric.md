Obtains a built-in algorithm from the factory and generates a key pair at one of its advertised sizes. ERET_AGAIN is not a failure: the fresh candidate flunked its own validation, and the documented response is to call generateKeyPair() again.

```cpp
crypto::IAsymmetricPtr algo = crypto::IAsymmetric::builtIn(crypto::EASYM_P256);
if (!algo) {
    return;
}

crypto::SKeyPair pair;
ERetCode ret = ERET_AGAIN;
for (size_t i = 0; i < 8 && ret == ERET_AGAIN; ++i) {
    ret = algo->generateKeyPair(256, pair);
}

if (ret != ERET_OK) {
    return;
}

// A key that came in from the wire instead would want checkPrivateKey() run on it by hand;
// generateKeyPair() has already done that here.
```
