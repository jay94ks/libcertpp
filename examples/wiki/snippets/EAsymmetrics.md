Selects the algorithm builtIn() hands back, and names the key size generateKeyPair() demands. That size is in bits and is checked exactly: Ed448 wants 456, not 448, because its keys are 57 bytes -- a wrong size is ERET_KEY_SIZE, never rounded to the nearest supported one.

```cpp
crypto::IAsymmetricPtr ed448 = crypto::IAsymmetric::builtIn(crypto::EASYM_ED448);
if (!ed448) {
    return;
}

crypto::SKeyPair pair;
if (ed448->generateKeyPair(456, pair) != ERET_OK) {
    return;
}

// The key remembers which algorithm made it, so a certificate builder can pick the matching
// SubjectPublicKeyInfo OID without being told separately.
if (pair.privateKey->algorithm() != crypto::EASYM_ED448) {
    return;
}
```
