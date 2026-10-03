Reads the algorithm and size an asymmetric key carries with it, which is what lets an encoder pick the right OID without the caller tracking which IAsymmetric produced the key. keySize() is in bits here.

```cpp
// given: const crypto::IAsymmetricKeyBasePtr& key
if (key->algorithm() == crypto::EASYM_UNKNOWN) {
    return; // a key that never came out of an IAsymmetric factory
}

if (key->algorithm() == crypto::EASYM_RSA && key->keySize() < 2048) {
    return; // too short for this deployment to accept
}

COctet encoded;
if (key->serialize(encoded) != ERET_OK) {
    return;
}
```
