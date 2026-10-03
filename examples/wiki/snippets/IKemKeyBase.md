Reads what a KEM key is, through the base both halves share. The algorithm travels with the key so an encoder can pick the right OID, and keySize() reports the parameter-set label (512/768/1024) rather than a bit count.

```cpp
// given: const crypto::IKemKeyBasePtr& key
if (key->algorithm() == crypto::EKEM_UNKNOWN) {
    return; // never came out of an IKem factory
}

if (key->keySize() < 768) {
    return; // ML-KEM-512 is below this deployment's floor
}

COctet encoded;
if (key->serialize(encoded) != ERET_OK) {
    return;
}
```
