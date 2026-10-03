One entry read out of a collection. A collection normally holds a mixture -- the end-entity certificate with its key, the CA certificates above it without -- so hasPrivateKey() is the test, and checkKeyPairing() is what establishes the key really is that certificate's.

```cpp
// given: const CCertCollection& col, size_t index
SCertEntry entry;
if (col.at(index, entry) != ERET_OK) {
    return; // index was at or beyond col.count()
}

if (!entry.hasPrivateKey()) {
    return; // a CA certificate in the chain, not the entry holding the key
}

// add() does not check the two against each other, because this costs a signature operation.
if (col.checkKeyPairing(index) != ERET_OK) {
    return; // ERET_KEY_ERROR: the key does not actually belong to entry.cert
}
// entry.friendlyName/entry.localKeyId are the PKCS#9 attributes a PFX pairs bags with
```
