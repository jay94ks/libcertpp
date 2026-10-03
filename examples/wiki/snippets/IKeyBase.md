Serializes a key and compares it with another through the base both key families share. compare() answers "the same bytes", which is a different question from "do these two form a pair" -- that one needs a signature, as CCertCollection::checkKeyPairing() does.

```cpp
// given: const crypto::IKeyBasePtr& key, const crypto::IKeyBasePtr& other
COctet encoded;
if (key->serialize(encoded) != ERET_OK || encoded.empty()) {
    return;
}

if (key->compare(other) != 0) {
    return; // different key material
}

// encoded is the algorithm-defined encoding, ready to go into a SubjectPublicKeyInfo or a
// private-key file.
```
