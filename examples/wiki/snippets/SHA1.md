Computes RFC 5280 4.2.1.2 method (1)'s keyIdentifier -- the SHA-1 of the subjectPublicKey BIT STRING's contents. Identifiers like this are the one place SHA-1 is still correct; a new signature is not.

```cpp
// given: const SReadOnlyByteSpan& subjectPublicKeyBits, SByteSpan keyId
if (keyId.size < 20) {
    return;
}

SHA1 hasher;
hasher.push(subjectPublicKeyBits);
if (!hasher.finish(keyId)) {
    return;
}

// keyId's first 20 bytes are the identifier that goes into subjectKeyIdentifier, and that
// an authorityKeyIdentifier in an issued certificate has to repeat. Collision resistance
// is not what is being relied on here -- matching a parent to a child is.
```
