Computes a SubjectKeyIdentifier the RFC 5280 4.2.1.2 "method 1" way -- the SHA-1 of the subject public key -- and attaches it while issuing. The digest is taken over the serialized public key, and SubjectKeyIdentifier is never critical: it identifies a key, it does not constrain its use.

```cpp
// given: CCertBuilder& builder, const IPublicKeyPtr& subjectKey
COctet publicKeyBytes;
if (subjectKey->serialize(publicKeyBytes) != ERET_OK) {
    return;
}

IHasherPtr sha1;
if (IHasher::create(EHASH_SHA1, sha1) != ERET_OK) {
    return;
}

uint8_t digest[20];
sha1->push(publicKeyBytes.toSpan());
if (!sha1->finish(SByteSpan(digest, sizeof(digest)))) {
    return;
}

CSkiExtensionBuilder ski;
ski.setKeyIdentifier(COctet(digest, sizeof(digest)));

IExtensionPtr ext = ski.build();
if (!ext) {
    return;
}

builder.extensions.add(ext);
```
