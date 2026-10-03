Selects ESYMPAD_NONE for a protocol that pads its own payload: IKEv2 (RFC 7296 3.14) builds a pad-length-terminated padding into the payload before encrypting, so a PKCS#7 block underneath it would be a second, unexpected padding the peer rejects.

```cpp
// given: const crypto::ISymmetricPtr& algo, const crypto::ISymmetricKeyPtr& key, const CBuffer& iv
crypto::ISymmetricContextPtr ctx = algo->createContext(key);
if (!ctx) {
    return;
}

// ESYMPAD_PKCS7 is the default; the choice is read when a transformer is built.
ctx->padding(crypto::ESYMPAD_NONE);
ctx->key(key, iv);

crypto::ISymmetricTransformerPtr encrypter;
if (ctx->createEncrypter(encrypter) != ERET_OK) {
    return;
}

// key() deliberately does not clear the padding mode, so this still holds.
if (ctx->padding() != crypto::ESYMPAD_NONE) {
    return;
}
```
