Signs a message with ML-DSA-65. As with Ed25519/Ed448 the `digest` parameter is the message -- `sizeOfDigest()` stays 0 -- and signing is hedged, so two signatures over the same message differ and both verify. What gets signed is FIPS 204's external form, `0x00 || 0x00 || message`, which is what RFC 9881 requires of an X.509 signature.

```cpp
// given: const SReadOnlyByteSpan& message
CMlDsa mldsa(EASYM_MLDSA65);    // the size is the set's name, 65, not a modulus width
SKeyPair pair;
if (mldsa.generateKeyPair(SKeySize(65), pair) != ERET_OK) {
    return;
}

IAsymmetricContextPtr ctx = mldsa.createContext();
ctx->keyPair(pair);

uint8_t buf[3309];              // ML-DSA-65's signature size
if (ctx->sizeOfSign() > sizeof(buf) || ctx->sizeOfDigest() != 0) {
    return;
}

SByteSpan signature(buf, sizeof(buf));
if (ctx->sign(message, signature) != ERET_OK) {
    return;
}

if (ctx->verify(message, SReadOnlyByteSpan(signature.data, signature.size)) != ERET_OK) {
    return;
}
```
