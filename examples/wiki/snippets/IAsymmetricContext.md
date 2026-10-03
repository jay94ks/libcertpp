Binds a key pair to a context and signs a digest. sizeOfSign() is the capacity to allocate and the signature's real length is the output span's narrowed .size afterwards; a sizeOfDigest() of 0 means the algorithm hashes internally and wants the message, not a digest.

```cpp
// given: const crypto::IAsymmetricPtr& algo, const crypto::SKeyPair& pair, const SReadOnlyByteSpan& digest
crypto::IAsymmetricContextPtr ctx = algo->createContext();
ctx->keyPair(pair);

if (ctx->sizeOfSign() == 0) {
    return; // nothing usable was bound
}

TArray<uint8_t> signature;
signature.resize(ctx->sizeOfSign());

SByteSpan out(signature.begin(), signature.size());
if (ctx->sign(digest, out) != ERET_OK) {
    return; // ERET_NOTSUP for an agreement-only algorithm such as X25519
}

signature.resize(out.size);
if (ctx->verify(digest, SReadOnlyByteSpan(signature.begin(), signature.size())) != ERET_OK) {
    return;
}
```
