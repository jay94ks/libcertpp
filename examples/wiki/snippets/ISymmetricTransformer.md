Encrypts a message in one transform() plus one transformFinal(). PKCS#7's padding block appears in that final call, so the ciphertext is longer than the plaintext: leave a block of slack and take the real length from the two narrowed spans, not from the capacity you passed.

```cpp
// given: const crypto::ISymmetricContextPtr& ctx, const SReadOnlyByteSpan& plaintext
crypto::ISymmetricTransformerPtr encrypter;
if (ctx->createEncrypter(encrypter) != ERET_OK) {
    return;
}

TArray<uint8_t> ciphertext;
ciphertext.resize(plaintext.size + encrypter->blockSize());

SByteSpan step(ciphertext.begin(), ciphertext.size());
if (encrypter->transform(plaintext, step) != ERET_OK) {
    return;
}

SByteSpan rest(ciphertext.begin() + step.size, ciphertext.size() - step.size);
if (encrypter->transformFinal(rest) != ERET_OK) {
    return;
}

ciphertext.resize(step.size + rest.size);

// The transformer is spent now; context() gets back the context that can build another.
crypto::ISymmetricContextPtr owner = encrypter->context();
```
