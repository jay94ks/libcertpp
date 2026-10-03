Encrypts with the context's bound public key. Asymmetric encryption works a block at a time, so it is a transform()-then-transformFinal() session; both narrow the span they wrote into, so advance by .size rather than by the capacity you handed over.

```cpp
// given: const crypto::IAsymmetricContextPtr& ctx, const SReadOnlyByteSpan& message
crypto::IAsymmetricTransformerPtr encrypter;
if (ctx->createEncrypter(encrypter) != ERET_OK) {
    return; // ERET_NOTSUP for an algorithm that only signs
}

TArray<uint8_t> ciphertext;
ciphertext.resize(encrypter->blockSize() * 2);

SByteSpan step(ciphertext.begin(), ciphertext.size());
if (encrypter->transform(message, step) != ERET_OK) {
    return;
}

SByteSpan rest(ciphertext.begin() + step.size, ciphertext.size() - step.size);
if (encrypter->transformFinal(rest) != ERET_OK) {
    return;
}

ciphertext.resize(step.size + rest.size);
```
