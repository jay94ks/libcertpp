Signs a SHA-256 digest with EMSA-PKCS1-v1_5. The hash identifier that goes into the DigestInfo is inferred from the digest's *length*, never passed in, so only the five lengths this library ships hashers for are accepted -- a truncated or non-standard digest is rejected rather than signed under the wrong AlgorithmIdentifier.

```cpp
// given: const SReadOnlyByteSpan& sha256Digest
RSA rsa;

SKeyPair pair;
if (rsa.generateKeyPair(SKeySize(2048), pair) != ERET_OK) {
    return;         // keySizes() runs 512-8192 in 8-bit steps
}

IAsymmetricContextPtr ctx = rsa.createContext();
ctx->keyPair(pair);

uint8_t buf[1024];
SByteSpan signature(buf, sizeof(buf));
if (ctx->sign(sha256Digest, signature) != ERET_OK) {
    return;
}

// signature.size is the modulus width, 256 bytes here -- not sizeof(buf).
IAsymmetricContextPtr verifier = rsa.createContext();
verifier->keyPair(pair.publicKey, nullptr);
if (verifier->verify(sha256Digest, SReadOnlyByteSpan(signature.data, signature.size))
    != ERET_OK) {
    return;
}
```
