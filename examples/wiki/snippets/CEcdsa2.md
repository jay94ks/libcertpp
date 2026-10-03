Signs a SHA-256 digest over the binary curve B-233 and verifies it from the public half alone. Unlike Ed25519/ML-DSA this really is a digest, and the output span comes back narrowed to the DER signature's real length -- passing sizeof(buf) onward would hash trailing garbage.

```cpp
// given: const SReadOnlyByteSpan& sha256Digest
CEcdsa2 ecdsa(ECURVE2_B233);    // keySizes() accepts only the field degree, 233
SKeyPair pair;
if (ecdsa.generateKeyPair(SKeySize(233), pair) != ERET_OK) {
    return;
}

IAsymmetricContextPtr ctx = ecdsa.createContext();
ctx->keyPair(pair);

uint8_t buf[128];
SByteSpan signature(buf, sizeof(buf));
if (ctx->sign(sha256Digest, signature) != ERET_OK) {
    return;
}

// SEQUENCE { r, s } is shorter than the buffer, so carry signature.size forward.
IAsymmetricContextPtr verifier = ecdsa.createContext();
verifier->keyPair(pair.publicKey, nullptr);
if (verifier->verify(sha256Digest, SReadOnlyByteSpan(signature.data, signature.size))
    != ERET_OK) {
    return;
}
```
