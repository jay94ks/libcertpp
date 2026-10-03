Parses a peer's public key material and binds it on its own. keyPair(publicKey, nullptr) is how you verify someone else's signature: there is no private half to supply, and the two-argument overload exists precisely so you do not have to fake one.

```cpp
// given: const crypto::IAsymmetricPtr& algo, const SReadOnlyByteSpan& keyData, const SReadOnlyByteSpan& digest, const SReadOnlyByteSpan& signature
crypto::IPublicKeyPtr peer = algo->createPublicKey(keyData);
if (!peer) {
    return; // keyData was not a valid encoding for this algorithm
}

crypto::IAsymmetricContextPtr ctx = algo->createContext();
ctx->keyPair(peer, nullptr);

if (ctx->verify(digest, signature) != ERET_OK) {
    return; // the signature does not match, or verification is unsupported
}
```
