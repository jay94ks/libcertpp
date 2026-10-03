Serializes an encapsulation key to hand to a peer, and parses the one they sent back. createPublicKey() returns null rather than a half-built key when the encoding is wrong, so the null check is the whole error report you get.

```cpp
// given: const crypto::IKemPtr& kem, const crypto::IKemPublicKeyPtr& own, const SReadOnlyByteSpan& peerKeyData
COctet encoded;
if (own->serialize(encoded) != ERET_OK) {
    return;
}

// ... send encoded, receive theirs.
crypto::IKemPublicKeyPtr peer = kem->createPublicKey(peerKeyData);
if (!peer || peer->algorithm() != own->algorithm()) {
    return; // a mismatched parameter set is not interoperable
}

crypto::IKemContextPtr ctx = kem->createContext();
ctx->keyPair(peer, nullptr);
```
