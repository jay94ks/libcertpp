Verifies a GOST R 34.10-2012 signature made by someone else. Every byte order here is a trap: the public key is x || y with each half *little*-endian, while the signature is s || r -- s first -- with each half *big*-endian and no DER SEQUENCE wrapper. This is not ECDSA with a different curve, and the digest must come from Streebog.

```cpp
// given: const SReadOnlyByteSpan& peerKey, const SReadOnlyByteSpan& signature, const SReadOnlyByteSpan& streebog256Digest
CGost3410 gost(ECURVE_GOST256B);

// 64 bytes for a 256-bit parameter set: two 32-byte little-endian coordinates (RFC 9215
// 2.4), not a SEC1 uncompressed point.
IPublicKeyPtr peer = gost.createPublicKey(peerKey);
if (!peer) {
    return;
}

// Verification needs the public half only, so bind it with no private key beside it.
IAsymmetricContextPtr ctx = gost.createContext();
ctx->keyPair(peer, nullptr);

// 64 bytes of s || r, each big-endian. deriveSharedSecret() reports ERET_NOTSUP here --
// VKO key agreement is not implemented.
if (ctx->verify(streebog256Digest, signature) != ERET_OK) {
    return;
}
```
