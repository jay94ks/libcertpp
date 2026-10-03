Agrees an RFC 5903 shared secret over P-256 and turns it into a session key. Key agreement lives on the ECDSA class because a prime-curve ECDH key pair *is* an ECDSA key pair -- the same context would sign with this key too -- and the x-coordinate it yields is not a key until HKDF has run over it. The scalar multiplication is not constant-time; prefer X25519 where the protocol lets you choose.

```cpp
// given: const IPublicKeyPtr& peerKey, const SReadOnlyByteSpan& info
CEcdsa ecdsa(ECURVE_P256);      // one instance per curve; keySizes() accepts only 256
SKeyPair mine;
if (ecdsa.generateKeyPair(SKeySize(256), mine) != ERET_OK) {
    return;
}

IAsymmetricContextPtr ctx = ecdsa.createContext();
ctx->keyPair(mine);

uint8_t secret[66];
SByteSpan shared(secret, sizeof(secret));
if (ctx->deriveSharedSecret(peerKey, shared) != ERET_OK) {
    return;
}

// shared.size is the curve's field width, not sizeof(secret).
uint8_t sessionKey[32];
ERetCode eRet = CHkdf::derive(EHASH_SHA256, SReadOnlyByteSpan(),
    SReadOnlyByteSpan(shared.data, shared.size), info,
    SByteSpan(sessionKey, sizeof(sessionKey)));
CSecure::zero(shared);
if (eRet != ERET_OK) {
    return;
}
```
