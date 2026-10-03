Encapsulates a fresh shared secret to a peer's ML-KEM-768 public key. encapsulate() chooses the secret itself -- there is no plaintext to supply -- and both output spans come back narrowed, so the ciphertext to transmit is ciphertext.size bytes long, not sizeof(ct).

```cpp
// given: const SReadOnlyByteSpan& info
MLKEM kem(EKEM_MLKEM768);
SKemKeyPair pair;
if (kem.generateKeyPair(SKeySize(768), pair) != ERET_OK) {
    return;         // 768 is the set's name, and the only size keySizes() accepts
}

IKemContextPtr ctx = kem.createContext();
ctx->keyPair(pair.publicKey, nullptr);  // encapsulating needs the public half alone

uint8_t ct[SMlKemParams::maxCiphertextBytes()], ss[32];
SByteSpan ciphertext(ct, sizeof(ct));
SByteSpan sharedSecret(ss, sizeof(ss));
if (ctx->encapsulate(ciphertext, sharedSecret) != ERET_OK) {
    return;
}

// The secret is not a key, and decapsulate() succeeding on the far side proves nothing
// about the ciphertext -- bind both to the transcript through the KDF.
uint8_t key[32];
ERetCode eRet = CHkdf::derive(EHASH_SHA256, SReadOnlyByteSpan(),
    SReadOnlyByteSpan(sharedSecret.data, sharedSecret.size), info,
    SByteSpan(key, sizeof(key)));
CSecure::zero(sharedSecret);
if (eRet != ERET_OK) {
    return;
}
```
