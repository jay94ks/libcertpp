Derives two independent directional keys from one shared secret. Mind the argument order -- the salt comes *before* the input keying material -- and give each use a different `info` label, or both directions derive the same bytes and a record can be replayed at its sender.

```cpp
// given: const SReadOnlyByteSpan& sharedSecret, const SReadOnlyByteSpan& salt
const uint8_t clientLabel[] = "certpp client write";
const uint8_t serverLabel[] = "certpp server write";
SReadOnlyByteSpan clientInfo(clientLabel, sizeof(clientLabel) - 1);
SReadOnlyByteSpan serverInfo(serverLabel, sizeof(serverLabel) - 1);

uint8_t clientKey[32];
uint8_t serverKey[32];
SByteSpan clientOut(clientKey, sizeof(clientKey));
SByteSpan serverOut(serverKey, sizeof(serverKey));

// One secret and one salt, two different info labels -- so two unrelated keys.
if (crypto::CHkdf::derive(
        crypto::EHASH_SHA256, salt, sharedSecret, clientInfo, clientOut) == ERET_OK &&
    crypto::CHkdf::derive(
        crypto::EHASH_SHA256, salt, sharedSecret, serverInfo, serverOut) == ERET_OK) {
    // ... key the two transport directions.
}

CSecure::zero(clientOut);
CSecure::zero(serverOut);
```
