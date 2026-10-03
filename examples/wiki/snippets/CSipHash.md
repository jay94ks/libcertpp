Computes a DNS server cookie (RFC 9018 2.2). Unlike CPoly1305 the key is long-lived: finish() leaves it in place, and the no-argument reset() starts the next message under the same key.

```cpp
// given: const SReadOnlyByteSpan& serverSecret, const SReadOnlyByteSpan& clientCookie, const SReadOnlyByteSpan& clientIp
crypto::CSipHash prf;
if (!prf.reset(serverSecret)) {
    return; // the key is exactly KEY_BYTES, which is 16
}

prf.push(clientCookie);
prf.push(clientIp);

uint8_t cookieHash[crypto::CSipHash::TAG_BYTES];
SByteSpan out(cookieHash, sizeof(cookieHash));
if (!prf.finish(out)) {
    return;
}

// The same instance serves the next query without re-supplying the key.
if (!prf.reset()) {
    return;
}
```
