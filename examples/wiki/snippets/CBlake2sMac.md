Verifies a tag from BLAKE2s's *native* keyed mode, which is what WireGuard's MAC() is. This is not HMAC-BLAKE2s: for the generic RFC 2104 construction over the same hash use CHmac with EHASH_BLAKE2S, which produces a completely different tag from the same key and message.

```cpp
// given: const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& receivedTag
if (!crypto::CBlake2sMac::verify(key, message, receivedTag)) {
    return; // constant-time -- never check a tag with memcmp
}

// A 16-byte tag is its own function, not the first 16 bytes of the 32-byte one: the length is
// bound into the parameter block.
crypto::CBlake2sMac mac;
if (!mac.reset(key, 16)) {
    return;
}

mac.push(message);

uint8_t tag[16];
if (!mac.finish(SByteSpan(tag, sizeof(tag)))) {
    return;
}
```
