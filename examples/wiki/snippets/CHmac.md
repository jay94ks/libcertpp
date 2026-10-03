Checks a received tag with verify(), which compares in time that depends only on the tag's length. finish() plus memcmp is a forgery oracle: it leaks how long a prefix the attacker guessed right, which is enough to build a valid tag one byte at a time.

```cpp
// given: const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& receivedTag
if (!crypto::CHmac::verify(crypto::EHASH_SHA256, key, message, receivedTag)) {
    return; // forged, truncated to a length you did not expect, or the wrong key
}

// Producing a tag of our own: reset() keys it, push() per chunk, finish() for the tag.
crypto::CHmac hmac;
if (hmac.reset(crypto::EHASH_SHA256, key) != ERET_OK) {
    return; // ERET_NOTSUP for SHAKE128/SHAKE256, which RFC 2104 is not defined over
}

hmac.push(message);

uint8_t tag[crypto::CHmac::MAX_BLOCK_BYTES];
SByteSpan out(tag, hmac.byteWidth());
if (!hmac.finish(out)) {
    return;
}
```
