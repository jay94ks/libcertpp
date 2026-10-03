Asks for a 16-byte BLAKE2s digest. The length is bound into BLAKE2s's parameter block, so a short digest is its own function and not a prefix of the 32-byte one.

```cpp
// given: const SReadOnlyByteSpan& message
// 1..32 is the permitted range; anything outside it is silently folded onto 32, because
// RFC 7693 has no encoding for a longer digest. Read byteWidth() back if it matters.
BLAKE2s hasher(16);

hasher.push(message);

uint8_t digest[BLAKE2s::MAX_DIGEST_BYTES];
SByteSpan out(digest, hasher.byteWidth());
if (!hasher.finish(out)) {
    return;
}

// out holds BLAKE2s-128 of message -- not the leading half of BLAKE2s-256 of the same
// bytes, which is a different value. A keyed tag is a third function again: that is
// CBlake2sMac (native keyed mode) or CHmac over EHASH_BLAKE2S, never this class with the
// key pushed in front of the message.
```
