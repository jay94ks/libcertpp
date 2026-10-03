Produces the 114-byte hash Ed448 (RFC 8032) uses everywhere Ed25519 uses SHA-512. The output length is this instance's constructor argument, not a constant of the algorithm.

```cpp
// given: const SReadOnlyByteSpan& privateKey
SHAKE256 xof(114);

if (xof.push(privateKey) != privateKey.size) {
    return;
}

uint8_t wide[114];
SByteSpan out(wide, sizeof(wide));
if (!xof.finish(out)) {
    return;
}

// All 114 bytes are filled, because byteWidth() is 114 -- the default SHAKE256() would
// have written 32 of them and left the rest alone. finish() squeezes from a copy of the
// sponge, so it hands back these same bytes however often it is called; squeeze() is the
// call for going further into the stream.
CSecure::zero(out);
```
