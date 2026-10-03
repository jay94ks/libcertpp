Copies out a named curve's parameters and validates a peer's SEC1 point against them -- decodePoint() rejects anything off the curve or outside the subgroup. The arithmetic here is not constant-time, so prefer X25519 for an online handshake wherever the protocol lets you.

```cpp
// given: const SReadOnlyByteSpan& sec1Point
crypto::CEcCurve curve;
if (!crypto::CEcCurve::knownCurves(crypto::ECURVE_P256, curve)) {
    return;
}

crypto::SEcPoint peer;
if (!curve.decodePoint(sec1Point, peer)) {
    return; // malformed, off-curve, or in the wrong subgroup
}

TArray<uint8_t> encoded;
if (!curve.encodePoint(peer, encoded)) {
    return;
}

// Each coordinate is padded to fieldByteLen(), so an uncompressed point is a fixed width.
if (encoded.size() != 1 + curve.fieldByteLen() * 2) {
    return;
}
```
