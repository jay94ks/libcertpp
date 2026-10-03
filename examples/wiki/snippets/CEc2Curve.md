Copies out a binary curve's parameters and multiplies its base point by a scalar. scalarMulBase() caches a table of small multiples of g inside the instance, so keep one curve around and reuse it instead of fetching a fresh copy per operation.

```cpp
// given: const CBigNum& scalar
crypto::CEc2Curve curve;
if (!crypto::CEc2Curve::knownCurves(crypto::ECURVE2_B163, curve)) {
    return;
}

crypto::SEc2Point point = curve.scalarMulBase(scalar);
if (point.infinity || !curve.isOnCurve(point)) {
    return;
}

TArray<uint8_t> encoded;
if (!curve.encodePoint(point, encoded)) {
    return;
}

// encoded is 0x04 || X || Y, each coordinate padded out to curve.fieldByteLen() bytes.
if (encoded.size() != 1 + curve.fieldByteLen() * 2) {
    return;
}
```
