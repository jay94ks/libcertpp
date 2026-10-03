A default-constructed SEc2Point is the point at infinity, with x/y meaningless until infinity is false. The coordinates are CGf2m field elements, not CBigNum: a binary curve's group law shares no formula with a prime curve's, and the two coordinate types do not convert.

```cpp
// given: const crypto::CEc2Curve& curve
crypto::SEc2Point identity;
if (!identity.infinity) {
    return;
}

crypto::SEc2Point doubled = curve.doublePoint(curve.g);
if (!doubled.equals(curve.add(curve.g, curve.g))) {
    return;
}

if (!curve.add(doubled, identity).equals(doubled)) {
    return;
}

// CGf2m's arithmetic mutates in place, so copy a coordinate before reusing the original.
CGf2m sum = doubled.x;
sum.add(doubled.y);
if (sum.isZero()) {
    return;
}
```
