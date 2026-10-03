A default-constructed SEcPoint is the point at infinity -- the group identity -- not (0, 0), and its x/y are meaningless while infinity is true. equals() knows that, so an identity only ever matches another identity.

```cpp
// given: const crypto::CEcCurve& curve
crypto::SEcPoint identity;
if (!identity.infinity) {
    return;
}

crypto::SEcPoint doubled = curve.doublePoint(curve.g);
if (!doubled.equals(curve.add(curve.g, curve.g))) {
    return;
}

// Adding the identity is a no-op, as the group law requires.
if (!curve.add(doubled, identity).equals(doubled)) {
    return;
}

if (!curve.isOnCurve(doubled)) {
    return;
}
```
