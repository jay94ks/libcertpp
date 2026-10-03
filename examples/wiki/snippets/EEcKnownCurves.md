Picks which prime curve's domain parameters knownCurves() copies out. Its numbering is its own and does not line up with EAsymmetrics -- use CEcCurve::identify() to cross between them rather than casting.

```cpp
// given: crypto::EEcKnownCurves which
crypto::CEcCurve curve;
if (!crypto::CEcCurve::knownCurves(which, curve)) {
    return; // ECURVE_UNKNOWN and ECURVE_MAX are both rejected, and curve is left untouched
}

crypto::IAsymmetricPtr algo = crypto::IAsymmetric::builtIn(crypto::CEcCurve::identify(which));
if (!algo) {
    return;
}

// curve.p is the field prime, for coordinates; curve.n is the subgroup order, for scalars.
// They are different numbers and are never interchangeable.
if (curve.p.isZero() || curve.n.isZero()) {
    return;
}
```
