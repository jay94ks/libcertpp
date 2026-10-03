Picks which binary curve knownCurves() copies out. A "B" and a "K" curve of the same bit size share one GF(2^m) field singleton, so between ECURVE2_B163 and ECURVE2_K163 only a, b, g and n differ -- the field pointer is literally the same object.

```cpp
crypto::CEc2Curve random;
crypto::CEc2Curve koblitz;
if (!crypto::CEc2Curve::knownCurves(crypto::ECURVE2_B163, random) ||
    !crypto::CEc2Curve::knownCurves(crypto::ECURVE2_K163, koblitz)) {
    return;
}

if (random.field != koblitz.field) {
    return; // cannot happen: the field is a program-lifetime singleton shared by both
}

crypto::IAsymmetricPtr algo =
    crypto::IAsymmetric::builtIn(crypto::CEc2Curve::identify(crypto::ECURVE2_K163));
if (!algo) {
    return;
}
```
