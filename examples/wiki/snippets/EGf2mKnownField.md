Names one of the five binary fields this library defines. The "B" (random) and "K" (Koblitz) curve of a given size share a field, so EGF2M_M233 covers both B-233 and K-233: the identifier picks m and the reduction polynomial, not a curve equation.

```cpp
// given: EGf2mKnownField which
if (which <= EGF2M_UNKNOWN || which >= EGF2M_MAX) {
    return;   // EGF2M_UNKNOWN and EGF2M_MAX are sentinels, not fields
}

const SGf2mField* field = CGf2m::knownFieldPtr(which);
if (!field) {
    return;
}

CGf2m one(*field, 1);
CGf2m squared = one;
squared.square();

if (squared != one) {
    return;   // 1^2 == 1 in every one of them
}
```
