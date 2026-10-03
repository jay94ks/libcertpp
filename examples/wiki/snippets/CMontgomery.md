A division-free modular-arithmetic context precomputed for one fixed modulus. It needs an odd modulus: built from an even or zero one, isValid() is false and every operation silently does nothing, so that check is not optional. CBigNum::mod()/mulMod() stay the path for any modulus.

```cpp
// given: const CBigNum& modulus, const CBigNum& base, const CBigNum& exponent
CMontgomery mont(modulus);
if (!mont.isValid()) {
    return;   // zero or even; use CBigNum::modExp() instead of getting no-ops
}

const CBigNum direct = mont.modExp(base, exponent);   // ordinary form in, ordinary form out

// Working in the Montgomery domain instead: convert in once, compute, convert back once.
// Mixing a converted value with an unconverted one is the way to misuse this class.
CBigNum acc = mont.toMont(base);
mont.mul(acc, acc);              // squaring through the same object is supported
mont.add(acc, mont.one());       // one() is R mod m, the Montgomery form of 1
const CBigNum ordinary = mont.fromMont(acc);

if (direct.compare(mont.modulus()) >= 0 || ordinary.compare(mont.modulus()) >= 0) {
    return;   // never happens: every result comes back already reduced
}
```
