Modular arithmetic on an arbitrary-precision unsigned integer. add/sub/mul/mod/mulMod mutate the value they are called on and return it only so calls can be chained, so a caller that still needs the original has to copy it first -- the most common way to corrupt a computation with this class.

```cpp
// given: const CBigNum& base, const CBigNum& modulus
CBigNum product = base;             // copy: base itself has to survive this
product.mulMod(CBigNum(3), modulus);

CBigNum inverse;
if (!CBigNum::modInverse(product, modulus, inverse)) {
    return;   // product and modulus are not coprime, so no inverse exists
}

uint8_t wire[32];
SByteSpan field(wire, sizeof(wire));
if (!inverse.toBigEndian(field)) {
    return;   // wider than 32 bytes: nothing was written, rather than a truncated value
}

// Both copies of a secret scalar have to go: the span, and the heap limbs behind the value.
CSecure::zero(field);
inverse.secureClear();
```
