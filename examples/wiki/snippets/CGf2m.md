Arithmetic in GF(2^m), the binary field the NIST B-/K- curves live in. A CGf2m keeps a non-owning pointer to its SGf2mField, so build one from knownFieldPtr()'s program-lifetime singleton: a field copied onto the stack leaves every element derived from it dangling.

```cpp
const SGf2mField* field = CGf2m::knownFieldPtr(EGF2M_M163);
if (!field) {
    return;
}

CGf2m b;
if (!CGf2m::fromHex(*field, "0x07b6882caaefa84f9554ff8428bd88e246d2782ae2", b)) {
    return;   // malformed, or not strictly below 2^163
}

CGf2m product(*field, 2);
product.mul(b);          // mutates product, as every operation here does

if (product.isZero()) {
    return;              // inverse() is undefined for zero
}

CGf2m check = product;   // copy first: inverse() would otherwise consume product
check.inverse();

TArray<uint8_t> wire;
product.toBigEndian(wire);   // always fieldByteLen() bytes -- 21 for GF(2^163)
```
