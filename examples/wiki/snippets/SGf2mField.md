The degree m plus the reduction polynomial x^m + x^terms[0] + ... + 1. knownField() copies the value out, which is right for reading these numbers -- but a CGf2m built from it keeps a pointer to it, so for that use CGf2m::knownFieldPtr() instead.

```cpp
SGf2mField field;
if (!CGf2m::knownField(EGF2M_M571, field)) {
    return;
}

// termCount is 1 for a trinomial and 3 for a pentanomial; only that many entries of terms[]
// carry anything, and reading the rest reads whatever was left there.
if (field.termCount != 1 && field.termCount != 3) {
    return;
}

for (size_t i = 0; i < field.termCount; ++i) {
    if (field.terms[i] == 0 || field.terms[i] >= field.m) {
        return;   // 0 < terms[i] < m always holds for a known field
    }
}

const size_t width = (field.m + 7) / 8;   // 72 bytes for GF(2^571)
if (width > CGf2m::LIMB_COUNT * sizeof(uint64_t)) {
    return;
}
```
