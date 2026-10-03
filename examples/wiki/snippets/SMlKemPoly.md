Samples one noise polynomial and measures how small its coefficients are. They come back reduced into [0, MODULUS), so a CBD sample of -1 reads as 3328 rather than as a negative int16_t -- centre them before measuring or comparing anything.

```cpp
// given: const SReadOnlyByteSpan& prfOutput
SMlKemPoly noise;
if (!CMlKemSampler::samplePolyCbd(2, prfOutput, noise)) {
    return;         // eta out of range, or prfOutput was not 64*eta = 128 bytes
}

int32_t norm = 0;
for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS; ++i) {
    int32_t coeff = noise.coeffs[i];
    if (coeff > SMlKemPoly::MODULUS / 2) {
        coeff -= SMlKemPoly::MODULUS;       // the representative in (-q/2, q/2]
    }

    coeff = coeff < 0 ? -coeff : coeff;
    norm = coeff > norm ? coeff : norm;
}

// norm is at most eta, which is what makes these the "small" error terms Module-LWE
// needs. The same 256-coefficient layout also carries NTT-domain values -- 128 degree-1
// blocks -- and nothing in the struct says which one an instance holds.
if (norm > 2) {
    return;
}
```
