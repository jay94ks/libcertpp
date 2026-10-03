Expands one entry of ML-KEM's public matrix A. The index order is the whole point: FIPS 203 computes A[i][j] as SampleNTT(rho || j || i), transposed relative to the natural loop order, and this function appends exactly the two bytes it is handed, in the order it is handed them.

```cpp
// given: const SReadOnlyByteSpan& rho, size_t i, size_t j
// rho is the 32-byte seed out of G(d || k), and j goes in ahead of i.
SMlKemPoly aHat;
if (!CMlKemSampler::sampleNtt(rho, static_cast<uint8_t>(j), static_cast<uint8_t>(i), aHat)) {
    return;         // rho was not 32 bytes, or the SHAKE128 XOF failed
}

// How much of the XOF stream that consumed is not knowable in advance -- it rejection-
// samples until 256 coefficients are accepted -- which is why SHAKE128::squeeze() exists.
// What comes back is an NTT-domain value, 128 degree-1 blocks rather than a polynomial,
// even though the type is the same SMlKemPoly a polynomial uses; nothing in it records
// which, so tracking that is the caller's job, as it is in FIPS 203 itself.
```
