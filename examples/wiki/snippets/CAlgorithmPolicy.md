Applies one central algorithm policy before generating output. Parsing stays separate so old signatures and certificates can still be inspected even when their algorithm is prohibited for new material.

```cpp
// given: crypto::EHashers requestedHash
crypto::EAlgorithmPolicy policy = crypto::CAlgorithmPolicy::classify(requestedHash);
if (!crypto::CAlgorithmPolicy::allowsGeneration(policy)) {
    return;
}

crypto::IHasherPtr hasher;
if (crypto::IHasher::create(requestedHash, hasher) != ERET_OK) {
    return; // policy acceptance does not replace implementation availability checks
}
```
