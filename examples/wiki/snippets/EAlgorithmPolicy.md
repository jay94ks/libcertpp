Treats the classifier result as generation policy. Compatibility-only algorithms remain readable for interoperability, while new keys, signatures and ciphertexts must use a class that allows generation.

```cpp
// given: crypto::EAsymmetrics requested, crypto::SKeySize keySize
crypto::EAlgorithmPolicy policy = crypto::CAlgorithmPolicy::classify(requested, keySize);
if (!crypto::CAlgorithmPolicy::allowsGeneration(policy)) {
    return; // report CAlgorithmPolicy::name(policy) to explain the rejected selection
}
```
