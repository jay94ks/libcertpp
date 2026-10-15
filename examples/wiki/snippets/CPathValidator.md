Builds and validates a leaf-first certification path against an explicit trust store. Passing intermediates supplies candidates only; none of them becomes trusted merely by being present.

```cpp
// given: const CCert& leaf, const CCert& intermediate, const CCert& configuredRoot
CCertCollection intermediates;
size_t index = 0;
if (intermediates.add(intermediate, index) != ERET_OK) {
    return;
}

CTrustStore trust;
if (trust.add(configuredRoot) != ERET_OK) {
    return;
}

SPathValidationPolicy policy;
policy.requiredLeafKeyUsages = EKUSE_DIGITAL_SIGNATURE;
SPathValidationResult result = CPathValidator::validate(
    leaf, intermediates, trust, policy
);
if (!result) {
    return; // inspect status, certificateIndex and detail for the exact failed rule
}
```
