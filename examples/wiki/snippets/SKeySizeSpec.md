Checks a caller-supplied key size against what the algorithm actually accepts, before generateKeyPair() rejects it. A spec built from one size has step 0 and includes() only that size; RSA's is a range with a step, so 2048 passes and 2049 does not.

```cpp
// given: const crypto::IAsymmetricPtr& algo, crypto::SKeySize requested
bool accepted = false;
for (const crypto::SKeySizeSpec& spec : algo->keySizes()) {
    if (spec.includes(requested)) {
        accepted = true;
        break;
    }
}

if (!accepted) {
    return; // generateKeyPair() would answer ERET_KEY_SIZE
}

crypto::SKeyPair pair;
if (algo->generateKeyPair(requested, pair) != ERET_OK) {
    return;
}
```
