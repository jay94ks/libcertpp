Reads the diagnostic result without reducing it to a Boolean. The completed path is leaf first, and on failure certificateIndex points at the certificate whose rule failed when one applies.

```cpp
// given: const SPathValidationResult& result
if (!result) {
    if (result.certificateIndex < result.path.size()) {
        const CCert& rejected = result.path[result.certificateIndex];
        (void)rejected; // report rejected.subject() together with result.status
    }
    return;
}

const CCert& trustAnchor = result.path[result.path.size() - 1];
(void)trustAnchor; // EPATH_OK means this exact certificate was in the supplied CTrustStore
```
