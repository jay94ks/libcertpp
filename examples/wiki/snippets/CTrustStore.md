Builds an explicit set of trust anchors. A self-signed certificate found beside the leaf does not become trusted by position; it must be added here through deployment configuration.

```cpp
// given: const CCert& configuredRoot
CTrustStore trust;
if (trust.add(configuredRoot) != ERET_OK) {
    return; // empty or malformed certificate
}

if (!trust.contains(configuredRoot) || trust.count() != 1) {
    return;
}
```
