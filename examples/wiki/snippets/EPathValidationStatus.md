Handles a path verdict as a typed result. EPATH_OK covers the validator's documented core profile; revocation and full RFC 5280 policy processing have explicit unavailable statuses rather than being silently included in success.

```cpp
// given: const SPathValidationResult& result
if (result.status == EPATH_REVOCATION_UNAVAILABLE
    || result.status == EPATH_POLICY_PROCESSING_UNAVAILABLE)
{
    return; // this deployment requested a capability the core validator does not provide
}

if (result.status != EPATH_OK) {
    // certificateIndex identifies the failing item in result.path, leaf first.
    return;
}
```
