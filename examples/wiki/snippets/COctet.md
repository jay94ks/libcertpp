Takes a private copy of a blob that only lives as long as the caller's span. store() reports false for a null or zero-length source and leaves whatever the octet already held, so an empty input has to go through clear() instead of store().

```cpp
// given: SReadOnlyByteSpan der
COctet owned;
if (der.empty()) {
    owned.clear();
} else if (!owned.store(der)) {
    return;
}

if (!owned) {
    return;
}

// toSpan()/toPtr() are views into the octet's own allocation, valid only while it lives.
SReadOnlyByteSpan view = owned.toSpan();
if (view.size > 1 && view[0] == 0x30) {
    // a SEQUENCE tag: this looks like DER
}

// If what it held were secret -- a decoded private key, a challengePassword -- release it
// with secureClear() rather than clear(). The octet's bytes are reachable only through the
// read-only toPtr()/toSpan(), so CSecure::zero() cannot be pointed at them from outside;
// secureClear() is that operation, named rather than reached through a const_cast.
owned.secureClear();
```
