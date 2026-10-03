Wraps an already-encoded value in a `[0] EXPLICIT` tag. The class is a constructor argument and cannot be inferred from the number: tag number 0 means an end-of-contents marker under EATAG_UNIVERSAL and the first context-specific field of the enclosing SEQUENCE under this one.

```cpp
// given: const IStreamPtr& out, SReadOnlyByteSpan inner
CTag explicitZero(EATAG_CONTEXT_SPECIFIC, 0, true);
if (!explicitZero) {
    return;
}

CWriter writer(out, EAENC_DER);
if (!writer.writeElement(explicitZero, inner)) {
    return;
}

// An IMPLICIT [0] over a primitive value is the same class with the constructed bit cleared.
const CTag implicitZero = explicitZero.asPrimitive();
if (implicitZero.tagClass() != EATAG_CONTEXT_SPECIFIC) {
    return;
}
```
