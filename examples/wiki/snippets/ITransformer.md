Drives any transformer -- symmetric or asymmetric -- to completion through the base interface: transform() per input chunk, then exactly one transformFinal(). Each call narrows the span it wrote into, so advance by .size rather than by the capacity handed over.

```cpp
// given: const crypto::ITransformerPtr& transformer, const SReadOnlyByteSpan& input, const SByteSpan& output
SByteSpan step(output.data, output.size);
if (transformer->transform(input, step) != ERET_OK) {
    return;
}

size_t written = step.size;
SByteSpan rest(output.data + written, output.size - written);
if (transformer->transformFinal(rest) != ERET_OK) {
    return;
}

written += rest.size;

// written is the total output length; the transformer is not usable again.
```
