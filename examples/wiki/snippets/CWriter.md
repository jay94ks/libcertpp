Writes a few typed elements, then a SEQUENCE and a SET built from children that are already complete tag-length-values -- writeSequence()/writeSet() wrap, they do not encode. writeSet() also reorders its argument in place into DER's canonical order, so that array is not left as-is.

```cpp
// given: const IStreamPtr& out, SReadOnlyByteSpan firstChild, SReadOnlyByteSpan secondChild
CWriter writer(out, EAENC_DER);

if (!writer.writeInteger(1) || !writer.writeNull()) {
    return;
}

SReadOnlyByteSpan children[] = { firstChild, secondChild };
if (!writer.writeSequence(TReadOnlySpan<SReadOnlyByteSpan>(children, 2))) {
    return;
}

if (!writer.writeSet(TSpan<SReadOnlyByteSpan>(children, 2))) {
    return;
}
```
