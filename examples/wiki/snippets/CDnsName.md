Encodes a presentation-format name into the canonical wire form everything DNSSEC hashes over, and counts its labels. toWire() always folds ASCII uppercase to lowercase and always writes the root label, so "Example.NET" and "example.net." produce identical bytes; a name that reaches a DS digest or an RRSIG prefix unfolded yields a digest that disagrees with every published one.

```cpp
// given: const CString& owner
TArray<uint8_t> wire;
if (!CDnsName::toWire(owner, wire)) {
    return;                     // an empty label, a label over 63 bytes, or a name over 255
}

const SReadOnlyByteSpan canonical(wire.begin(), wire.size());

// Always true of toWire() output; worth asserting on a name that arrived from the wire,
// where fromWire() hands back whatever case the sender used.
if (!CDnsName::isCanonical(canonical)) {
    return;
}

size_t labels = 0;
if (!CDnsName::countLabels(canonical, labels)) {
    return;
}

// labels excludes the root, which is the value RRSIG's Labels field carries: two for
// "example.net.", and the caller subtracts one more for a wildcard owner.
SRrsig sig;
sig.labels = uint8_t(labels);
```
