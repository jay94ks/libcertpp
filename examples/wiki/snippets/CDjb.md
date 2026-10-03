The fast non-cryptographic hash the library uses to short-circuit CName comparison: unequal hashes settle it in one integer compare, and only equal ones go on to compare bytes. Never for a security decision -- it is deliberately not one of crypto's hashers.

```cpp
// given: const CString& key, SReadOnlyByteSpan blob
if (key.empty() || blob.size < 2) {
    return;
}

// computeAsLower()/computeAsUpper() fold case so a case-insensitive key hashes alike, but
// they are two different functions: pick one per table and keep to it.
const SDjbValue folded = CDjb::computeAsLower(key.toSpan());

// combine() folds two finished hashes into one.
const SDjbValue pair = CDjb::combine(folded, CDjb::compute(blob));

// compute(hash, span) instead continues one hash over more data, for input arriving in
// pieces; the one-argument overload is just compute(SEED, span).
const size_t half = blob.size / 2;
SDjbValue running = CDjb::compute(CDjb::SEED, blob.slice(0, half));
running = CDjb::compute(running, blob.slice(half));

if (CDjb::combine(folded, running) != pair) {
    return;   // chunked and one-shot agree, which is what makes streaming safe
}
```
