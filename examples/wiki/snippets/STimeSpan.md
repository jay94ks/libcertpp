A signed duration in milliseconds. Every accessor is taken from absolute(), so totalDays() of a negative span comes back positive -- the sign survives only in the milliseconds field, which is what to test when the direction is the thing you care about.

```cpp
// given: const SDateTime& notBefore, const SDateTime& notAfter
const STimeSpan validity = notAfter.diff(notBefore);
if (validity.milliseconds <= 0) {
    return;   // notAfter is not actually after notBefore; totalDays() would not have shown it
}

if (validity.totalDays() > 398) {
    return;   // longer than a public TLS certificate is allowed to live
}

// Arithmetic is plain +/-; a literal is implicitly a millisecond count.
const STimeSpan skew(5 * 60 * 1000);
const SDateTime earliest = notBefore.subtract(skew);
if (earliest.isZero()) {
    return;
}
```
