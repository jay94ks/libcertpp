Reads the current time and checks it against a validity bound. now() and from() default to *local* time -- pass true for UTC, which is the only form X.509 encodes and the only one the two sides of a comparison can safely share.

```cpp
// given: const SDateTime& notAfter
if (notAfter.isZero()) {
    return;   // the field was absent, or never decoded
}

const SDateTime now = SDateTime::now(true);
const SDateTime bound = notAfter.isUtc ? notAfter : notAfter.toUtc();

if (now.toMilliseconds() > bound.toMilliseconds()) {
    return;   // already expired
}

const STimeSpan left = bound.diff(now);
if (left.totalDays() < 30) {
    // renew soon
}
```
