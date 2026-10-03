A magnitude plus a sign flag, for the one thing CBigNum cannot represent. CBigNum is unsigned and its sub() requires the operand to be no larger, so a difference that may come out either way is carried as a magnitude and a bool.

```cpp
// given: const CBigNum& a, const CBigNum& b
SignedBig diff;

if (a.compare(b) >= 0) {
    diff.mag = a;        // copy first: sub() mutates the value it is called on
    diff.mag.sub(b);
    diff.neg = false;
} else {
    diff.mag = b;
    diff.mag.sub(a);
    diff.neg = true;
}

if (diff.mag.isZero()) {
    diff.neg = false;    // there is only one zero; keep the sign canonical
}
```
