The raw-pointer string primitives TString and CName are built on, usable directly when you have a pointer and a length instead of a TString. Everything here takes an explicit size and never looks for a terminator -- countOf() is the one call that does.

```cpp
// given: const char* header
using Fn = TStringFunctions<char>;

const size_t len = Fn::countOf(header);
if (len == 0) {
    return;   // also what a null pointer reports, rather than crashing
}

const offset_t colon = Fn::find(header, len, ':');
if (colon < 0) {
    return;
}

// caseCmp() compares exactly the count it is given and does not stop at a terminator, so
// the length has to be checked first, not inferred from the result.
const size_t nameLen = static_cast<size_t>(colon);
if (nameLen != 12 || Fn::caseCmp(header, "content-type", nameLen) != 0) {
    return;
}
```
