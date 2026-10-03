Picks the container implementation for a buffer whose format is not known. The two are not interchangeable: ECHAINFMT_PEM has no password and no encryption, so needsPassword() returning false is a warning about what a private key in the collection would become, not a convenience.

```cpp
// given: const COctet& container, const COctet& password
EChainFormats which = IChainFormat::detect(container.toSpan());
if (which == ECHAINFMT_UNKNOWN) {
    return; // not a container shape this library recognizes
}

IChainFormatPtr format = IChainFormat::builtIn(which);
if (!format) {
    return; // a format this build does not implement
}

CCertCollection col;
if (format->load(container.toSpan(), password.toSpan(), col) != ERET_OK) {
    return; // malformed container, wrong password, or an algorithm not implemented
}
// load() appends, so loading a second container into col merges the two
```
