Starts from builtIn() and writes a collection out. A PEM container has no password and no encryption at all, so a private key held in the collection is written in the clear -- check needsPassword() and choose ECHAINFMT_PFX when the key is going to rest on disk.

```cpp
// given: const CCertCollection& col, const COctet& password
IChainFormatPtr format = IChainFormat::builtIn(ECHAINFMT_PEM);
if (!format) {
    return;
}

if (!format->needsPassword()) {
    // Nothing in this container will be encrypted, whatever password is passed.
} else if (password.empty()) {
    return; // save() would refuse with ERET_BADREQ
}

CBuffer out;
if (format->save(col, password.toSpan(), out) != ERET_OK) {
    return; // ERET_NOTSUP when an entry holds a key this format cannot carry
}
// out holds the container's bytes; format->format() reports which format they are
```
