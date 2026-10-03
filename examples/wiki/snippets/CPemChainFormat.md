Loads a PEM bundle as a collection, then writes the ordered chain back out. The format object is obtained from builtIn(), which returns the certificates-only form: writing private keys is a separate constructor argument because PEM has no encryption, so a key it writes is in the clear and should never be one a caller got by accident.

```cpp
// given: const SReadOnlyByteSpan& pemFile
IChainFormatPtr pem = IChainFormat::builtIn(ECHAINFMT_PEM);
if (!pem) {
    return;
}

// The password argument is ignored outright in both directions -- needsPassword() is false,
// and that is a warning, not a convenience.
CCertCollection collection;
ERetCode rc = pem->load(pemFile, SReadOnlyByteSpan(), collection);
if (rc != ERET_OK) {
    return;         // ERET_BADREQ: malformed container. ERET_NOTSUP: an encrypted key block.
}

TArray<size_t> chain;
if (collection.buildChain(0, chain) != ECHAINRES_OK) {
    return;         // ordered, still not validated -- see CCertCollection
}

CBuffer out;
pem->save(collection, SReadOnlyByteSpan(), out);
```
