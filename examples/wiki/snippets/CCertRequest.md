Imports a PKCS#10 request on the CA side. importDer() verifies the self-signature before it reports success, because that signature is the only thing a CSR attests: until it holds every field is an unauthenticated claim, and once it holds they are still only a request.

```cpp
// given: const COctet& csrDer
CCertRequest request;
if (request.importDer(csrDer) != ERET_OK) {
    return; // malformed, or the self-signature did not hold
}

if (!request.publicKey()) {
    return; // an algorithm this library does not implement
}

// The requester proved possession of that key and of nothing else. A requested extension is
// a wish: read the specific one this CA will grant, check it, and decide -- there is
// deliberately no API that copies them into a certificate.
auto san = request.extension<CSanExtension>();
if (san) {
    for (const CGeneralName& name : san->names()) {
        if (name.type() == EGNAME_DNS) {
            // check name.text() against what this requester actually controls
        }
    }
}
```
