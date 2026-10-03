The top-level responseStatus, which answers for the *request* and is separate from any certificate's own status. A non-successful response has no room for anything else: build() encodes the single ENUMERATED and ignores the responder certificate, entries and producedAt.

```cpp
// given: const CCert& responderCert, const COcspRequest& request, COctet& out
COcspResponseBuilder builder;

if (request.certIds().empty()) {
    builder.status(EOCSP_MALFORMED);
} else if (request.certIds().size() > 16) {
    builder.status(EOCSP_UNAUTHORIZED);
} else {
    builder.status(EOCSP_TRY_LATER);
}

if (builder.build(responderCert, out) != ERET_OK) {
    return;
}
// out carries the status and nothing more -- a client must read status() before entries()
```
