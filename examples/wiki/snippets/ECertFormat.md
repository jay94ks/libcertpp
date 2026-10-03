ECERT_AUTO, the default, sniffs DER from PEM out of the data itself, which is what to pass for a file whose format is not known up front. It is an import-only value: exportAs() has nothing to detect from and reports ERET_NOTSUP, so an export must name ECERT_DER or ECERT_PEM.

```cpp
// given: const SReadOnlyByteSpan& fileContents
CCert cert;
if (cert.importFrom(fileContents, ECERT_AUTO) != ERET_OK) {
    return;
}

COctet pem;
if (cert.exportAs(pem, false, ECERT_PEM) != ERET_OK) {
    return;
}
// pem holds a "-----BEGIN CERTIFICATE-----" block; ECERT_AUTO here would have been ERET_NOTSUP
```
