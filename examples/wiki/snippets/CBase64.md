Streams bytes through the incremental Base64 encoder. finish() may need more than one call: it returns how many bytes it produced, and a non-zero return means there may be more, so it has to be drained in a loop before the output is complete.

```cpp
// given: SReadOnlyByteSpan der
CBase64 b64(EB64M_ENCODE_BR);

uint8_t out[4096];
SByteSpan whole(out, sizeof(out));

size_t total = b64.push(der, whole);
if (b64.state() != ERET_OK) {
    return;   // ERET_NOSPC means `whole` was too small; retrying bigger works, no reset()
}

size_t more = 0;
do {
    SByteSpan tail(out + total, sizeof(out) - total);
    more = b64.finish(tail);
    total += more;
} while (more > 0);

if (b64.state() != ERET_OK) {
    return;
}

CString pem(reinterpret_cast<const char*>(out), total);
```
