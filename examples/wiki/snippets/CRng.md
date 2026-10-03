Fills a nonce and a PKCS#1 v1.5 padding string from the OS CSPRNG. fillNonZero() is the variant that padding needs, where a zero byte would terminate the padding string early.

```cpp
uint8_t nonce[12];
SByteSpan nonceSpan(nonce, sizeof(nonce));
if (crypto::CRng::fill(nonceSpan) != ERET_OK) {
    return; // there is no safe degraded mode -- do not fall back to rand()
}

uint8_t padding[64];
SByteSpan paddingSpan(padding, sizeof(padding));
if (crypto::CRng::fillNonZero(paddingSpan) != ERET_OK) {
    return;
}

// ... build the encoded message, then clear the padding.
CSecure::zero(paddingSpan);
```
