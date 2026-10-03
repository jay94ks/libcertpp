Derives a key from a password. Unlike CHkdf, whose input is already a high-entropy secret, PBKDF2's whole purpose is the iteration count: it makes each guess of a low-entropy password expensive. Pick the count from how long you can afford to spend, not from a standard's decade-old floor -- RFC 8018 suggests 1000 and OWASP's 2023 figure for HMAC-SHA256 is 600,000.

```cpp
// given: const SReadOnlyByteSpan& password
// The salt is per-password and need not be secret; it stops one precomputed table from
// covering every user. Never reuse one, and never omit it.
uint8_t saltBytes[16];
SByteSpan salt(saltBytes, sizeof(saltBytes));
if (crypto::CRng::fill(salt) != ERET_OK) {
    return;
}

uint8_t keyBytes[32];
SByteSpan key(keyBytes, sizeof(keyBytes));

ERetCode rc = crypto::CPbkdf2::derive(
    crypto::EHASH_SHA256, password, SReadOnlyByteSpan(salt.data, salt.size), 600000, key);
if (rc != ERET_OK) {
    return;         // ERET_BADREQ for zero iterations, or an output past maxDeriveBytes()
}

// Store the salt and the iteration count alongside the result: verifying a password later
// means repeating this derivation exactly, and neither value is a secret.
CSecure::zero(key);
```
