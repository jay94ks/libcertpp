Encapsulates under whichever parameter set an EKems names, taking every length off the parameter set instead of writing it down -- a mistyped key or ciphertext length stays internally consistent and is caught only by an external test vector. isValid() guards a set that came from anywhere but these accessors, since a larger k would overflow the fixed-capacity buffers inside. The message must be fresh CSPRNG output.

```cpp
// given: EKems which, const SReadOnlyByteSpan& ek, const SReadOnlyByteSpan& message
SMlKemParams params{};
if (!MLKEM::paramsOf(which, params) || !params.isValid()) {
    return;         // which named no ML-KEM parameter set
}

// ekBytes() is 384*k + 32: 800, 1184 or 1568. checkEncapsulationKey() applies the same
// figure, and also rejects an encoding whose t-hat segments are not all below q.
if (!CMlKem::checkEncapsulationKey(params, ek)) {
    return;
}

// Two buffers wide enough for any set, each narrowed to the width this one needs --
// CMlKem refuses a span of any other length rather than writing a prefix of it.
uint8_t ctBuf[SMlKemParams::maxCiphertextBytes()], ssBuf[32];
SByteSpan ciphertext(ctBuf, params.ciphertextBytes());
SByteSpan sharedSecret(ssBuf, params.sharedSecretBytes());
if (!CMlKem::encapsulate(params, ek, message, ciphertext, sharedSecret)) {
    return;
}

CSecure::zero(sharedSecret);
```
