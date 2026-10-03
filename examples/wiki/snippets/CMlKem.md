Decapsulates a received ciphertext through the raw-span algorithm. decapsulate() returning true says only that the spans were the right size: a corrupted ciphertext yields a well-formed but unrelated shared secret rather than an error, which is the Fujisaki-Okamoto implicit rejection ML-KEM's security rests on. Whether the peer holds the same secret is settled by the transcript MAC that follows, never here.

```cpp
// given: const SReadOnlyByteSpan& dk, const SReadOnlyByteSpan& ciphertext
static constexpr SMlKemParams params = SMlKemParams::mlKem768();

// A decapsulation key that arrived from elsewhere is checked first: this verifies its
// length and that the H(ek) it embeds matches the encapsulation key it carries.
if (!CMlKem::checkDecapsulationKey(params, dk)) {
    return;
}

uint8_t ss[params.sharedSecretBytes()];
if (!CMlKem::decapsulate(params, dk, ciphertext, SByteSpan(ss, sizeof(ss)))) {
    return;         // only a wrong-sized span or a non-FIPS-203 parameter set gets here
}

// Bind ss to the handshake transcript via a KDF; do not compare it against anything to
// decide whether the ciphertext was genuine, and wipe it when the session ends.
CSecure::zero(SByteSpan(ss, sizeof(ss)));
```
