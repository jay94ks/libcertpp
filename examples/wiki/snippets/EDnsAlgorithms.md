The algorithm number selects the hash too -- RFC 5702, 6605 and 8080 bind one to the other instead of leaving it to the signer -- so hasherOf() is how a verifier decides what to hash with. It reports EHASH_UNKNOWN with a true return for Ed25519 and Ed448, which hash internally and take the signed data whole; treating that as a failure would reject two supported algorithms.

```cpp
// given: EDnsAlgorithms algorithm, const SReadOnlyByteSpan& signedData
crypto::EHashers which = crypto::EHASH_UNKNOWN;
if (!CDnssecKeys::hasherOf(algorithm, which)) {
    return;                     // e.g. EDNSALG_ECC_GOST, named so it can be rejected
}

if (which == crypto::EHASH_UNKNOWN) {
    return;                     // Ed25519/Ed448: pass signedData to verify() unhashed
}

crypto::IHasherPtr hasher;
if (crypto::IHasher::create(which, hasher) != ERET_OK) {
    return;
}

if (hasher->push(signedData) != signedData.size) {
    return;
}

// byteWidth() is the digest length this algorithm number implies: 32 for
// EDNSALG_ECDSAP256SHA256, 48 for EDNSALG_ECDSAP384SHA384, 64 for EDNSALG_RSASHA512.
uint8_t buffer[64];
const SByteSpan digest(buffer, hasher->byteWidth());
if (!hasher->finish(digest)) {
    return;
}
```
