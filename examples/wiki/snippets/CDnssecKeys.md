Verifies an RRSIG against the DNSKEY that made it. DNSSEC reuses none of X.509's encodings -- a DNSKEY's key material is not a SubjectPublicKeyInfo and an ECDSA RRSIG signature is bare `r | s` rather than a DER SEQUENCE -- so both have to come through these conversions; handing either straight to createPublicKey() or verify() is the bug this class exists to prevent.

```cpp
// given: const SDnskey& key, const SRrsig& sig, const SReadOnlyByteSpan& digest
crypto::EAsymmetrics asymmetric = crypto::EASYM_UNKNOWN;
crypto::IPublicKeyPtr publicKey;
if (!CDnssecKeys::asymmetricOf(sig.algorithm, asymmetric)
    || !CDnssecKeys::toPublicKey(key, publicKey)) {
    return false;               // no implementation for that number, or malformed material
}

TArray<uint8_t> signature;
if (!CDnssecKeys::signatureToNative(sig.algorithm,
        SReadOnlyByteSpan(sig.signature.toPtr(), sig.signature.size()), signature)) {
    return false;               // an ECDSA signature the wrong length for its curve
}

crypto::IAsymmetricPtr algorithm = crypto::IAsymmetric::builtIn(asymmetric);
crypto::IAsymmetricContextPtr context = algorithm ? algorithm->createContext() : nullptr;
if (!context) {
    return false;
}

// Public half only: a verify that somehow reached for a private key fails here rather than
// passing for the wrong reason.
context->keyPair(publicKey, nullptr);

return context->verify(
    digest, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK;
```
