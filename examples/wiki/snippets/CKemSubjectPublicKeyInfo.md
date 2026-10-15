Exchanges an ML-KEM encapsulation key in RFC 9935 SubjectPublicKeyInfo form. The decoder checks the algorithm OID, requires absent parameters and constructs the matching ML-KEM public key.

```cpp
// given: const IKemPublicKeyPtr& ownPublicKey, const SReadOnlyByteSpan& receivedDer
CBuffer encoded;
if (CKemSubjectPublicKeyInfo::encode(ownPublicKey, encoded) != ERET_OK) {
    return;
}

EKems peerAlgorithm = EKEM_UNKNOWN;
IKemPublicKeyPtr peerPublicKey;
if (CKemSubjectPublicKeyInfo::decode(receivedDer, peerAlgorithm, peerPublicKey) != ERET_OK) {
    return;
}

if (peerAlgorithm != ownPublicKey->algorithm()) {
    return; // the peers selected different ML-KEM parameter sets
}
```
