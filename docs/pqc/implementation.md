# Remaining PQC work

[한국어](implementation.ko.md)

← [Post-quantum cryptography](../PQC.md)

The core ML-KEM and ML-DSA implementations are complete. Their implementation
history is in [History](../HISTORY.md); this page contains only open work.

## ML-KEM certificate integration

Add ML-KEM SubjectPublicKeyInfo support to the X.509 algorithm tables and key
codec. The implementation must preserve the parameter set through import and
export, require absent AlgorithmIdentifier parameters, carry the raw FIPS 203
encapsulation key in the BIT STRING, and use an independently produced fixture
or second implementation for interoperability testing.

This work adds a KEM public key to certificates. It does not make ML-KEM a
certificate signature algorithm and does not force it through
`IAsymmetric`.

## ML-DSA timing review

Review signing specifically for data-dependent branches, memory access, and
observable retry behavior. Compare the implementation against the published
Dilithium timing attacks, record what can and cannot be made constant-time,
and add focused tests or measurement tools for any enforceable property.

## Additional algorithms

Re-evaluate SLH-DSA, FN-DSA, HQC, and composite or hybrid certificate schemes
only when there is a stable interoperable encoding and a concrete caller need.
Adding one requires the same external-vector, malformed-input, and independent
interoperability evidence used for ML-KEM and ML-DSA.
