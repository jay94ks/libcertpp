# Future PQC candidates

[한국어](implementation.ko.md)

← [Post-quantum cryptography](../PQC.md)

The core ML-KEM and ML-DSA implementations, RFC 9935 ML-KEM public-key SPKI
codec, and ML-DSA retry/timing audit tool are complete. Their implementation
history is in [History](../HISTORY.md). The audit tool reports attempts and
rejection categories for analysis; it does not turn Fiat-Shamir-with-aborts
signing into a constant-time operation.

## Additional algorithms

Re-evaluate SLH-DSA, FN-DSA, HQC, and composite or hybrid certificate schemes
only when there is a stable interoperable encoding and a concrete caller need.
Adding one requires the same external-vector, malformed-input, and independent
interoperability evidence used for ML-KEM and ML-DSA.
