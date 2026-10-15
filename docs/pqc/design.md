# Standards and interface design

[한국어](design.ko.md)

← [Post-quantum cryptography](../PQC.md)

## Implemented scope

`libcertpp` implements the standardized ML-KEM and ML-DSA families. ML-KEM
provides key encapsulation; ML-DSA provides signatures. SLH-DSA, FN-DSA, HQC,
and composite or hybrid certificate schemes are outside the current
implementation and are tracked only as possible future work.

Both implemented families follow the repository's dependency rule: the
cryptographic code is implemented in-tree, while published ACVP vectors and
independent implementations serve as test oracles. No third-party
cryptographic library is linked into `certpp`.

## Interface fit

ML-DSA implements `IAsymmetric` because its public operations are key
generation, signing, and verification. `CMlDsa` handles all three parameter
sets selected by `EASYM_MLDSA44`, `EASYM_MLDSA65`, and `EASYM_MLDSA87`.
Unlike the classical hash-then-sign implementations, ML-DSA receives the
message directly and reports a digest size of zero.

ML-KEM has a separate `IKem`/`IKemContext` interface. Encapsulation produces a
ciphertext and a fresh shared secret together, and decapsulation turns a
ciphertext into a shared secret; neither operation is ordinary asymmetric
encryption. `MLKEM` handles `EKEM_MLKEM512`, `EKEM_MLKEM768`, and
`EKEM_MLKEM1024`.

KEM keys form their own family in `crypto/keys.hpp`: `IKemPublicKey`,
`IKemPrivateKey`, and `SKemKeyPair`. A context operates on its bound key, in
the same style as `IAsymmetricContext`.

## X.509 fit

ML-DSA AlgorithmIdentifiers use absent parameters and carry the raw FIPS 204
public key or signature in the surrounding BIT STRING. The certificate and
CSR code recognizes all three ML-DSA OIDs, verifies them as direct-message
signatures, and can build ML-DSA-signed objects.

`CKemSubjectPublicKeyInfo` imports and exports RFC 9935 ML-KEM-512,
ML-KEM-768, and ML-KEM-1024 public keys. It enforces absent AlgorithmIdentifier
parameters and byte-aligned raw public-key BIT STRING contents. Because a KEM
key is not a signature key, this codec is intentionally separate from
`CCert`, whose public-key accessor returns `IAsymmetricPublicKey`.
