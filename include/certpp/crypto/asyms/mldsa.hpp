#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_MLDSA_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_MLDSA_HPP__

#include <certpp/crypto/asym.hpp>

namespace certpp {
namespace crypto {

    /**
     * ML-DSA (NIST FIPS 204), the module-lattice digital signature algorithm, for all three
     * parameter sets -- one instance per set, the same arrangement CEcdsa has across its curves.
     * Sign/verify only: a signature scheme has no encryption operation, so createEncrypter()/
     * createDecrypter() always report ERET_NOTSUP, and neither does it do key agreement.
     *
     * **sign()/verify()'s "digest" parameter is the message, not a hash of it.** ML-DSA has no
     * externally supplied digest: Sign() hashes the message internally, twice and with different
     * domain separation each time (`mu = H(tr || M')`, then the commitment `H(mu || w1)`), and
     * what it signs is a lattice commitment rather than a fixed-width digest. Handing it a
     * pre-computed SHA-256 value would produce a perfectly valid ML-DSA signature **over that
     * 32-byte string** -- one no other implementation would ever generate or check, since the
     * verifier re-derives mu from the message it was given. Ed25519/Ed448 already read this
     * parameter the same way, for the same reason, and `CDnssecKeys::hasherOf()` expresses the
     * same fact from the other direction ("supported, but there is no external hash"). The
     * parameter keeps its name because it is `IAsymmetricContext`'s, and renaming it per
     * implementation would make the override relationship harder to see, not easier.
     *
     * Consequently `sizeOfDigest()` stays 0 for a bound ML-DSA key, which is how a caller can
     * tell: zero means "there is no digest to compute, pass the message".
     *
     * **sign()/verify() implement FIPS 204's external interface with an empty context string**
     * (Algorithms 2 and 3) -- that is, the signed message is `0x00 || 0x00 || M`, not `M`. This
     * is not an embellishment: RFC 9881's `id-ml-dsa-44/65/87` define an X.509 signature exactly
     * that way, so a certificate's signature covers `0x00 || 0x00 || tbsCertificate`. Using the
     * internal interface instead (FIPS 204 Algorithms 7-8, which take M' verbatim) yields a
     * scheme that round-trips perfectly against itself and rejects every real certificate. Only
     * the pure variant is implemented; HashML-DSA has its own distinct OIDs and appears in no
     * certificate this library is meant to read.
     *
     * keySizes() accepts exactly one size, and it is the parameter set's own number (44, 65 or
     * 87) rather than a modulus width or a claimed security strength -- the same choice MLKEM
     * makes, for the same reason: ML-DSA has no size that can be scaled. The three sets differ
     * in (k, l), eta, tau, gamma1/gamma2 and omega, and 44/65/87 are names. Note that **eta is
     * not monotone across them** (2, 4, 2) and **gamma1 is shared by ML-DSA-65 and -87**, so
     * neither can be used to tell a set apart.
     *
     * Keys serialize as FIPS 204's own byte encodings and nothing more: a public key is
     * pkEncode's output (1312/1952/2592 bytes), a private key skEncode's (2560/4032/4896).
     * That is also exactly what a `SubjectPublicKeyInfo` BIT STRING carries for these OIDs --
     * RFC 9881 puts the raw public key there, with no inner OCTET STRING wrapper and with the
     * AlgorithmIdentifier's `parameters` field absent -- so `CCert` needs no reshaping step for
     * ML-DSA the way it does for DSA. Since a private key does not embed its public key,
     * IPrivateKey::publicKey() re-derives it from the key's own rho/s1/s2 rather than reading it
     * out, and checks the result against the key's stored `tr` (which is H(pk)) as the one
     * available internal-consistency test.
     *
     * Signing is a rejection loop whose iteration count depends on the key and the message, so
     * it is not constant-time and FIPS 204 offers no way to make it so; see docs/pqc-review.md.
     * This class is also where randomness enters: the raw algorithm under `src/` takes its seed
     * and signing randomness as parameters so it can be driven from a test vector, while
     * generateKeyPair()/sign() here draw from CRng. Signing is **hedged** -- a fresh 32-byte rnd
     * per signature, FIPS 204's recommended default -- so two signatures over the same message
     * differ, and a known-answer test has to go through the raw layer with rnd = 0 instead.
     *
     * Validated against NIST's ACVP vectors for all three parameter sets: keyGen 75/75,
     * sigGen 360/360 byte-exact across all 24 groups, sigVer 180/180 verdicts including every
     * modified-hint, modified-z, modified-commitment and modified-message case.
     */
    class CERTPP_API CMlDsa : public IAsymmetric {
    private:
        EAsymmetrics _which;    // --> Which of the three parameter sets this instance runs; the
                                // parameter table itself is private to src/, so only the
                                // identity is held here and the figures are looked up per call.

    public:
        /**
         * Reports whether an EAsymmetrics names one of ML-DSA's parameter sets -- i.e. whether
         * CMlDsa is the implementation behind it.
         *
         * Exposed because the X.509 layer needs to ask it: ML-DSA signs the message rather than
         * a digest, so CCert::verifyBy() and its CRL/OCSP counterparts have to recognize these
         * three the same way they recognize Ed25519/Ed448.
         * @param which The algorithm to test.
         * @return true for EASYM_MLDSA44, EASYM_MLDSA65 or EASYM_MLDSA87.
         */
        static bool isMlDsa(EAsymmetrics which);

    public:
        /**
         * Constructs an ML-DSA instance for one parameter set; keySizes() accepts exactly that
         * set's number (44, 65 or 87). An unrecognized value yields an instance whose keySizes()
         * is empty and whose every operation fails, rather than an exception --
         * IAsymmetric::builtIn() returns null for such a value and is the way this is normally
         * reached.
         * @param which EASYM_MLDSA44, EASYM_MLDSA65 or EASYM_MLDSA87.
         */
        explicit CMlDsa(EAsymmetrics which);

        /**
         * @return The parameter set this instance runs, or EASYM_UNKNOWN if it was constructed
         * from a value that names no ML-DSA set.
         */
        inline EAsymmetrics which() const {
            return _which;
        }

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;

        // --> Re-exposes IAsymmetric's COctet convenience overloads, which the SReadOnlyByteSpan
        // overrides above would otherwise hide: name lookup stops at the first scope holding the
        // name, so without these a caller holding a concrete CMlDsa cannot pass a COctet at all,
        // while the same call through an IAsymmetricPtr compiles.
        using IAsymmetric::createPublicKey;
        using IAsymmetric::createPrivateKey;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
