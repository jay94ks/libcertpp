#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_ED25519_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_ED25519_HPP__

#include <certpp/crypto/asym.hpp>

namespace certpp {
namespace crypto {

    /**
     * Ed25519 (EdDSA over edwards25519, RFC 8032), the pure (non-prehashed, non-contextual)
     * variant. Sign/verify only -- EdDSA has no encryption operation, so createEncrypter()/
     * createDecrypter() always report ERET_NOTSUP. keySizes() accepts exactly 256 bits.
     *
     * Unlike every other IAsymmetric implementation in this library, sign()/verify()'s "digest"
     * parameter is the raw message, not a pre-computed hash: pure EdDSA hashes its input
     * internally (twice, each combined with a different prefix), so there is no
     * caller-supplied digest to accept here -- passing an externally pre-hashed value would not
     * produce a standard, interoperable Ed25519 signature.
     *
     * Keys serialize as the raw 32-byte values RFC 8032 itself defines them as (a private key
     * is literally 32 random bytes, the "seed"; a public key is the 32-byte encoded point they
     * produce) -- there is no ASN.1 structure to add here, unlike RSA/DSA/ECDSA. Signatures
     * serialize as the standard raw 64-byte `R || S` encoding (RFC 8032 5.1.6).
     */
    class CERTPP_API Ed25519 : public IAsymmetric {
    private:
        /**
         * Builds the matching public key for a 32-byte seed (shared by generateKeyPair() and
         * createPrivateKey(), which both need to derive A from d/s).
         * @return The derived public key, or null on failure.
         */
        static IPublicKeyPtr publicKeyFromSeed(const uint8_t seed[32]);

    public:
        /**
         * Constructs an Ed25519 algorithm instance; keySizes() accepts exactly 256 bits.
         */
        Ed25519();

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
