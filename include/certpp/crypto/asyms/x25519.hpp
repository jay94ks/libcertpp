#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_X25519_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_X25519_HPP__

#include <certpp/crypto/asym.hpp>

namespace certpp {
namespace crypto {

    /**
     * X25519 (Diffie-Hellman key agreement over Curve25519, RFC 7748), the Montgomery-form
     * curve birationally equivalent to Ed25519's edwards25519. Key-agreement only -- sign()/
     * verify() have no meaning here and always report ERET_NOTSUP (inherited from
     * IAsymmetricContext's default), and there is no encryption operation either, so
     * createEncrypter()/createDecrypter() always report ERET_NOTSUP. keySizes() accepts exactly
     * 256 bits.
     *
     * Unlike every sign/verify-capable IAsymmetric implementation in this library,
     * IAsymmetricContext::deriveSharedSecret() is the operation this algorithm supports:
     * combine this context's bound private key with a peer's public key to produce the shared
     * secret (RFC 7748 6.1's X25519 function applied to the private scalar and the peer's
     * u-coordinate).
     *
     * Keys serialize as the raw 32-byte values RFC 7748 itself defines them as -- a private key
     * is 32 bytes clamped at use (never stored pre-clamped, so create*Key()/serialize() round-
     * trip the exact original bytes); a public key is the 32-byte encoded u-coordinate -- there
     * is no ASN.1 structure to add here, matching Ed25519/Ed448.
     */
    class CERTPP_API X25519 : public IAsymmetric {
    private:
        /**
         * Builds the matching public key for a 32-byte raw private key (shared by
         * generateKeyPair() and createPrivateKey()).
         * @return The derived public key, or null on failure.
         */
        static IPublicKeyPtr publicKeyFromRaw(const uint8_t raw[32]);

    public:
        /**
         * Constructs an X25519 algorithm instance; keySizes() accepts exactly 256 bits.
         */
        X25519();

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
