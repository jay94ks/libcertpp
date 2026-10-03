#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_ED448_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_ED448_HPP__

#include <certpp/crypto/asym.hpp>

namespace certpp {
namespace crypto {

    /**
     * Ed448 (EdDSA over edwards448/"Ed448-Goldilocks", RFC 8032), the pure (non-prehashed,
     * empty-context) variant. Sign/verify only -- EdDSA has no encryption operation, so
     * createEncrypter()/createDecrypter() always report ERET_NOTSUP. keySizes() accepts exactly
     * 456 bits (57 bytes, RFC 8032's fixed Ed448 key size).
     *
     * Like Ed25519, sign()/verify()'s "digest" parameter is the raw message, not a pre-computed
     * hash -- see Ed25519's doc comment for why. Unlike Ed25519, every hash Ed448 computes uses
     * SHAKE256 (114-byte output) rather than SHA-512, and is prefixed with RFC 8032 5.2's
     * `dom4(F, C)` string (here always `F = 0`, empty context `C`, i.e. `"SigEd448" || 0x00 ||
     * 0x00` -- context strings aren't supported).
     *
     * Keys serialize as the raw byte values RFC 8032 itself defines them as (a private key is
     * literally 57 random bytes, the "seed"; a public key is the 57-byte encoded point they
     * produce). Signatures serialize as the standard raw 114-byte `R || S` encoding.
     */
    class CERTPP_API Ed448 : public IAsymmetric {
    private:
        /**
         * Builds the matching public key for a 57-byte seed (shared by generateKeyPair() and
         * createPrivateKey(), which both need to derive A from d/s).
         * @return The derived public key, or null on failure.
         */
        static IPublicKeyPtr publicKeyFromSeed(const uint8_t seed[57]);

    public:
        /**
         * Constructs an Ed448 algorithm instance; keySizes() accepts exactly 456 bits.
         */
        Ed448();

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;

        // --> Re-exposes IAsymmetric's COctet convenience overloads, which the SReadOnlyByteSpan
        // overrides above would otherwise hide: name lookup stops at the first scope holding the
        // name, so without these a caller holding a concrete Ed448 cannot pass a COctet at all,
        // while the same call through an IAsymmetricPtr compiles.
        using IAsymmetric::createPublicKey;
        using IAsymmetric::createPrivateKey;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
