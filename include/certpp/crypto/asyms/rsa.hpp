#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_RSA_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_RSA_HPP__

#include <certpp/crypto/asym.hpp>

namespace certpp {
namespace crypto {

    /**
     * RSA (RFC 8017 / PKCS#1 v1.5). Keys serialize as PKCS#1 DER (RSAPublicKey/RSAPrivateKey,
     * two-prime form only). sign()/verify() use EMSA-PKCS1-v1_5, wrapping the digest in a
     * DigestInfo whose hash AlgorithmIdentifier is inferred from the digest's byte length (16 =
     * MD5, 20 = SHA-1, 32 = SHA-256, 48 = SHA-384, 64 = SHA-512 -- every hasher this library
     * ships, and the only digest lengths sign()/verify() accept), since IAsymmetricContext::
     * sign()/verify() aren't told which hash produced the digest. createEncrypter()/
     * createDecrypter() use RSAES-PKCS1-v1_5 padding.
     */
    class CERTPP_API RSA : public IAsymmetric {
    public:
        /**
         * Constructs an RSA algorithm instance; keySizes() accepts 512-8192 bit moduli, in
         * 8-bit steps.
         */
        RSA();

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;

        // --> Re-exposes IAsymmetric's COctet convenience overloads, which the SReadOnlyByteSpan
        // overrides above would otherwise hide: name lookup stops at the first scope holding the
        // name, so without these a caller holding a concrete RSA cannot pass a COctet at all,
        // while the same call through an IAsymmetricPtr compiles.
        using IAsymmetric::createPublicKey;
        using IAsymmetric::createPrivateKey;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
