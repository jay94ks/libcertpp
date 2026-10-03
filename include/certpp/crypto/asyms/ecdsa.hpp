#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_ECDSA_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_ECDSA_HPP__

#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/eccurve.hpp>

namespace certpp {
namespace crypto {

    /**
     * ECDSA (FIPS 186-4 / SEC 1) over one of this library's known curves (see EEcKnownCurves:
     * P-256, P-384, P-521, secp256k1). Sign/verify plus ECDH key agreement (RFC 5903 /
     * SP 800-56A, via IAsymmetricContext::deriveSharedSecret() -- see its own doc comment on
     * this class's context for the shared secret's format and its timing caveat); no encryption
     * operation, so createEncrypter()/createDecrypter() always report ERET_NOTSUP. keySizes()
     * accepts exactly one size: the chosen curve's fixed field width (256/384/521 bits).
     *
     * Key agreement lives on this class rather than a separate CEcdh for two reasons: an ECDH
     * key pair over a prime curve *is* an ECDSA key pair (RFC 5480's id-ecPublicKey
     * SubjectPublicKeyInfo, with the same curve OID, serves both), so splitting them would mean
     * two EAsymmetrics enumerators describing one encoded key; and a context already carries
     * several unrelated operations for one key type where the algorithm supports them (RSA's
     * sign/verify alongside createEncrypter()/createDecrypter()). The practical consequence is
     * that one generated key pair can be bound to one context and used for both.
     *
     * Public keys serialize as a SEC1 uncompressed point (0x04 || X || Y). Private keys
     * serialize as this library's own DER layout,
     * `SEQUENCE { version INTEGER (0), d INTEGER, publicKey OCTET STRING }` (there is no
     * equally simple traditional single-blob layout -- RFC 5915's ECPrivateKey wraps its curve
     * OID and public point in explicit context tags this library doesn't model yet). Signatures
     * serialize as the standard `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
     * (RFC 3279/SEC 1).
     */
    class CERTPP_API CEcdsa : public IAsymmetric {
    private:
        CEcCurve _curve;
        EAsymmetrics _which; // --> The specific curve, for IKeyBase::algorithm() -- CEcCurve
                                   // itself carries only domain parameters, no identity.

    public:
        /**
         * @param which The known curve to run ECDSA over.
         */
        explicit CEcdsa(EEcKnownCurves which);

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;

        // --> Re-exposes IAsymmetric's COctet convenience overloads, which the SReadOnlyByteSpan
        // overrides above would otherwise hide: name lookup stops at the first scope holding the
        // name, so without these a caller holding a concrete CEcdsa cannot pass a COctet at all,
        // while the same call through an IAsymmetricPtr compiles.
        using IAsymmetric::createPublicKey;
        using IAsymmetric::createPrivateKey;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
