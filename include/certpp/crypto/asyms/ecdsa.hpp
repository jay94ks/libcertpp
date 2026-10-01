#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_ECDSA_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_ECDSA_HPP__

#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/eccurve.hpp>

namespace certpp {
namespace crypto {

    /**
     * ECDSA (FIPS 186-4 / SEC 1) over one of this library's known curves (see EEcKnownCurves:
     * P-256, P-384, P-521, secp256k1). Sign/verify only -- ECDSA has no encryption operation, so
     * createEncrypter()/createDecrypter() always report ERET_NOTSUP. keySizes() accepts exactly
     * one size: the chosen curve's fixed field width (256/384/521 bits).
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
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
