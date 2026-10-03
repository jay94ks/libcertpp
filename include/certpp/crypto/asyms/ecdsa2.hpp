#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_ECDSA2_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_ECDSA2_HPP__

#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/ec2curve.hpp>

namespace certpp {
namespace crypto {

    /**
     * ECDSA (FIPS 186-4 / SEC 1) over one of this library's known binary curves (see
     * EEc2KnownCurves: B-163/K-163 .. B-571/K-571). The binary-curve counterpart of CEcdsa --
     * see that class's doc comment for the shared reasoning (a single class parametrized by
     * curve, rather than one class per curve) -- but built on CEc2Curve/CGf2m instead of
     * CEcCurve/CBigNum for the point arithmetic. The actual ECDSA math (r/s reduced mod the
     * subgroup order n) is identical either way, since n stays a CBigNum regardless of curve
     * family; only the signed point's x-coordinate needs converting from a GF(2^m) element to
     * an integer first (FIPS 186-4 Appendix C.2: a field element's m-bit polynomial-basis
     * representation, reinterpreted directly as an unsigned integer -- the same bytes
     * CGf2m::toBigEndian()/CBigNum::fromBigEndian() already agree on).
     *
     * Sign/verify only -- ECDSA has no encryption operation, so createEncrypter()/
     * createDecrypter() always report ERET_NOTSUP. keySizes() accepts exactly one size: the
     * chosen curve's field degree m (163/233/283/409/571 bits).
     *
     * Public keys serialize as a SEC1 uncompressed point (0x04 || X || Y). Private keys
     * serialize as this library's own DER layout, identical in shape to CEcdsa's:
     * `SEQUENCE { version INTEGER (0), d INTEGER, publicKey OCTET STRING }`. Signatures
     * serialize as the standard `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
     * (RFC 3279/SEC 1).
     */
    class CERTPP_API CEcdsa2 : public IAsymmetric {
    private:
        CEc2Curve _curve;
        EAsymmetrics _which; // --> The specific curve, for IKeyBase::algorithm() -- CEc2Curve
                                   // itself carries only domain parameters, no identity.

    public:
        /**
         * @param which The known binary curve to run ECDSA over.
         */
        explicit CEcdsa2(EEc2KnownCurves which);

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;

        // --> Re-exposes IAsymmetric's COctet convenience overloads, which the SReadOnlyByteSpan
        // overrides above would otherwise hide: name lookup stops at the first scope holding the
        // name, so without these a caller holding a concrete CEcdsa2 cannot pass a COctet at all,
        // while the same call through an IAsymmetricPtr compiles.
        using IAsymmetric::createPublicKey;
        using IAsymmetric::createPrivateKey;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
