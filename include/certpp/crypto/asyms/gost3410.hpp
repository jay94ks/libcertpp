#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_GOST3410_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_GOST3410_HPP__

#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/eccurve.hpp>

namespace certpp {
namespace crypto {

    /**
     * GOST R 34.10-2012 (RFC 7091) over one of this library's GOST parameter sets (see
     * EEcKnownCurves's ECURVE_GOST* entries). Sign/verify only -- GOST R 34.10 has no
     * encryption operation, so createEncrypter()/createDecrypter() always report ERET_NOTSUP,
     * and its VKO key agreement (RFC 7836 section 4.3) isn't implemented either, so
     * deriveSharedSecret() reports ERET_NOTSUP too. keySizes() accepts exactly one size: the
     * parameter set's nominal 256 or 512 bits.
     *
     * This is *not* ECDSA with a different curve, and reusing CEcdsa's math would silently
     * produce signatures nothing else accepts. The differences, all from RFC 7091 section 6:
     *
     * - s = (r*d + k*e) mod q, with no modular inversion of k, where ECDSA has
     *   s = k^-1 * (z + r*d) mod q.
     * - verification recovers C = z1*P + z2*Q with z1 = s*e^-1 and z2 = -r*e^-1 mod q, where
     *   ECDSA inverts s instead of the hash.
     * - the hash becomes an integer by its own rule (step 2): e is the hash *vector* read as an
     *   integer, which for a Streebog digest in stream order means reading it little-endian --
     *   not ECDSA's leftmost-bits big-endian truncation. And an e of zero is replaced by 1
     *   rather than left alone.
     *
     * Serialization, all per RFC 9215 (byte orders verified against that document's own
     * appendix D test certificates, since this is where an implementation that only ever talks
     * to itself goes undetected):
     *
     * - Public keys: `x || y`, each a fixed-width *little-endian* integer of the parameter
     *   set's half-width (32 or 64 bytes), i.e. 64 or 128 bytes total (RFC 9215 section 2.4) --
     *   not a SEC1 point, and not big-endian like every other key in this library.
     * - Signatures: `s || r`, each a fixed-width *big-endian* integer of the same half-width
     *   (RFC 9215 section 2.3) -- note both that s comes first and that these halves are
     *   big-endian while the public key's are little-endian. There is no DER
     *   `SEQUENCE { r, s }` wrapper as there is for ECDSA.
     * - Private keys: d as a fixed-width little-endian integer of the half-width, matching the
     *   public key's coordinate order; the corresponding public point is re-derived as d*P on
     *   import rather than stored alongside.
     */
    class CERTPP_API CGost3410 : public IAsymmetric {
    private:
        CEcCurve _curve;
        EAsymmetrics _which;  // --> The specific parameter set, for IKeyBase::algorithm() --
                              // CEcCurve itself carries only domain parameters, no identity.
        size_t _halfLen;      // --> Width in bytes of one serialized r/s/coordinate (32 or 64).

    public:
        /**
         * @param which The GOST parameter set to run GOST R 34.10-2012 over; must be one of
         * EEcKnownCurves's ECURVE_GOST* entries.
         */
        explicit CGost3410(EEcKnownCurves which);

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;

        // --> Re-exposes IAsymmetric's COctet convenience overloads, which the SReadOnlyByteSpan
        // overrides above would otherwise hide: name lookup stops at the first scope holding the
        // name, so without these a caller holding a concrete CGost3410 cannot pass a COctet at all,
        // while the same call through an IAsymmetricPtr compiles.
        using IAsymmetric::createPublicKey;
        using IAsymmetric::createPrivateKey;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
