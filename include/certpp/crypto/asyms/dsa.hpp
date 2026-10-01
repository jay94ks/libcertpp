#ifndef __INCLUDE_CERTPP_CRYPTO_ASYMS_DSA_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYMS_DSA_HPP__

#include <certpp/crypto/asym.hpp>
#include <certpp/utils/bignum.hpp>

namespace certpp {
namespace crypto {

    /**
     * DSA (FIPS 186-4). Sign/verify only -- DSA has no encryption operation, so
     * createEncrypter()/createDecrypter() always report ERET_NOTSUP. keySizes() accepts the
     * three FIPS 186-4 approved (L, N) modulus/subgroup-order pairs, selected by L alone
     * (1024/160, 2048/256, 3072/256); generateKeyPair() also generates fresh domain parameters
     * (p, q, g) rather than requiring them supplied separately, since this library has no
     * separate domain-parameter type to share them through.
     *
     * Keys serialize as DER SEQUENCEs of the domain parameters plus the key material:
     * createPrivateKey()/serialize() use the traditional (OpenSSL-compatible) DSAPrivateKey
     * layout, `SEQUENCE { version INTEGER (0), p, q, g, y, x }`; the public key layout,
     * `SEQUENCE { p, q, g, y }`, is this library's own choice (there is no equally simple
     * traditional single-blob public-key format -- OpenSSL's splits the domain parameters into
     * a SubjectPublicKeyInfo AlgorithmIdentifier, which this library doesn't model yet).
     * Signatures serialize as the standard `Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
     * (RFC 3279).
     */
    class CERTPP_API DSA : public IAsymmetric {
    private:
        /**
         * Maps a DSA modulus size (L, in bits) to its FIPS 186-4 subgroup order (N, in bits).
         * @return The subgroup order N, or 0 for any L not among the three approved sizes this
         * library supports.
         */
        static size_t subgroupBitsFor(SKeySize keySizeL);

        /**
         * Generates FIPS 186-4-style domain parameters: q (an N-bit prime), p (an L-bit prime
         * with q | (p - 1)), and g (a generator of the order-q subgroup of Z*p).
         * @return true on success; false on failure (exhausted attempts or a CRng failure).
         */
        static bool generateDomainParams(size_t bitsL, size_t bitsN, CBigNum& p, CBigNum& q, CBigNum& g);

    public:
        /**
         * Constructs a DSA algorithm instance; keySizes() accepts exactly 1024, 2048, and 3072
         * bits (each selecting its FIPS 186-4 subgroup order N: 160, 256, and 256 respectively).
         */
        DSA();

        ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) override;
        ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const override;
        IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;
        IAsymmetricContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
