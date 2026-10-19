#ifndef __INCLUDE_CERTPP_CRYPTO_SYMS_DES_HPP__
#define __INCLUDE_CERTPP_CRYPTO_SYMS_DES_HPP__

#include <certpp/crypto/sym.hpp>

namespace certpp {
namespace crypto {

    /**
     * DES (FIPS 46-3), with a 64-bit key (56 effective bits; the 8 parity bits are accepted but
     * not checked). Provided for interoperating with legacy systems -- its 56-bit effective
     * security level is far below what any new design should use; see TripleDES or AES instead.
     * The ISymmetricContext createContext() returns operates in CBC mode with PKCS#7 padding
     * (RFC 5652 6.3); its iv() must be exactly 8 bytes (sizeOfBlock() once a key is bound) before
     * createEncrypter()/createDecrypter() will succeed.
     */
    class CERTPP_API DES : public ISymmetric {
    public:
        /**
         * Constructs a DES algorithm instance; keySizes() accepts only a 64-bit key.
         */
        DES();

        using ISymmetric::generateKey;
        using ISymmetric::createKey;
        ERetCode generateKey(
            const IRng& rng, ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const override;
        ERetCode createKey(ISymmetricKeyPtr& out, const SReadOnlyByteSpan& keyData) const override;
        using ISymmetric::generateIV;
        ERetCode generateIV(
            const IRng& rng, const ISymmetricKeyPtr& key, CBuffer& out) const override;
        using ISymmetric::createContext;
        ERetCode createContext(
            ISymmetricContextPtr& out, const ISymmetricKeyPtr& key) const override;
    };

} // namespace crypto
} // namespace certpp

#endif
