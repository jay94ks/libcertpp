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

        ERetCode generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const override;
        ISymmetricKeyPtr createKey(const SReadOnlyByteSpan& keyData) const override;
        ERetCode generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const override;
        ISymmetricContextPtr createContext(const ISymmetricKeyPtr& key) const override;
    };

} // namespace crypto
} // namespace certpp

#endif
