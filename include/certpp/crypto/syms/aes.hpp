#ifndef __INCLUDE_CERTPP_CRYPTO_SYMS_AES_HPP__
#define __INCLUDE_CERTPP_CRYPTO_SYMS_AES_HPP__

#include <certpp/crypto/sym.hpp>

namespace certpp {
namespace crypto {

    /**
     * AES (FIPS-197), with keys of 128/192/256 bits. The ISymmetricContext createContext()
     * returns operates in CBC mode with PKCS#7 padding (RFC 5652 6.3) -- the only mode this
     * library's block ciphers implement; its iv() must be exactly 16 bytes (sizeOfBlock() once a
     * key is bound) before createEncrypter()/createDecrypter() will succeed.
     */
    class CERTPP_API AES : public ISymmetric {
    public:
        /**
         * Constructs an AES algorithm instance; keySizes() accepts 128/192/256-bit keys.
         */
        AES();

        ERetCode generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const override;
        ISymmetricKeyPtr createKey(const SReadOnlyByteSpan& keyData) const override;
        ERetCode generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const override;
        ISymmetricContextPtr createContext(const ISymmetricKeyPtr& key) const override;
    };

} // namespace crypto
} // namespace certpp

#endif
