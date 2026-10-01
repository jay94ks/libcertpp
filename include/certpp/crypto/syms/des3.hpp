#ifndef __INCLUDE_CERTPP_CRYPTO_SYMS_DES3_HPP__
#define __INCLUDE_CERTPP_CRYPTO_SYMS_DES3_HPP__

#include <certpp/crypto/sym.hpp>

namespace certpp {
namespace crypto {

    /**
     * Triple DES / TDEA (FIPS 46-3 / SP 800-67) in two-key (K1 == K3, 128-bit) or three-key
     * (192-bit) Encrypt-Decrypt-Encrypt (EDE) mode, built on the same DES block core as DES.
     * The ISymmetricContext createContext() returns operates in CBC mode with PKCS#7 padding
     * (RFC 5652 6.3), chaining whole EDE blocks exactly like DES/AES chain single-cipher blocks;
     * its iv() must be exactly 8 bytes (sizeOfBlock() once a key is bound) before
     * createEncrypter()/createDecrypter() will succeed.
     */
    class CERTPP_API TripleDES : public ISymmetric {
    public:
        /**
         * Constructs a TripleDES algorithm instance; keySizes() accepts 128-bit (two-key) or
         * 192-bit (three-key) keys.
         */
        TripleDES();

        ERetCode generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const override;
        ISymmetricKeyPtr createKey(const SReadOnlyByteSpan& keyData) const override;
        ERetCode generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const override;
        ISymmetricContextPtr createContext(const ISymmetricKeyPtr& key) const override;
    };

} // namespace crypto
} // namespace certpp

#endif
