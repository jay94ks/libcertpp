#ifndef __INCLUDE_CERTPP_CRYPTO_SYMS_AES_HPP__
#define __INCLUDE_CERTPP_CRYPTO_SYMS_AES_HPP__

#include <certpp/crypto/sym.hpp>

namespace certpp {
namespace crypto {

    /**
     * AES (FIPS-197), with keys of 128/192/256 bits. The ISymmetricContext createContext()
     * returns operates in CBC mode -- the only mode this library's ISymmetric block ciphers
     * implement; its iv() must be exactly 16 bytes (sizeOfBlock() once a key is bound) before
     * createEncrypter()/createDecrypter() will succeed.
     *
     * Padding is PKCS#7 (RFC 5652 6.3) unless the context's padding() is set to ESYMPAD_NONE,
     * which gives unpadded CBC for a caller whose payload is already block-aligned and carries
     * its own padding (IKEv2, RFC 7296 3.14).
     *
     * AES-GCM is not reachable from here: an AEAD takes additional authenticated data and
     * produces a tag, neither of which this interface has anywhere to put. See
     * `crypto/aeads/aesgcm.hpp` (CAesGcm) for it.
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
