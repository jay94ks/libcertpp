#ifndef __INCLUDE_CERTPP_CRYPTO_SYMS_ARIA_HPP__
#define __INCLUDE_CERTPP_CRYPTO_SYMS_ARIA_HPP__

#include <certpp/crypto/sym.hpp>

namespace certpp {
namespace crypto {

    /**
     * ARIA (RFC 5794 / KS X 1213:2004), the Korean national block cipher: a 128-bit block
     * cipher with 128/192/256-bit keys and 12/14/16 rounds respectively.
     *
     * The `ISymmetricContext` createContext() returns operates in CBC mode -- the only mode
     * this library's ISymmetric block ciphers implement; its iv() must be exactly 16 bytes
     * (sizeOfBlock() once a key is bound) before createEncrypter()/createDecrypter() will
     * succeed.
     *
     * Padding is PKCS#7 (RFC 5652 6.3) unless the context's padding() is set to
     * ESYMPAD_NONE, which gives unpadded CBC for a caller whose payload is already
     * block-aligned and carries its own padding (IKEv2, RFC 7296 3.14).
     *
     * ARIA has no AEAD mode reachable from here, for the same reason AES-GCM is not: an AEAD
     * takes additional authenticated data and produces a tag, neither of which this
     * interface has anywhere to put.
     *
     * **There is no hardware acceleration path.** Unlike AES-NI, which Intel and AMD both
     * implement, ARIA has no instruction-set extension on any mainstream x86, so the
     * portable round functions are the implementation. The
     * `CERTPP_DISABLE_HWACCEL_SIMD` build option is accepted and deliberately changes
     * nothing here, so a build script that disables acceleration uniformly still configures.
     */
    class CERTPP_API ARIA : public ISymmetric {
    public:
        /**
         * Constructs an ARIA algorithm instance; keySizes() accepts 128/192/256-bit keys.
         */
        ARIA();

        ERetCode generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const override;
        ISymmetricKeyPtr createKey(const SReadOnlyByteSpan& keyData) const override;
        ERetCode generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const override;
        ISymmetricContextPtr createContext(const ISymmetricKeyPtr& key) const override;
    };

} // namespace crypto
} // namespace certpp

#endif