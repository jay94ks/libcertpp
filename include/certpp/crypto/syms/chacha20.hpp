#ifndef __INCLUDE_CERTPP_CRYPTO_SYMS_CHACHA20_HPP__
#define __INCLUDE_CERTPP_CRYPTO_SYMS_CHACHA20_HPP__

#include <certpp/crypto/sym.hpp>

namespace certpp {
namespace crypto {

    /**
     * ChaCha20 (RFC 8439), a 256-bit-keyed stream cipher: a 96-bit nonce plus an internal 32-bit
     * block counter (always starting at 0) are expanded into a keystream that's simply XORed
     * with the input, so encryption and decryption are the same operation and
     * createDecrypter() returns the same kind of transformer as createEncrypter(). Being a
     * stream cipher, it needs no padding and places no block-alignment requirement on input
     * length; sizeOfBlock() (64 once a key is bound) only reports the cipher's internal
     * keystream-generation granularity. iv() (the 96-bit nonce) must be exactly 12 bytes before
     * createEncrypter()/createDecrypter() will succeed.
     */
    class CERTPP_API ChaCha20 : public ISymmetric {
    public:
        /**
         * Constructs a ChaCha20 algorithm instance; keySizes() accepts only a 256-bit key.
         */
        ChaCha20();

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
