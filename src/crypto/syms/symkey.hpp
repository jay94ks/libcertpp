#ifndef __SRC_CRYPTO_SYMS_SYMKEY_HPP__
#define __SRC_CRYPTO_SYMS_SYMKEY_HPP__

#include <certpp/crypto/keys.hpp>

namespace certpp {
namespace crypto {

    /* A plain raw-byte symmetric key, shared by every ISymmetric implementation under
     * crypto/syms/ -- none of AES/DES/3DES/ChaCha20 need anything beyond the raw key bytes
     * ISymmetricKey already stores, so there's no reason for each to define its own
     * near-identical ISymmetricKey subclass. */
    class SymRawKey : public ISymmetricKey {
    public:
        SymRawKey(ESymmetrics algo, const COctet& raw) {
            algorithm(algo);
            keyData(raw);
        }

        size_t keySize() const override {
            return keyData().size();
        }
    };

} // namespace crypto
} // namespace certpp

#endif
