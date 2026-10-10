#include <certpp/crypto/sym.hpp>
#include <certpp/crypto/syms/aes.hpp>
#include <certpp/crypto/syms/aria.hpp>
#include <certpp/crypto/syms/des.hpp>
#include <certpp/crypto/syms/des3.hpp>
#include <certpp/crypto/syms/chacha20.hpp>

namespace certpp {
namespace crypto {

    ISymmetricPtr ISymmetric::builtIn(ESymmetrics which) {
        switch (which) {
            case ESYM_AES:
                return std::make_shared<AES>();

            case ESYM_DES:
                return std::make_shared<DES>();

            case ESYM_3DES:
                return std::make_shared<TripleDES>();

            case ESYM_CHACHA20:
                return std::make_shared<ChaCha20>();

            case ESYM_ARIA:
                return std::make_shared<ARIA>();

            default:
                return nullptr;
        }
    }

} // namespace crypto
} // namespace certpp
