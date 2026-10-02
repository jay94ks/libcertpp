#include <certpp/crypto/kem.hpp>
#include <certpp/crypto/kems/mlkem.hpp>

namespace certpp {
namespace crypto {

    /* Resolves an EKems value to its concrete IKem implementation. */
    IKemPtr IKem::builtIn(EKems which) {
        switch (which) {
            case EKEM_MLKEM512:
            case EKEM_MLKEM768:
            case EKEM_MLKEM1024:
                // One class across all three, the way CEcdsa serves every prime curve -- the
                // parameter set is constructor state, not a separate implementation.
                return std::make_shared<MLKEM>(which);

            default:
                return nullptr;
        }
    }

} // namespace crypto
} // namespace certpp
