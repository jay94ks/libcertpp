#include <certpp/crypto/kem.hpp>

namespace certpp {
namespace crypto {

    /* Resolves an EKems value to its concrete IKem implementation. */
    IKemPtr IKem::builtIn(EKems which) {
        // --> No KEM is implemented yet: EKems has no concrete enumerators (EKEM_MAX == 0), so
        // there is nothing to dispatch to and every input is unknown. This definition exists
        // anyway because the declaration in kem.hpp does: without it, calling builtIn() fails at
        // link time instead of returning null, which is a worse way to find out. Each ML-KEM
        // parameter set adds its own case here, the same way IAsymmetric::builtIn() grows (see
        // src/crypto/asym.cpp, and docs/pqc-review.md's implementation plan).
        (void)which;
        return nullptr;
    }

} // namespace crypto
} // namespace certpp
