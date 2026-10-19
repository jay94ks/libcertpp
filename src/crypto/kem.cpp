#include <certpp/crypto/kem.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/crypto/kems/mlkem.hpp>

namespace certpp {
namespace crypto {

    IKemContext::IKemContext(const std::shared_ptr<IRng>& rng)
        : _rng(rng), _sizeOfCiphertext(0), _sizeOfSharedSecret(0) { }

    /* Returns the context-owned generator used by encapsulation. */
    const IRng& IKemContext::randomGenerator() const {
        return *_rng;
    }

    /* Generates a KEM key pair through the default operating-system-backed generator. */
    ERetCode IKem::generateKeyPair(SKeySize keySize, SKemKeyPair& out) {
        CRng rng;
        return generateKeyPair(rng, keySize, out);
    }

    /* Clones a caller-owned generator before placing it in a long-lived context. */
    ERetCode IKem::createContext(IKemContextPtr& out, const IRng& rng) const {
        out.reset();
        std::shared_ptr<IRng> owned;
        const ERetCode result = rng.clone(owned);
        if (result != ERET_OK) {
            return result;
        }
        return createContext(out, owned);
    }

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
