#include <certpp/x509/chain.hpp>

namespace certpp {
namespace x509 {

    /* Constructs an empty entry. */
    SCertEntry::SCertEntry() {
    }

    // --> Interface only, for now. `chain.hpp` is the design being settled before the PKCS#12
    // container that will sit on it, since the container needs every one of these operations and
    // nothing beyond them -- so the shape is worth agreeing on before it is buried behind
    // password-based encryption.
    //
    // The remaining members are declared in the header and not yet defined here. That is the
    // stub arrangement docs/coding-conventions.md describes for a header whose out-of-line code
    // has not been written: the file exists so the definitions have a home without restructuring,
    // and CMakeLists.txt globs it automatically. Nothing in the library or the tests calls them
    // yet, so nothing fails to link; the first caller will be the PKCS#12 work.
    //
    // One note for whoever writes them, because it is the only part of this interface that is
    // easy to get subtly wrong: findIssuerOf() must prefer an AuthorityKeyIdentifier match over
    // a bare subject-name match. A CA that re-keys issues a second certificate with the same
    // subject and a different key, so name matching alone can return the wrong one -- and the
    // failure is not a clean error. The chain assembles, verifyLinks() then fails on a signature
    // that was never going to match, and the symptom points at the signature rather than at the
    // lookup that chose the wrong issuer.

} // namespace x509
} // namespace certpp
