#ifndef __INCLUDE_CERTPP_CRYPTO_POLICY_HPP__
#define __INCLUDE_CERTPP_CRYPTO_POLICY_HPP__

#include <certpp/common.hpp>
#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/keys.hpp>

namespace certpp {
namespace crypto {

    /** Library guidance for selecting algorithms for new output. It does not disable parsing. */
    enum EAlgorithmPolicy {
        EALGPOL_RECOMMENDED = 0,          /**< Suitable for new output under the library's default guidance. */
        EALGPOL_COMPATIBILITY_ONLY,       /**< Retained for reading or interoperating with existing systems. */
        EALGPOL_DISABLED_FOR_GENERATION,  /**< Must not be selected for newly generated output. */
        EALGPOL_TEST_ONLY,                /**< Exposed only for test vectors and conformance work. */
        EALGPOL_UNKNOWN,                  /**< No policy rule is registered for the value. */
    };

    /** Central policy classifier used by applications before generating keys or signatures. */
    class CERTPP_API CAlgorithmPolicy {
    public:
        /** Classifies a hash algorithm for generation. */
        static EAlgorithmPolicy classify(EHashers algorithm);
        /** Classifies an asymmetric algorithm, including size-sensitive RSA and DSA rules. */
        static EAlgorithmPolicy classify(EAsymmetrics algorithm, SKeySize keySize = 0);
        /** Classifies a symmetric algorithm for generation. */
        static EAlgorithmPolicy classify(ESymmetrics algorithm);
        /** Classifies a key-encapsulation algorithm for generation. */
        static EAlgorithmPolicy classify(EKems algorithm);

        /** Returns whether the class permits generation of new output. */
        static bool allowsGeneration(EAlgorithmPolicy policy);
        /** Returns the stable diagnostic name of a policy class. */
        static const char* name(EAlgorithmPolicy policy);
    };

} // namespace crypto
} // namespace certpp

#endif
