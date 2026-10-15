#include <certpp/crypto/policy.hpp>

namespace certpp {
namespace crypto {

    EAlgorithmPolicy CAlgorithmPolicy::classify(EHashers algorithm) {
        switch (algorithm) {
            case EHASH_MD4:
            case EHASH_MD5:
                return EALGPOL_DISABLED_FOR_GENERATION;
            case EHASH_SHA1:
                return EALGPOL_COMPATIBILITY_ONLY;
            case EHASH_SHA224:
            case EHASH_SHA256:
            case EHASH_SHA384:
            case EHASH_SHA512:
            case EHASH_SHA3_256:
            case EHASH_SHA3_512:
            case EHASH_SHAKE128:
            case EHASH_SHAKE256:
            case EHASH_BLAKE2S:
            case EHASH_STREEBOG256:
            case EHASH_STREEBOG512:
                return EALGPOL_RECOMMENDED;
            default:
                return EALGPOL_UNKNOWN;
        }
    }

    EAlgorithmPolicy CAlgorithmPolicy::classify(EAsymmetrics algorithm, SKeySize keySize) {
        switch (algorithm) {
            case EASYM_GOST256TEST:
            case EASYM_GOST512TEST:
                return EALGPOL_TEST_ONLY;
            case EASYM_DSA:
            case EASYM_P192:
            case EASYM_BPOOL160R1:
            case EASYM_BPOOL160T1:
            case EASYM_BPOOL192R1:
            case EASYM_BPOOL192T1:
            case EASYM_B163:
            case EASYM_K163:
                return EALGPOL_DISABLED_FOR_GENERATION;
            case EASYM_P224:
            case EASYM_BPOOL224R1:
            case EASYM_BPOOL224T1:
            case EASYM_B233:
            case EASYM_K233:
                return EALGPOL_COMPATIBILITY_ONLY;
            case EASYM_RSA:
                if (keySize != 0 && keySize < 2048) {
                    return EALGPOL_DISABLED_FOR_GENERATION;
                }
                return EALGPOL_RECOMMENDED;
            case EASYM_ED25519:
            case EASYM_ED448:
            case EASYM_P256:
            case EASYM_P384:
            case EASYM_P521:
            case EASYM_SECP256K1:
            case EASYM_BPOOL256R1:
            case EASYM_BPOOL320R1:
            case EASYM_BPOOL384R1:
            case EASYM_BPOOL512R1:
            case EASYM_BPOOL256T1:
            case EASYM_BPOOL320T1:
            case EASYM_BPOOL384T1:
            case EASYM_BPOOL512T1:
            case EASYM_X25519:
            case EASYM_B283:
            case EASYM_K283:
            case EASYM_B409:
            case EASYM_K409:
            case EASYM_B571:
            case EASYM_K571:
            case EASYM_GOST256A:
            case EASYM_GOST256B:
            case EASYM_GOST256C:
            case EASYM_GOST256D:
            case EASYM_GOST512A:
            case EASYM_GOST512B:
            case EASYM_GOST512C:
            case EASYM_MLDSA44:
            case EASYM_MLDSA65:
            case EASYM_MLDSA87:
                return EALGPOL_RECOMMENDED;
            default:
                return EALGPOL_UNKNOWN;
        }
    }

    EAlgorithmPolicy CAlgorithmPolicy::classify(ESymmetrics algorithm) {
        switch (algorithm) {
            case ESYM_DES:
                return EALGPOL_DISABLED_FOR_GENERATION;
            case ESYM_3DES:
                return EALGPOL_COMPATIBILITY_ONLY;
            case ESYM_AES:
            case ESYM_CHACHA20:
            case ESYM_ARIA:
                return EALGPOL_RECOMMENDED;
            default:
                return EALGPOL_UNKNOWN;
        }
    }

    EAlgorithmPolicy CAlgorithmPolicy::classify(EKems algorithm) {
        switch (algorithm) {
            case EKEM_MLKEM512:
            case EKEM_MLKEM768:
            case EKEM_MLKEM1024:
                return EALGPOL_RECOMMENDED;
            default:
                return EALGPOL_UNKNOWN;
        }
    }

    bool CAlgorithmPolicy::allowsGeneration(EAlgorithmPolicy policy) {
        return policy == EALGPOL_RECOMMENDED;
    }

    const char* CAlgorithmPolicy::name(EAlgorithmPolicy policy) {
        switch (policy) {
            case EALGPOL_RECOMMENDED: return "recommended";
            case EALGPOL_COMPATIBILITY_ONLY: return "compatibility-only";
            case EALGPOL_DISABLED_FOR_GENERATION: return "disabled-for-generation";
            case EALGPOL_TEST_ONLY: return "test-only";
            default: return "unknown";
        }
    }

} // namespace crypto
} // namespace certpp
