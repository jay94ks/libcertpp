#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <string>

using namespace certpp;
using namespace certpp::crypto;

TEST_CASE("CAlgorithmPolicy classifies current, legacy, disabled and test-only algorithms") {
    CHECK(CAlgorithmPolicy::classify(EHASH_SHA256) == EALGPOL_RECOMMENDED);
    CHECK(CAlgorithmPolicy::classify(EHASH_SHA1) == EALGPOL_COMPATIBILITY_ONLY);
    CHECK(CAlgorithmPolicy::classify(EHASH_MD5) == EALGPOL_DISABLED_FOR_GENERATION);

    CHECK(CAlgorithmPolicy::classify(EASYM_RSA, 1024)
        == EALGPOL_DISABLED_FOR_GENERATION);
    CHECK(CAlgorithmPolicy::classify(EASYM_RSA, 3072) == EALGPOL_RECOMMENDED);
    CHECK(CAlgorithmPolicy::classify(EASYM_P224) == EALGPOL_COMPATIBILITY_ONLY);
    CHECK(CAlgorithmPolicy::classify(EASYM_GOST256TEST) == EALGPOL_TEST_ONLY);
    CHECK(CAlgorithmPolicy::classify(EASYM_MLDSA65) == EALGPOL_RECOMMENDED);

    CHECK(CAlgorithmPolicy::classify(ESYM_DES) == EALGPOL_DISABLED_FOR_GENERATION);
    CHECK(CAlgorithmPolicy::classify(ESYM_3DES) == EALGPOL_COMPATIBILITY_ONLY);
    CHECK(CAlgorithmPolicy::classify(ESYM_AES) == EALGPOL_RECOMMENDED);
    CHECK(CAlgorithmPolicy::classify(EKEM_MLKEM768) == EALGPOL_RECOMMENDED);

    CHECK(CAlgorithmPolicy::allowsGeneration(EALGPOL_RECOMMENDED));
    CHECK_FALSE(CAlgorithmPolicy::allowsGeneration(EALGPOL_COMPATIBILITY_ONLY));
    CHECK(std::string(CAlgorithmPolicy::name(EALGPOL_TEST_ONLY)) == "test-only");
}

TEST_CASE("CAlgorithmPolicy reports unknown enum values") {
    CHECK(CAlgorithmPolicy::classify(EHashers(0x7fff)) == EALGPOL_UNKNOWN);
    CHECK(CAlgorithmPolicy::classify(EAsymmetrics(0x7fff)) == EALGPOL_UNKNOWN);
    CHECK(CAlgorithmPolicy::classify(ESymmetrics(0x7fff)) == EALGPOL_UNKNOWN);
    CHECK(CAlgorithmPolicy::classify(EKems(0x7fff)) == EALGPOL_UNKNOWN);
}
