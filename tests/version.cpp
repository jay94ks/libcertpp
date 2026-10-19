#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/version.hpp>

using namespace certpp;

TEST_CASE("SVersion comparisons ignore the secure-memory build marker") {
    const SVersion ordinary(1, 2, 3);
    const SVersion unprotected(1 | VERSION_FLAG_SECURE_MEM_DISABLED, 2, 3);

    CHECK(ordinary == unprotected);
    CHECK_FALSE(ordinary != unprotected);
    CHECK_FALSE(ordinary < unprotected);
    CHECK_FALSE(ordinary > unprotected);
    CHECK(ordinary <= unprotected);
    CHECK(ordinary >= unprotected);
    CHECK(ordinary.isSecureMemory());
    CHECK_FALSE(unprotected.isSecureMemory());

    const SVersion nextMajor(2, 0, 0);
    const SVersion markedNextMajor(2 | VERSION_FLAG_SECURE_MEM_DISABLED, 0, 0);
    CHECK(ordinary < markedNextMajor);
    CHECK(markedNextMajor > ordinary);
    CHECK(nextMajor == markedNextMajor);
}

TEST_CASE("GetLibraryVersion preserves the semantic header version") {
    const SVersion linked = GetLibraryVersion();
    CHECK(linked == HEADER_VERSION);
    CHECK((linked.major & ~VERSION_FLAG_SECURE_MEM_DISABLED) == HEADER_VERSION.major);
#if defined(CERTPP_TEST_SECURE_MEMORY_DISABLED)
    CHECK_FALSE(linked.isSecureMemory());
#else
    CHECK(linked.isSecureMemory());
#endif
}
