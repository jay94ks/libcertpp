#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

TEST_CASE("CRng::fill fills a buffer and is not all-zero") {
    uint8_t buf[64] = { 0 };
    CHECK(CRng::fill(SByteSpan(buf, sizeof(buf))) == ERET_OK);

    bool allZero = true;
    for (size_t i = 0; i < sizeof(buf); ++i) {
        if (buf[i] != 0) {
            allZero = false;
            break;
        }
    }

    CHECK_FALSE(allZero);
}

TEST_CASE("CRng::fill on empty span succeeds trivially") {
    CHECK(CRng::fill(SByteSpan(nullptr, 0)) == ERET_OK);
}

TEST_CASE("CRng::fillNonZero fills a buffer with no zero bytes") {
    uint8_t buf[256] = { 0 };
    CHECK(CRng::fillNonZero(SByteSpan(buf, sizeof(buf))) == ERET_OK);

    for (size_t i = 0; i < sizeof(buf); ++i) {
        CHECK(buf[i] != 0);
    }
}

TEST_CASE("CRng::fillNonZero on empty span succeeds trivially") {
    CHECK(CRng::fillNonZero(SByteSpan(nullptr, 0)) == ERET_OK);
}
