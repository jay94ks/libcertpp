#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/io/buffer.hpp>
#include <cstdint>
#include <cstring>
#include <utility>

using namespace certpp;

TEST_CASE("CBuffer stores, resizes, copies, and moves owned bytes") {
    const uint8_t bytes[] = { 1, 2, 3, 4 };
    CBuffer original(bytes, sizeof(bytes));
    REQUIRE(original.size() == sizeof(bytes));

    CBuffer copy(original);
    REQUIRE(copy.toPtr() != original.toPtr());
    CHECK(std::memcmp(copy.toPtr(), bytes, sizeof(bytes)) == 0);

    REQUIRE(copy.resize(6));
    CHECK(std::memcmp(copy.toPtr(), bytes, sizeof(bytes)) == 0);

    const uint8_t* movedPointer = copy.toPtr();
    CBuffer moved(std::move(copy));
    CHECK(moved.toPtr() == movedPointer);
    CHECK(copy.empty());
}

TEST_CASE("CSecureBuffer preserves the CBuffer value contract") {
    const uint8_t first[] = { 0x11, 0x22, 0x33, 0x44 };
    const uint8_t second[] = { 0xAA, 0xBB };

    CSecureBuffer original(first, sizeof(first));
    REQUIRE(original.size() == sizeof(first));
    CHECK(reinterpret_cast<std::uintptr_t>(original.toPtr()) % 16 == 0);
    CHECK(std::memcmp(original.toPtr(), first, sizeof(first)) == 0);

    CSecureBuffer copy(original);
    REQUIRE(copy.toPtr() != original.toPtr());
    CHECK(std::memcmp(copy.toPtr(), first, sizeof(first)) == 0);

    REQUIRE(copy.resize(2));
    CHECK(std::memcmp(copy.toPtr(), first, 2) == 0);
    REQUIRE(copy.store(second, sizeof(second)));
    CHECK(std::memcmp(copy.toPtr(), second, sizeof(second)) == 0);

    const uint8_t* movedPointer = copy.toPtr();
    CSecureBuffer moved(std::move(copy));
    CHECK(moved.toPtr() == movedPointer);
    CHECK(copy.empty());

    moved.clear();
    CHECK(moved.empty());
    CHECK(moved.toPtr() == nullptr);
}

TEST_CASE("CSecureBuffer copies from ordinary and protected buffers") {
    const uint8_t bytes[] = { 7, 8, 9 };
    CBuffer ordinary(bytes, sizeof(bytes));
    CSecureBuffer first;
    CSecureBuffer second;

    REQUIRE(first.storeFrom(ordinary));
    REQUIRE(second.storeFrom(first));
    CHECK(std::memcmp(second.toPtr(), bytes, sizeof(bytes)) == 0);
}
