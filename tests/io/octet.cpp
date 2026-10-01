#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/io/octet.hpp>
#include <cstring>
#include <utility>

using namespace certpp;

TEST_CASE("COctet default construction is empty") {
    COctet octet;

    CHECK(octet.empty());
    CHECK_FALSE(bool(octet));
    CHECK(!octet);
    CHECK(octet.size() == 0);
    CHECK(octet.toPtr() == nullptr);
}

TEST_CASE("COctet(data, size) copies and owns the data") {
    const uint8_t data[] = { 1, 2, 3, 4 };
    COctet octet(data, sizeof(data));

    REQUIRE_FALSE(octet.empty());
    CHECK(bool(octet));
    REQUIRE(octet.size() == sizeof(data));
    CHECK(std::memcmp(octet.toPtr(), data, sizeof(data)) == 0);

    // --> Must be an owning copy, not a view over the caller's buffer.
    CHECK(octet.toPtr() != data);
}

TEST_CASE("COctet(SReadOnlyByteSpan) copies and owns the data") {
    const uint8_t data[] = { 5, 6, 7 };
    COctet octet(SReadOnlyByteSpan(data, sizeof(data)));

    REQUIRE(octet.size() == sizeof(data));
    CHECK(std::memcmp(octet.toPtr(), data, sizeof(data)) == 0);
    CHECK(octet.toPtr() != data);
}

TEST_CASE("COctet(nullptr, 0) / empty span construction stays empty") {
    COctet fromNull(nullptr, 0);
    CHECK(fromNull.empty());

    COctet fromEmptySpan(SReadOnlyByteSpan(nullptr, 0));
    CHECK(fromEmptySpan.empty());
}

TEST_CASE("COctet::toSpan reflects the stored data") {
    const uint8_t data[] = { 9, 8, 7 };
    COctet octet(data, sizeof(data));

    SReadOnlyByteSpan span = octet.toSpan();
    REQUIRE(span.size == sizeof(data));
    CHECK(span.data == octet.toPtr());
    CHECK(std::memcmp(span.data, data, sizeof(data)) == 0);

    COctet empty;
    CHECK(empty.toSpan().empty());
}

TEST_CASE("COctet::store replaces prior content") {
    const uint8_t first[] = { 1, 2, 3 };
    const uint8_t second[] = { 9, 9 };

    COctet octet;
    REQUIRE(octet.store(first, sizeof(first)));
    REQUIRE(octet.size() == sizeof(first));

    // --> A shorter store must fully replace the prior content, not just overwrite a prefix.
    REQUIRE(octet.store(second, sizeof(second)));
    REQUIRE(octet.size() == sizeof(second));
    CHECK(std::memcmp(octet.toPtr(), second, sizeof(second)) == 0);

    // --> Same-size store reuses the buffer but must still overwrite its content.
    const uint8_t sameSize[] = { 4, 5 };
    REQUIRE(octet.store(sameSize, sizeof(sameSize)));
    CHECK(std::memcmp(octet.toPtr(), sameSize, sizeof(sameSize)) == 0);
}

TEST_CASE("COctet::store rejects null/zero-size input without touching existing content") {
    const uint8_t data[] = { 1, 2, 3 };
    COctet octet(data, sizeof(data));

    CHECK_FALSE(octet.store(nullptr, sizeof(data)));
    CHECK_FALSE(octet.store(data, 0));

    // --> A rejected store must leave the previous content untouched.
    REQUIRE(octet.size() == sizeof(data));
    CHECK(std::memcmp(octet.toPtr(), data, sizeof(data)) == 0);
}

TEST_CASE("COctet::clear releases the data and resets to empty") {
    const uint8_t data[] = { 1, 2, 3 };
    COctet octet(data, sizeof(data));

    octet.clear();
    CHECK(octet.empty());
    CHECK(octet.size() == 0);
    CHECK(octet.toPtr() == nullptr);

    // --> Clearing an already-empty instance must be a harmless no-op.
    octet.clear();
    CHECK(octet.empty());
}

TEST_CASE("COctet copy constructor makes an independent copy") {
    const uint8_t data[] = { 1, 2, 3 };
    COctet original(data, sizeof(data));
    COctet copy(original);

    REQUIRE(copy.size() == original.size());
    CHECK(std::memcmp(copy.toPtr(), original.toPtr(), copy.size()) == 0);
    CHECK(copy.toPtr() != original.toPtr());

    // --> Mutating one must not affect the other.
    const uint8_t replacement[] = { 9 };
    copy.store(replacement, sizeof(replacement));
    CHECK(original.size() == sizeof(data));
    CHECK(std::memcmp(original.toPtr(), data, sizeof(data)) == 0);
}

TEST_CASE("COctet copy constructor from an empty instance stays empty") {
    COctet empty;
    COctet copy(empty);
    CHECK(copy.empty());
}

TEST_CASE("COctet copy assignment makes an independent copy") {
    const uint8_t data[] = { 1, 2, 3, 4, 5 };
    COctet original(data, sizeof(data));
    COctet copy;

    copy = original;
    REQUIRE(copy.size() == original.size());
    CHECK(std::memcmp(copy.toPtr(), original.toPtr(), copy.size()) == 0);
    CHECK(copy.toPtr() != original.toPtr());
}

TEST_CASE("COctet copy assignment from an empty instance clears the destination") {
    // Regression test: operator=(const COctet&) delegated straight to store(), which no-ops
    // (returns false) on a null/zero-size source instead of clearing -- so assigning from an
    // empty COctet onto a non-empty one used to leave the stale content in place.
    const uint8_t data[] = { 1, 2, 3 };
    COctet nonEmpty(data, sizeof(data));
    COctet empty;

    nonEmpty = empty;
    CHECK(nonEmpty.empty());
    CHECK(nonEmpty.size() == 0);
    CHECK(nonEmpty.toPtr() == nullptr);
}

TEST_CASE("COctet copy assignment self-assignment is a harmless no-op") {
    const uint8_t data[] = { 1, 2, 3 };
    COctet octet(data, sizeof(data));

    octet = octet;
    REQUIRE(octet.size() == sizeof(data));
    CHECK(std::memcmp(octet.toPtr(), data, sizeof(data)) == 0);
}

TEST_CASE("COctet move constructor transfers ownership and empties the source") {
    const uint8_t data[] = { 1, 2, 3 };
    COctet original(data, sizeof(data));
    const uint8_t* originalPtr = original.toPtr();

    COctet moved(std::move(original));
    REQUIRE(moved.size() == sizeof(data));
    CHECK(moved.toPtr() == originalPtr);
    CHECK(std::memcmp(moved.toPtr(), data, sizeof(data)) == 0);

    CHECK(original.empty());
    CHECK(original.toPtr() == nullptr);
}

TEST_CASE("COctet move assignment swaps state with the source, rather than emptying it") {
    // Move assignment is swap-based: the moved-from object ends up holding whatever the
    // destination held before the assignment (still a valid COctet, just not necessarily
    // empty) -- freeing dest's original content happens later, when source's destructor runs.
    const uint8_t sourceData[] = { 1, 2, 3 };
    const uint8_t destData[] = { 9, 9 };

    COctet source(sourceData, sizeof(sourceData));
    COctet dest(destData, sizeof(destData));
    const uint8_t* sourcePtr = source.toPtr();
    const uint8_t* destPtr = dest.toPtr();

    dest = std::move(source);
    REQUIRE(dest.size() == sizeof(sourceData));
    CHECK(dest.toPtr() == sourcePtr);
    CHECK(std::memcmp(dest.toPtr(), sourceData, sizeof(sourceData)) == 0);

    REQUIRE(source.size() == sizeof(destData));
    CHECK(source.toPtr() == destPtr);
    CHECK(std::memcmp(source.toPtr(), destData, sizeof(destData)) == 0);
}

TEST_CASE("COctet move assignment from/into an empty instance still empties the right side") {
    const uint8_t data[] = { 1, 2, 3 };

    COctet nonEmpty(data, sizeof(data));
    COctet empty;
    nonEmpty = std::move(empty);
    CHECK(nonEmpty.empty());
    CHECK(nonEmpty.toPtr() == nullptr);
    // `empty` now holds what `nonEmpty` used to (swap semantics), not necessarily empty itself.
    REQUIRE(empty.size() == sizeof(data));
    CHECK(std::memcmp(empty.toPtr(), data, sizeof(data)) == 0);
}
