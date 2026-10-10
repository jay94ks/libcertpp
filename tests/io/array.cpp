#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/io/array.hpp>
#include <utility>

using namespace certpp;

namespace {
    /* An element type that tracks its own construction/destruction/assignment, so tests can
     * catch object-lifetime bugs (a leaked construction, a double destruction, or -- the one
     * this file's tests actually caught in TArray::insert() -- operator= or a copy/move
     * constructor running against memory whose object lifetime has already ended) that would be
     * invisible with a plain type like int. magic is set to ALIVE by every constructor and to
     * DEAD by the destructor; reading a "dead" object's leftover magic byte from operator=/a
     * copy or move constructor is exactly the diagnostic this is for, even though the object's
     * formal lifetime has ended -- the bytes are still there until something else overwrites them.
     */
    struct Tracker {
        static constexpr uint32_t ALIVE = 0xA11CE123u;
        static constexpr uint32_t DEAD = 0xDEADDEADu;

        static size_t liveCount;
        static size_t corruptionCount;

        uint32_t magic;
        int value;

        explicit Tracker(int v = 0) : magic(ALIVE), value(v) {
            ++liveCount;
        }

        Tracker(const Tracker& other) : magic(ALIVE), value(other.value) {
            if (other.magic != ALIVE) {
                ++corruptionCount;
            }
            ++liveCount;
        }

        Tracker(Tracker&& other) noexcept : magic(ALIVE), value(other.value) {
            if (other.magic != ALIVE) {
                ++corruptionCount;
            }
            other.value = -1;
            ++liveCount;
        }

        Tracker& operator=(const Tracker& other) {
            if (magic != ALIVE || other.magic != ALIVE) {
                ++corruptionCount;
            }
            value = other.value;
            return *this;
        }

        Tracker& operator=(Tracker&& other) noexcept {
            if (magic != ALIVE || other.magic != ALIVE) {
                ++corruptionCount;
            }
            value = other.value;
            other.value = -1;
            return *this;
        }

        ~Tracker() {
            if (magic != ALIVE) {
                ++corruptionCount; // double destruction
            }
            magic = DEAD;
            --liveCount;
        }
    };

    size_t Tracker::liveCount = 0;
    size_t Tracker::corruptionCount = 0;

    /* Resets Tracker's counters on construction, and asserts both are back to a clean state
     * (corruptionCount == 0, liveCount == 0) on destruction -- wrap a TEST_CASE's body in a nested
     * scope and construct one of these right before it to verify every Tracker the test created
     * was properly destroyed exactly once, with no lifetime corruption along the way.
     */
    struct TrackerGuard {
        TrackerGuard() {
            Tracker::liveCount = 0;
            Tracker::corruptionCount = 0;
        }

        ~TrackerGuard() {
            CHECK(Tracker::corruptionCount == 0);
            CHECK(Tracker::liveCount == 0);
        }
    };
}

TEST_CASE("TArray default construction is empty") {
    TArray<int> a;

    CHECK(a.empty());
    CHECK_FALSE(bool(a));
    CHECK(!a);
    CHECK(a.size() == 0);
    CHECK(a.capacity() == 0);
    CHECK(a.type() == EARRAY_NONE);
}

TEST_CASE("TArray(EArrayType) records the requested type even while still empty") {
    // empty() only looks at size (and treats EARRAY_NONE as empty regardless), so a freshly
    // constructed, still-size-0 array reports empty() even when given a non-NONE type.
    TArray<int> a(EARRAY_DYNAMIC);

    CHECK(a.empty());
    CHECK(a.type() == EARRAY_DYNAMIC);
}

TEST_CASE("TArray::add appends elements, growing capacity as needed") {
    TArray<int> a;

    REQUIRE(a.add(1));
    REQUIRE(a.add(2));
    REQUIRE(a.add(3));

    CHECK(a.size() == 3);
    CHECK(a.capacity() >= 3);
    CHECK(a[0] == 1);
    CHECK(a[1] == 2);
    CHECK(a[2] == 3);
    CHECK_FALSE(a.empty());
    CHECK(bool(a));
}

TEST_CASE("TArray::add(T&&) moves the value in rather than copying it") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        Tracker t(42);

        REQUIRE(a.add(std::move(t)));
        CHECK(a[0].value == 42);
        CHECK(t.value == -1); // moved-from, per Tracker's move constructor/assignment
    }
}

TEST_CASE("TArray::operator[] provides mutable and const element access") {
    TArray<int> a;
    a.add(10);
    a.add(20);

    a[0] = 99;
    CHECK(a[0] == 99);

    const TArray<int>& constRef = a;
    CHECK(constRef[1] == 20);
}

TEST_CASE("TArray begin()/end() support range-based iteration in insertion order") {
    TArray<int> a;
    a.add(1);
    a.add(2);
    a.add(3);

    int sum = 0;
    size_t count = 0;
    for (int v : a) {
        sum += v;
        ++count;
    }

    CHECK(count == 3);
    CHECK(sum == 6);
    CHECK(a.end() - a.begin() == static_cast<ptrdiff_t>(a.size()));
}

TEST_CASE("TArray copy constructor makes an independent, element-wise deep copy") {
    TrackerGuard guard;
    {
        TArray<Tracker> original;
        original.add(Tracker(1));
        original.add(Tracker(2));

        TArray<Tracker> copy(original);
        REQUIRE(copy.size() == 2);
        CHECK(copy[0].value == 1);
        CHECK(copy[1].value == 2);

        // Mutating the copy must not affect the original.
        copy[0].value = 999;
        CHECK(original[0].value == 1);
    }
}

TEST_CASE("TArray copy constructor of an empty array stays empty") {
    TArray<int> original;
    TArray<int> copy(original);

    CHECK(copy.empty());
    CHECK(copy.size() == 0);
}

TEST_CASE("TArray move constructor transfers ownership and empties the source") {
    TrackerGuard guard;
    {
        TArray<Tracker> original;
        original.add(Tracker(1));
        original.add(Tracker(2));

        const Tracker* originalData = original.begin();

        TArray<Tracker> moved(std::move(original));
        REQUIRE(moved.size() == 2);
        CHECK(moved.begin() == originalData); // ownership transferred, not re-copied
        CHECK(moved[0].value == 1);

        CHECK(original.empty());
        CHECK(original.size() == 0);
        CHECK(original.type() == EARRAY_NONE);
    }
}

TEST_CASE("TArray copy assignment deep-copies and is safe against self-assignment") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        a.add(Tracker(1));
        a.add(Tracker(2));

        TArray<Tracker> b;
        b.add(Tracker(100));

        b = a;
        REQUIRE(b.size() == 2);
        CHECK(b[0].value == 1);
        CHECK(b[1].value == 2);

        b[0].value = 555;
        CHECK(a[0].value == 1); // independent copy

        // Self-assignment must be a no-op, not a use-after-free.
        a = a;
        REQUIRE(a.size() == 2);
        CHECK(a[0].value == 1);
        CHECK(a[1].value == 2);
    }
}

TEST_CASE("TArray move assignment swaps state with the source") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        a.add(Tracker(1));

        TArray<Tracker> b;
        b.add(Tracker(2));
        b.add(Tracker(3));

        const Tracker* bData = b.begin();

        a = std::move(b);
        REQUIRE(a.size() == 2);
        CHECK(a.begin() == bData);
        CHECK(a[0].value == 2);
        CHECK(a[1].value == 3);

        // Swapped, not cleared: b now holds what a used to.
        REQUIRE(b.size() == 1);
        CHECK(b[0].value == 1);
    }
}

TEST_CASE("TArray constructed from a span copies elements independently of the source") {
    int raw[] = { 5, 6, 7 };
    TSpan<int> span(raw, 3);

    TArray<int> a(span);
    REQUIRE(a.size() == 3);
    CHECK(a[0] == 5);
    CHECK(a[2] == 7);

    a[0] = 999;
    CHECK(raw[0] == 5); // the array owns a copy, not a view over raw
}

TEST_CASE("TArray constructed from a read-only span copies elements independently of the source") {
    const int raw[] = { 8, 9 };
    TReadOnlySpan<int> span(raw, 2);

    TArray<int> a(span);
    REQUIRE(a.size() == 2);
    CHECK(a[0] == 8);
    CHECK(a[1] == 9);
}

TEST_CASE("TArray construction from an empty span stays empty") {
    TArray<int> fromSpan{ TSpan<int>(nullptr, 0) };
    CHECK(fromSpan.empty());

    TArray<int> fromReadOnlySpan{ TReadOnlySpan<int>(nullptr, 0) };
    CHECK(fromReadOnlySpan.empty());
}

TEST_CASE("TArray::operator=(TSpan) replaces existing content") {
    TArray<int> a;
    a.add(1);
    a.add(2);
    a.add(3);

    int raw[] = { 10, 20 };
    a = TSpan<int>(raw, 2);

    REQUIRE(a.size() == 2);
    CHECK(a[0] == 10);
    CHECK(a[1] == 20);
}

TEST_CASE("TArray::clear destroys all elements but keeps the reserved capacity") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        a.add(Tracker(1));
        a.add(Tracker(2));
        a.add(Tracker(3));

        size_t capBefore = a.capacity();
        a.clear();

        CHECK(a.size() == 0);
        CHECK(a.empty());
        CHECK(a.capacity() == capBefore); // clear() doesn't release memory, unlike trimExcess()
        CHECK(Tracker::liveCount == 0);
    }
}

TEST_CASE("TArray::reserve grows capacity and preserves existing elements") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        a.add(Tracker(1));
        a.add(Tracker(2));

        REQUIRE(a.reserve(64));
        CHECK(a.capacity() >= 64);
        REQUIRE(a.size() == 2);
        CHECK(a[0].value == 1);
        CHECK(a[1].value == 2);
    }
}

TEST_CASE("TArray::reserve is a no-op when capacity already suffices") {
    TArray<int> a;
    REQUIRE(a.reserve(16));
    size_t capAfterFirst = a.capacity();

    REQUIRE(a.reserve(4)); // smaller than current capacity
    CHECK(a.capacity() == capAfterFirst);
}

TEST_CASE("TArray::resize grows with default-constructed elements and shrinks by destroying trailing ones") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        REQUIRE(a.resize(3));
        REQUIRE(a.size() == 3);
        CHECK(a[0].value == 0); // default-constructed
        CHECK(Tracker::liveCount == 3);

        a[0].value = 10;
        a[1].value = 20;
        a[2].value = 30;

        REQUIRE(a.resize(5));
        REQUIRE(a.size() == 5);
        CHECK(a[0].value == 10); // untouched by growth
        CHECK(a[3].value == 0);  // newly default-constructed
        CHECK(Tracker::liveCount == 5);

        REQUIRE(a.resize(2));
        REQUIRE(a.size() == 2);
        CHECK(a[0].value == 10);
        CHECK(a[1].value == 20);
        CHECK(Tracker::liveCount == 2); // the 3 trailing elements were destroyed
    }
}

TEST_CASE("TArray::trimExcess shrinks capacity to match size, and fully releases memory when empty") {
    TArray<int> a;
    a.reserve(64);
    a.add(1);
    a.add(2);

    REQUIRE(a.trimExcess());
    CHECK(a.capacity() == a.size());

    a.clear();
    REQUIRE(a.trimExcess());
    CHECK(a.capacity() == 0);
    CHECK(a.type() == EARRAY_NONE); // an emptied-out dynamic array resets to EARRAY_NONE
}

TEST_CASE("TArray::remove(index) removes and shifts subsequent elements down") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        a.add(Tracker(1));
        a.add(Tracker(2));
        a.add(Tracker(3));

        REQUIRE(a.remove(1));
        REQUIRE(a.size() == 2);
        CHECK(a[0].value == 1);
        CHECK(a[1].value == 3);
        CHECK(Tracker::liveCount == 2);

        // Removing the last element needs no shifting.
        REQUIRE(a.remove(1));
        REQUIRE(a.size() == 1);
        CHECK(a[0].value == 1);
        CHECK(Tracker::liveCount == 1);
    }
}

TEST_CASE("TArray::remove(index) rejects an out-of-range index") {
    TArray<int> a;
    a.add(1);

    CHECK_FALSE(a.remove(1));
    CHECK_FALSE(a.remove(100));
    CHECK(a.size() == 1);
}

TEST_CASE("TArray::remove(index, count) removes a range and clamps count to what's available") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        for (int i = 0; i < 5; ++i) {
            a.add(Tracker(i));
        }

        CHECK(a.remove(1, 2) == 2); // removes values 1, 2
        REQUIRE(a.size() == 3);
        CHECK(a[0].value == 0);
        CHECK(a[1].value == 3);
        CHECK(a[2].value == 4);
        CHECK(Tracker::liveCount == 3);

        // count is clamped to the remaining elements from index onward.
        CHECK(a.remove(1, 100) == 2);
        REQUIRE(a.size() == 1);
        CHECK(a[0].value == 0);
        CHECK(Tracker::liveCount == 1);

        CHECK(a.remove(5, 1) == 0); // index >= size
    }
}

TEST_CASE("TArray::insert shifts existing elements and inserts the new value at any position") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        a.add(Tracker(1));
        a.add(Tracker(2));
        a.add(Tracker(3));

        SUBCASE("insert at the front") {
            REQUIRE(a.insert(0, Tracker(100)));
            REQUIRE(a.size() == 4);
            CHECK(a[0].value == 100);
            CHECK(a[1].value == 1);
            CHECK(a[2].value == 2);
            CHECK(a[3].value == 3);
        }

        SUBCASE("insert in the middle") {
            REQUIRE(a.insert(1, Tracker(100)));
            REQUIRE(a.size() == 4);
            CHECK(a[0].value == 1);
            CHECK(a[1].value == 100);
            CHECK(a[2].value == 2);
            CHECK(a[3].value == 3);
        }

        SUBCASE("insert at the end (equivalent to append)") {
            REQUIRE(a.insert(3, Tracker(100)));
            REQUIRE(a.size() == 4);
            CHECK(a[3].value == 100);
        }

        SUBCASE("insert at an out-of-range index fails") {
            CHECK_FALSE(a.insert(5, Tracker(100)));
            CHECK(a.size() == 3);
        }

        // Regression coverage: insert() used to shift elements by move-constructing sources
        // into place and destroying them, then *assign* (operator=, not placement-new) the new
        // value into the vacated front/middle slot -- but by then that slot's object lifetime
        // had already ended (its destructor ran as part of the shift), so the assignment ran
        // against dead memory. It also placement-constructed the first shifted element on top of
        // resize()'s freshly-default-constructed last slot without destroying it first, leaking
        // that instance. Tracker's operator=/copy-and-move constructors flag exactly this via
        // corruptionCount, checked by TrackerGuard's destructor at the end of this test case.
        CHECK(Tracker::corruptionCount == 0);
    }
}

TEST_CASE("TArray::insert(index, const T&) copies rather than moving the caller's value") {
    TArray<int> a;
    a.add(1);
    a.add(3);

    int value = 2;
    REQUIRE(a.insert(1, value));
    REQUIRE(a.size() == 3);
    CHECK(a[1] == 2);
    CHECK(value == 2); // untouched -- copied, not moved
}

TEST_CASE("TArray::pop(value) removes and returns the last element") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        a.add(Tracker(1));
        a.add(Tracker(2));

        Tracker out(0);
        REQUIRE(a.pop(out));
        CHECK(out.value == 2);
        REQUIRE(a.size() == 1);
        CHECK(a[0].value == 1);
        CHECK(Tracker::liveCount == 2); // `out` plus the one remaining element

        REQUIRE(a.pop(out));
        CHECK(out.value == 1);
        CHECK(a.empty());

        CHECK_FALSE(a.pop(out)); // empty
    }
}

TEST_CASE("TArray::pop() removes the last element without storing it") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;
        a.add(Tracker(1));
        a.add(Tracker(2));

        REQUIRE(a.pop());
        REQUIRE(a.size() == 1);
        CHECK(a[0].value == 1);
        CHECK(Tracker::liveCount == 1);

        REQUIRE(a.pop());
        CHECK(a.empty());
        CHECK(Tracker::liveCount == 0);

        CHECK_FALSE(a.pop()); // empty
    }
}

TEST_CASE("TArray::wrap aliases an existing buffer instead of copying it") {
    int raw[3] = { 1, 2, 3 };

    TArray<int> a;
    TArray<int>::wrap(a, raw, 3);

    REQUIRE(a.size() == 3);
    CHECK(a.begin() == raw); // aliased, not copied
    CHECK((a.type() & EARRAY_TYPE_MASK) == EARRAY_STATIC);
    CHECK(a[1] == 2);

    a[0] = 99;
    CHECK(raw[0] == 99); // mutating through the array mutates the wrapped buffer
}

TEST_CASE("TArray::wrap(fixed=true) rejects growth via reserve()/trimExcess()") {
    int raw[3] = { 1, 2, 3 };

    TArray<int> a;
    TArray<int>::wrap(a, raw, 3, true);

    CHECK(a.type() == EARRAY_STATIC_FIXED);
    CHECK_FALSE(a.reserve(10));
    CHECK_FALSE(a.trimExcess());
    CHECK(a.capacity() == 3); // unchanged by the rejected reserve()
}

TEST_CASE("TArray::wrap without fixed=true transforms into a dynamic array on growth, without freeing the wrapped buffer") {
    int raw[2] = { 1, 2 };

    TArray<int> a;
    TArray<int>::wrap(a, raw, 2, false);

    REQUIRE(a.reserve(10));
    CHECK((a.type() & EARRAY_TYPE_MASK) == EARRAY_DYNAMIC);
    CHECK(a.begin() != raw); // now backed by its own heap allocation
    CHECK(a.capacity() >= 10);

    REQUIRE(a.size() == 2);
    CHECK(a[0] == 1); // original wrapped content carried over
    CHECK(a[1] == 2);

    // raw is untouched (not freed) since it was never owned by the array.
    CHECK(raw[0] == 1);
    CHECK(raw[1] == 2);
}

TEST_CASE("TArray::markFixed prevents further growth") {
    TArray<int> a;
    a.add(1);
    a.add(2);

    REQUIRE((a.type() & EARRAY_FIXED) == 0);
    a.markFixed();
    CHECK((a.type() & EARRAY_FIXED) != 0);
    CHECK((a.type() & EARRAY_TYPE_MASK) == EARRAY_DYNAMIC); // sub-type preserved

    CHECK_FALSE(a.reserve(100));
    CHECK_FALSE(a.add(3)); // add() grows via resize()/reserve(), which now fails
    CHECK(a.size() == 2);
}

TEST_CASE("TArray::markFixed is a no-op on a still-EARRAY_NONE array") {
    TArray<int> a;
    REQUIRE(a.type() == EARRAY_NONE);

    a.markFixed();
    CHECK(a.type() == EARRAY_NONE); // markFixed() explicitly skips EARRAY_NONE arrays
}

TEST_CASE("TArray: a fixed array still gives back the buffer it owns") {
    // --> The destructor used to call trimExcess(), which returns false immediately on
    // EARRAY_FIXED -- before reaching its delete[]. So an array that had grown onto the heap
    // and was then marked fixed never released that buffer. An ASan leak check is the only
    // thing that sees it: the array's own observable state is entirely correct, so every
    // assertion an ordinary test could make passed while the memory leaked.
    //
    // Nothing here can assert the absence of a leak directly, so this test asserts the
    // behaviour the fix rests on -- that ownership is released regardless of the fixed flag --
    // and the leak checker covers the rest. It is worth keeping as an executable statement of
    // the intent even on a build without a leak checker.
    {
        TArray<int> a;
        a.add(1);
        a.add(2);
        REQUIRE((a.type() & EARRAY_TYPE_MASK) == EARRAY_DYNAMIC); // it owns heap memory

        a.markFixed();
        REQUIRE((a.type() & EARRAY_DYNAMIC_FIXED) == EARRAY_DYNAMIC_FIXED);
    } // destroyed here -- must not leak

    // --> Same for the static-fixed case, where the array does NOT own the buffer: wrapping a
    // fixed array over a caller-owned one must not free the caller's memory, and must still
    // give back whatever it owned before the wrap.
    int callerOwned[4] = { 1, 2, 3, 4 };
    {
        TArray<int> a;
        a.add(9);
        a.add(8);
        a.markFixed();

        TArray<int>::wrap(a, callerOwned, 4, /*fixed=*/true);
        CHECK(a.size() == 4);
        CHECK(a.type() == EARRAY_STATIC_FIXED);
    }

    // --> Still intact: wrap() must not have freed a buffer the array never owned.
    CHECK(callerOwned[0] == 1);
    CHECK(callerOwned[3] == 4);
}

TEST_CASE("TArray element lifetimes stay balanced across a mixed sequence of operations") {
    TrackerGuard guard;
    {
        TArray<Tracker> a;

        for (int i = 0; i < 10; ++i) {
            a.add(Tracker(i));
        }

        a.insert(0, Tracker(-1));
        a.insert(5, Tracker(-2));
        a.remove(3);
        a.remove(2, 3);
        a.resize(20);
        a.resize(4);

        Tracker popped(0);
        a.pop(popped);
        a.pop();

        REQUIRE(a.size() == Tracker::liveCount - 1); // -1 accounts for `popped`, still alive
        CHECK(Tracker::corruptionCount == 0);

        a.clear();
        CHECK(Tracker::liveCount == 1); // only `popped` remains
    }
}
