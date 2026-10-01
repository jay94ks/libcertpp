#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/string.hpp>
#include <cstring>
#include <clocale>
#include <cwchar>
#include <string>
#include <type_traits>

using namespace certpp;

/* Temporarily switches the C locale for a scope, restoring the previous one on destruction --
 * mbsrtowcs()/wcsrtombs() (used by TString's char<->wchar_t convert()) only interpret multibyte
 * text as UTF-8 when the active locale says so; the process otherwise starts in the "C" locale. */
struct LocaleGuard {
    std::string previous;
    bool active;

    explicit LocaleGuard(const char* name) : active(false) {
        const char* cur = std::setlocale(LC_ALL, nullptr);
        previous = cur ? cur : "C";
        active = std::setlocale(LC_ALL, name) != nullptr;
    }

    ~LocaleGuard() {
        std::setlocale(LC_ALL, previous.c_str());
    }
};

// ===========================================================================
// TStringFunctions<T> -- the static character-array primitives TString<T> is
// built on (extracted out of TString itself so they can be reused directly).
// ===========================================================================

TEST_CASE("TStringFunctions::fillZero zeroes exactly size elements") {
    using F = TStringFunctions<char>;

    char buf[6] = { 'A', 'A', 'A', 'A', 'A', 'Z' };
    F::fillZero(buf, 5);

    for (int i = 0; i < 5; ++i) {
        CHECK(buf[i] == '\0');
    }
    CHECK(buf[5] == 'Z'); // untouched, one past what was asked to be filled
}

TEST_CASE("TStringFunctions::copy copies exactly size elements, non-overlapping") {
    using F = TStringFunctions<char>;

    const char src[] = "hello!";
    char dest[7] = {};
    F::copy(dest, src, 5);

    CHECK(std::memcmp(dest, "hello", 5) == 0);
    CHECK(dest[5] == '\0'); // untouched
}

TEST_CASE("TStringFunctions::move handles overlapping ranges correctly") {
    using F = TStringFunctions<char>;

    char buf[] = "abcdefgh";
    // Shift "cdefgh" (6 chars starting at index 2) left onto index 0 -- source and destination
    // overlap, which is exactly why move() must use memmove(), not memcpy().
    F::move(buf, buf + 2, 6);

    CHECK(std::memcmp(buf, "cdefgh", 6) == 0);
}

TEST_CASE("TStringFunctions::chr finds the first occurrence, including at index 0") {
    using F = TStringFunctions<char>;

    const char data[] = "banana";
    CHECK(F::chr(data, 6, 'b') == data);       // first character
    CHECK(F::chr(data, 6, 'a') == data + 1);   // first of several
    CHECK(F::chr(data, 6, 'z') == nullptr);    // not present
    CHECK(F::chr(nullptr, 6, 'a') == nullptr);
    CHECK(F::chr(data, 0, 'b') == nullptr);
}

TEST_CASE("TStringFunctions::rchr finds the last occurrence, including at index 0") {
    // Regression test: rchr() used to start at str[size] (one past the last valid index --
    // harmlessly the NUL terminator for a TString's own buffer, but still logically wrong) and
    // stop as soon as size reached 0 without ever checking str[0], so a match at the very start
    // of the string was never found.
    using F = TStringFunctions<char>;

    const char data[] = "banana";
    CHECK(F::rchr(data, 6, 'a') == data + 5);  // last of several
    CHECK(F::rchr(data, 6, 'b') == data);      // only occurrence is at index 0
    CHECK(F::rchr(data, 6, 'z') == nullptr);
    CHECK(F::rchr(nullptr, 6, 'a') == nullptr);
    CHECK(F::rchr(data, 0, 'b') == nullptr);

    const char single[] = "x";
    CHECK(F::rchr(single, 1, 'x') == single);
}

TEST_CASE("TStringFunctions::cmp compares like memcmp, sign only") {
    using F = TStringFunctions<char>;

    CHECK(F::cmp("abc", "abc", 3) == 0);
    CHECK(F::cmp("abc", "abd", 3) < 0);
    CHECK(F::cmp("abd", "abc", 3) > 0);
    CHECK(F::cmp("ABC", "abc", 3) != 0); // case-sensitive

    CHECK(F::cmp(nullptr, "abc", 3) == 0);
    CHECK(F::cmp("abc", nullptr, 3) == 0);
    CHECK(F::cmp("abc", "abc", 0) == 0);
}

TEST_CASE("TStringFunctions::caseCmp compares ASCII letters case-insensitively") {
    using F = TStringFunctions<char>;

    CHECK(F::caseCmp("ABC", "abc", 3) == 0);
    CHECK(F::caseCmp("Hello", "hello", 5) == 0);
    CHECK(F::caseCmp("abc", "abd", 3) < 0);
    CHECK(F::caseCmp("abd", "abc", 3) > 0);

    // Non-letter bytes participate as-is (no folding), same as the real content would compare.
    CHECK(F::caseCmp("abc123", "ABC123", 6) == 0);
    CHECK(F::caseCmp("abc!", "ABC?", 4) != 0);

    CHECK(F::caseCmp(nullptr, "abc", 3) == 0);
    CHECK(F::caseCmp("abc", "abc", 0) == 0);
}

TEST_CASE("TStringFunctions<wchar_t>::cmp / caseCmp mirror the char instantiation") {
    using F = TStringFunctions<wchar_t>;

    CHECK(F::cmp(L"abc", L"abc", 3) == 0);
    CHECK(F::cmp(L"abc", L"abd", 3) < 0);

    CHECK(F::caseCmp(L"ABC", L"abc", 3) == 0);
    CHECK(F::caseCmp(L"abc", L"abd", 3) < 0);
}

TEST_CASE("TStringFunctions::find / findLast return offsets, not pointers") {
    // Regression test: find()/findLast() used to declare a local `const T* ch` that shadowed the
    // `T ch` parameter, and then passed that (not-yet-initialized-at-that-point) shadowed `ch`
    // to chr()/rchr() as the character to search for instead of the caller's argument -- a
    // self-referential initializer bug that shouldn't even type-check (T vs const T*), let alone
    // return a correct offset.
    using F = TStringFunctions<char>;

    const char data[] = "banana";
    CHECK(F::find(data, 6, 'b') == 0);
    CHECK(F::find(data, 6, 'a') == 1);
    CHECK(F::find(data, 6, 'z') == -1);
    CHECK(F::find(nullptr, 6, 'a') == -1);

    CHECK(F::findLast(data, 6, 'a') == 5);
    CHECK(F::findLast(data, 6, 'b') == 0); // only occurrence is at index 0
    CHECK(F::findLast(data, 6, 'z') == -1);
    CHECK(F::findLast(nullptr, 6, 'a') == -1);
}

TEST_CASE("TStringFunctions::countOf stops at a NUL within limit, or at limit itself") {
    using F = TStringFunctions<char>;

    CHECK(F::countOf("hello") == 5);
    CHECK(F::countOf("hello", 3) == 3);       // limited before the NUL
    CHECK(F::countOf("hello", 100) == 5);     // limit beyond the NUL doesn't overrun it

    const char embeddedNul[] = { 'a', 'b', '\0', 'c' };
    CHECK(F::countOf(embeddedNul, 4) == 2);   // stops at the embedded NUL

    CHECK(F::countOf(nullptr) == 0);
    CHECK(F::countOf("hello", 0) == 0);
}

TEST_CASE("TStringFunctions::isSpace / toLower / toUpper") {
    using F = TStringFunctions<char>;

    CHECK(F::isSpace(' '));
    CHECK(F::isSpace('\t'));
    CHECK_FALSE(F::isSpace('a'));

    CHECK(F::toLower('A') == 'a');
    CHECK(F::toLower('a') == 'a');
    CHECK(F::toUpper('a') == 'A');
    CHECK(F::toUpper('A') == 'A');
}

TEST_CASE("TStringFunctions<wchar_t> mirrors the char instantiation") {
    using F = TStringFunctions<wchar_t>;

    const wchar_t data[] = L"banana";
    CHECK(F::chr(data, 6, L'b') == data);
    CHECK(F::rchr(data, 6, L'b') == data); // regression case, wide instantiation too
    CHECK(F::find(data, 6, L'a') == 1);
    CHECK(F::findLast(data, 6, L'b') == 0); // regression case
    CHECK(F::countOf(data) == 6);
    CHECK(F::toUpper(L'a') == L'A');
}

TEST_CASE("TString<T>::Functions is the same type as TStringFunctions<T>") {
    CHECK(std::is_same<TString<char>::Functions, TStringFunctions<char>>::value);
    CHECK(std::is_same<TString<wchar_t>::Functions, TStringFunctions<wchar_t>>::value);
}

// ===========================================================================
// TString<T>
// ===========================================================================

TEST_CASE("default construction") {
    TString<char> s;

    CHECK(s.empty());
    CHECK(s.size() == 0);
    CHECK(s.capacity() == 0);
    CHECK_FALSE(bool(s));
    CHECK(!s);
}

TEST_CASE("construction from a C string") {
    TString<char> s("hello");

    CHECK_FALSE(s.empty());
    CHECK(s.size() == 5);
    CHECK(std::memcmp(s.toPtr(), "hello", 5) == 0);
    CHECK(s.toPtr()[5] == '\0'); // null-terminated
}

TEST_CASE("construction from a pointer + a limit stops early at an embedded NUL") {
    // TString(data, limit) delegates to append()/countOf(), which treats limit as an upper
    // bound on a NUL-terminated string, not a raw byte count -- an embedded NUL within limit
    // ends the copy early, same as countOf(data, limit) elsewhere in this class.
    const char data[] = { 'a', 'b', '\0', 'c' };
    TString<char> s(data, 4);

    REQUIRE(s.size() == 2);
    CHECK(s.toPtr()[0] == 'a');
    CHECK(s.toPtr()[1] == 'b');
    CHECK(s.toPtr()[2] == '\0'); // null-terminated past the copied content

    // Without an embedded NUL, exactly limit characters are copied.
    const char noNul[] = { 'w', 'x', 'y', 'z' };
    TString<char> full(noNul, 4);
    REQUIRE(full.size() == 4);
    CHECK(std::memcmp(full.toPtr(), noNul, 4) == 0);
}

TEST_CASE("copy construction / assignment are independent copies") {
    TString<char> a("hello");
    TString<char> b(a);

    CHECK(b.size() == 5);
    CHECK(std::memcmp(b.toPtr(), "hello", 5) == 0);

    b.append('!');
    CHECK(a.size() == 5); // a is untouched
    CHECK(b.size() == 6);

    TString<char> c;
    c = a;
    CHECK(c.size() == 5);
    CHECK(std::memcmp(c.toPtr(), "hello", 5) == 0);
}

TEST_CASE("move construction / assignment transfer ownership") {
    TString<char> a("hello");
    const char* originalPtr = a.toPtr();

    TString<char> b(std::move(a));
    CHECK(b.size() == 5);
    CHECK(b.toPtr() == originalPtr); // buffer was transferred, not copied
    CHECK(a.empty());
    CHECK(a.toPtr() == nullptr);

    TString<char> c;
    c = std::move(b);
    CHECK(c.toPtr() == originalPtr);
    CHECK(b.empty());
}

TEST_CASE("move assignment swaps state with the source, rather than emptying it") {
    // Move assignment is swap-based: the moved-from object ends up holding whatever the
    // destination held before the assignment (still a valid TString, just not necessarily
    // empty) -- freeing dest's original content happens later, when source's destructor runs.
    TString<char> source("hello");
    TString<char> dest("worldwide"); // longer, so its buffer is distinguishable from source's
    const char* sourcePtr = source.toPtr();
    const char* destPtr = dest.toPtr();

    dest = std::move(source);
    CHECK(dest.toPtr() == sourcePtr);
    CHECK(dest == TString<char>("hello"));

    CHECK(source.toPtr() == destPtr);
    CHECK(source == TString<char>("worldwide"));
}

TEST_CASE("assignment from a C string replaces existing content") {
    TString<char> s("hello");
    s = "world!";

    CHECK(s.size() == 6);
    CHECK(std::memcmp(s.toPtr(), "world!", 6) == 0);
}

TEST_CASE("reserve rounds up to the capacity increment and never shrinks") {
    TString<char> s;

    REQUIRE(s.reserve(1));
    CHECK(s.capacity() == 64); // CAP_INC

    REQUIRE(s.reserve(64));
    CHECK(s.capacity() == 64); // already enough, no change

    REQUIRE(s.reserve(65));
    CHECK(s.capacity() == 128);

    REQUIRE(s.reserve(1)); // smaller than current capacity: no-op, not a shrink
    CHECK(s.capacity() == 128);
}

TEST_CASE("resize grows/shrinks the logical size and keeps the string null-terminated") {
    TString<char> s("hello");

    REQUIRE(s.resize(3));
    CHECK(s.size() == 3);
    CHECK(std::memcmp(s.toPtr(), "hel", 3) == 0);
    CHECK(s.toPtr()[3] == '\0');

    REQUIRE(s.resize(5));
    CHECK(s.size() == 5);
    CHECK(s.toPtr()[5] == '\0');
}

TEST_CASE("clear resets size but keeps allocated capacity") {
    TString<char> s("hello");
    size_t capBefore = s.capacity();

    REQUIRE(s.clear());
    CHECK(s.empty());
    CHECK(s.size() == 0);
    CHECK(s.capacity() == capBefore);
}

TEST_CASE("trimExcess drops unused capacity, and frees storage entirely when empty") {
    TString<char> s("hi");
    REQUIRE(s.capacity() >= 64);

    REQUIRE(s.trimExcess());
    CHECK(s.capacity() == s.size() + 1);

    REQUIRE(s.trimExcess()); // already minimal: still reports success
    CHECK(s.capacity() == s.size() + 1);

    s.clear();
    REQUIRE(s.trimExcess());
    CHECK(s.capacity() == 0);
}

TEST_CASE("append(C string) / append(TString) / append(char)") {
    TString<char> s("foo");

    s.append("bar");
    CHECK(s.size() == 6);
    CHECK(std::memcmp(s.toPtr(), "foobar", 6) == 0);

    TString<char> suffix("baz");
    s.append(suffix);
    CHECK(s.size() == 9);
    CHECK(std::memcmp(s.toPtr(), "foobarbaz", 9) == 0);

    s.append('!');
    CHECK(s.size() == 10);
    CHECK(s.toPtr()[9] == '!');
    CHECK(s.toPtr()[10] == '\0');
}

TEST_CASE("append(C string, limit) only copies up to limit characters") {
    TString<char> s;
    s.append("hello world", 5);

    CHECK(s.size() == 5);
    CHECK(std::memcmp(s.toPtr(), "hello", 5) == 0);
}

TEST_CASE("append of an empty string/char sequence is a no-op") {
    TString<char> s("foo");

    s.append("");
    CHECK(s.size() == 3);

    TString<char> empty;
    s.append(empty);
    CHECK(s.size() == 3);
}

TEST_CASE("erase removes a range and shifts the remainder left") {
    TString<char> s("hello world");

    s.erase(5, 1); // remove the space
    CHECK(s.size() == 10);
    CHECK(std::memcmp(s.toPtr(), "helloworld", 10) == 0);
    CHECK(s.toPtr()[10] == '\0');
}

TEST_CASE("erase with only a start position removes to the end (default count)") {
    TString<char> s("hello world");

    s.erase(5);
    CHECK(s.size() == 5);
    CHECK(std::memcmp(s.toPtr(), "hello", 5) == 0);
}

TEST_CASE("erase clamps an out-of-range count and ignores an out-of-range start") {
    TString<char> s("hello");

    s.erase(2, 1000);
    CHECK(s.size() == 2);
    CHECK(std::memcmp(s.toPtr(), "he", 2) == 0);

    TString<char> t("hello");
    t.erase(100, 1); // start beyond size: no-op
    CHECK(t.size() == 5);
}

TEST_CASE("find(char) and find(char, skipBefore)") {
    TString<char> s("hello world");

    CHECK(s.find('o') == 4);
    CHECK(s.find('o', 5) == 7);
    CHECK(s.find('z') == -1);
    CHECK(s.find('o', 100) == -1); // skipBefore out of range
}

TEST_CASE("find(substring) and find(substring, skipBefore)") {
    TString<char> s("hello world hello");

    CHECK(s.find("world") == 6);
    CHECK(s.find("hello") == 0);
    CHECK(s.find("hello", 1) == 12);
    CHECK(s.find("xyz") == -1);
    CHECK(s.find("hello world hello!") == -1); // longer than the string
}

TEST_CASE("findLast(char) and findLast(char, skipFromEnd)") {
    TString<char> s("hello world");

    CHECK(s.findLast('o') == 7);
    CHECK(s.findLast('o', 4) == 4); // skip the last 4 chars ("orld"), leaves "hello w"
    CHECK(s.findLast('z') == -1);
}

TEST_CASE("findLast(substring)") {
    TString<char> s("abcabcabc");

    CHECK(s.findLast("abc") == 6);
    CHECK(s.findLast("bc") == 7);
    CHECK(s.findLast("xyz") == -1);
}

TEST_CASE("find(wchar_t)/findLast(wchar_t) return element indices, not byte offsets") {
    // Regression test: TStringFunctions<T>::find()/findLast() (which TString<T>::find()/
    // findLast() delegate the single-character search to) used to compute the raw
    // intptr_t byte-address difference between the found pointer and the string's start,
    // instead of a plain pointer subtraction -- these only coincide when sizeof(T) == 1, so
    // TString<wchar_t> (sizeof(wchar_t) == 2 on this platform) silently returned offsets
    // roughly double what they should have been.
    TString<wchar_t> s(L"hello world");

    CHECK(s.find(L'o') == 4);
    CHECK(s.find(L'o', 5) == 7);
    CHECK(s.find(L'z') == -1);

    CHECK(s.findLast(L'o') == 7);
    CHECK(s.findLast(L'o', 4) == 4);
    CHECK(s.findLast(L'z') == -1);
}

TEST_CASE("subString(start, length) and subString(start)") {
    TString<char> s("hello world");

    TString<char> a = s.subString(6, 5);
    CHECK(a.size() == 5);
    CHECK(std::memcmp(a.toPtr(), "world", 5) == 0);

    TString<char> b = s.subString(6);
    CHECK(b.size() == 5);
    CHECK(std::memcmp(b.toPtr(), "world", 5) == 0);

    // Length exceeding what's available is clamped, not an error.
    TString<char> c = s.subString(6, 1000);
    CHECK(c.size() == 5);

    // Out-of-range start returns an empty string.
    TString<char> d = s.subString(100);
    CHECK(d.empty());
}

TEST_CASE("trim removes leading/trailing whitespace only") {
    TString<char> s("   hello world   ");

    TString<char> trimmed = s.trim();
    CHECK(trimmed.size() == 11);
    CHECK(std::memcmp(trimmed.toPtr(), "hello world", 11) == 0);

    // start ends up == _size and end stays at _size-1, so end-start+1 wraps (unsigned) to
    // exactly 0 -- well-defined, not UB, and subString(start>=size, ...) returns empty on top.
    TString<char> allSpace("   ");
    CHECK(allSpace.trim().empty());
}

TEST_CASE("toLower / toUpper leave the original unchanged") {
    TString<char> s("Hello World 123");

    TString<char> lower = s.toLower();
    CHECK(std::memcmp(lower.toPtr(), "hello world 123", lower.size()) == 0);

    TString<char> upper = s.toUpper();
    CHECK(std::memcmp(upper.toPtr(), "HELLO WORLD 123", upper.size()) == 0);

    // Originals are untouched.
    CHECK(std::memcmp(s.toPtr(), "Hello World 123", s.size()) == 0);
}

TEST_CASE("reverse mutates in place") {
    TString<char> s("hello");

    s.reverse();
    CHECK(s.size() == 5);
    CHECK(std::memcmp(s.toPtr(), "olleh", 5) == 0);

    // Odd vs even length.
    TString<char> even("abcd");
    even.reverse();
    CHECK(std::memcmp(even.toPtr(), "dcba", 4) == 0);

    TString<char> empty;
    empty.reverse(); // must not crash
    CHECK(empty.empty());
}

TEST_CASE("toSpan reflects the current content") {
    TString<char> s("hello");

    SByteSpan mutableSpan = s.toSpan().reinterpret<uint8_t>();
    CHECK(mutableSpan.size == 5);

    const TString<char>& constRef = s;
    auto readOnly = constRef.toSpan();
    CHECK(readOnly.size == 5);
    CHECK(std::memcmp(readOnly.data, "hello", 5) == 0);
}

TEST_CASE("works for a non-char character type (wchar_t)") {
    TString<wchar_t> s(L"hi");

    CHECK(s.size() == 2);
    CHECK(s.toPtr()[0] == L'h');
    CHECK(s.toPtr()[1] == L'i');

    s.append(L'!');
    CHECK(s.size() == 3);

    TString<wchar_t> upper = s.toUpper();
    CHECK(upper.toPtr()[0] == L'H');
    CHECK(upper.toPtr()[1] == L'I');

    upper.reverse();
    CHECK(upper.toPtr()[0] == L'!');
}

TEST_CASE("operator[] provides indexed read access") {
    TString<char> s("hello");

    CHECK(s[0] == 'h');
    CHECK(s[4] == 'o');
}

TEST_CASE("compare(TString) orders by content, then by length") {
    CHECK(TString<char>("abc").compare(TString<char>("abc")) == 0);
    CHECK(TString<char>().compare(TString<char>()) == 0); // both empty

    CHECK(TString<char>("abc").compare(TString<char>("abd")) < 0);
    CHECK(TString<char>("abd").compare(TString<char>("abc")) > 0);

    // Same prefix, different length: the shorter one sorts first.
    CHECK(TString<char>("ab").compare(TString<char>("abc")) < 0);
    CHECK(TString<char>("abc").compare(TString<char>("ab")) > 0);

    // Empty vs non-empty, both directions.
    CHECK(TString<char>().compare(TString<char>("a")) < 0);
    CHECK(TString<char>("a").compare(TString<char>()) > 0);
}

TEST_CASE("operator== / operator!= for TString") {
    TString<char> a("hello");
    TString<char> b("hello");
    TString<char> c("world");

    CHECK(a == b);
    CHECK_FALSE(a != b);
    CHECK(a != c);
    CHECK_FALSE(a == c);
    CHECK(TString<char>() == TString<char>());
}

TEST_CASE("compare(const char*) against an equal literal reports equal") {
    // Regression test: compare(data, limit) used to treat the default limit (size_t(-1)) as if
    // it were data's actual length for the final length tie-break, so a TString equal to a
    // same-content C string compared as "less than" instead of equal.
    TString<char> s("hello");

    CHECK(s.compare("hello") == 0);
    CHECK(s == TString<char>("hello")); // sanity check via the TString overload too
}

TEST_CASE("compare(const char*) orders by content, then by length") {
    TString<char> s("hello");

    CHECK(s.compare("hello") == 0);
    CHECK(s.compare("hellp") < 0);   // differs in the last char
    CHECK(s.compare("hellz") < 0);
    CHECK(s.compare("hell") > 0);    // s is longer, same prefix
    CHECK(s.compare("helloo") < 0);  // s is shorter, same prefix

    CHECK(TString<char>().compare("") == 0);
    CHECK(TString<char>().compare("a") < 0);
    CHECK(s.compare("") > 0);
    CHECK(s.compare(nullptr) > 0);
    CHECK(TString<char>().compare(nullptr) == 0);
}

TEST_CASE("compare(const char*, limit) only considers the first limit characters") {
    TString<char> s("hello world");

    // "hello" == "hello w..." when compared over just the first 5 characters of data,
    // but s itself is longer than 5, so unlimited comparison is NOT equal.
    CHECK(s.compare("hello", 5) > 0);   // s (11 chars) is longer than "hello" (5 chars, unbounded)
    CHECK(s.compare("hello world and more", 11) == 0); // only the first 11 chars of data considered, matches s exactly
    CHECK(s.compare("hello world and more") < 0); // unbounded: data is longer than s
}

TEST_CASE("compareIgnoreCase(TString) orders by content ignoring ASCII case, then by length") {
    CHECK(TString<char>("ABC").compareIgnoreCase(TString<char>("abc")) == 0);
    CHECK(TString<char>("Hello").compareIgnoreCase(TString<char>("HELLO")) == 0);
    CHECK(TString<char>().compareIgnoreCase(TString<char>()) == 0);

    CHECK(TString<char>("abc").compareIgnoreCase(TString<char>("ABD")) < 0);
    CHECK(TString<char>("ABD").compareIgnoreCase(TString<char>("abc")) > 0);

    // Still case-sensitive-shaped in the sense that a plain compare() of the same two strings
    // would NOT be equal -- compareIgnoreCase() must actually differ from compare() here.
    TString<char> upper("ABC");
    TString<char> lower("abc");
    CHECK(upper.compare(lower) != 0);
    CHECK(upper.compareIgnoreCase(lower) == 0);

    CHECK(TString<char>("ab").compareIgnoreCase(TString<char>("ABC")) < 0);
    CHECK(TString<char>().compareIgnoreCase(TString<char>("a")) < 0);
}

TEST_CASE("compareIgnoreCase(const char*, limit) mirrors compare(const char*, limit)'s rules") {
    TString<char> s("Hello World");

    CHECK(s.compareIgnoreCase("HELLO WORLD") == 0);
    CHECK(s.compareIgnoreCase("hello", 5) > 0);          // s is longer than the 5-char comparand
    CHECK(s.compareIgnoreCase("HELLO WORLD AND MORE", 11) == 0);
    CHECK(s.compareIgnoreCase("HELLQ WORLD") < 0);

    CHECK(TString<char>().compareIgnoreCase("") == 0);
    CHECK(TString<char>().compareIgnoreCase(nullptr) == 0);
    CHECK(s.compareIgnoreCase(nullptr) > 0);
}

TEST_CASE("operator+= appends a TString or a C string in place") {
    TString<char> s("foo");

    s += TString<char>("bar");
    CHECK(s.size() == 6);
    CHECK(std::memcmp(s.toPtr(), "foobar", 6) == 0);

    s += "baz";
    CHECK(s.size() == 9);
    CHECK(std::memcmp(s.toPtr(), "foobarbaz", 9) == 0);
}

TEST_CASE("convert<T>() to the same character type is a plain copy") {
    TString<char> s("hello");
    TString<char> copy = s.convertTo<char>();

    CHECK(copy.size() == 5);
    CHECK(std::memcmp(copy.toPtr(), "hello", 5) == 0);
    CHECK(copy.toPtr() != s.toPtr()); // an independent copy, not aliasing the original

    TString<wchar_t> ws(L"hello");
    TString<wchar_t> wcopy = ws.convertTo<wchar_t>();
    CHECK(wcopy.size() == 5);
    CHECK(std::memcmp(wcopy.toPtr(), L"hello", 5 * sizeof(wchar_t)) == 0);
}

TEST_CASE("convert<T>() on an empty TString returns an empty TString") {
    TString<char> empty;
    TString<wchar_t> converted = empty.convertTo<wchar_t>();
    CHECK(converted.empty());
}

TEST_CASE("convert<T>() round-trips plain ASCII between char and wchar_t") {
    // Scoped to plain ASCII: mbsrtowcs/wcsrtombs are locale-dependent, and ASCII round-trips
    // correctly under the default "C" locale on every platform, unlike arbitrary multibyte text.
    TString<char> original("Hello, World! 123");

    TString<wchar_t> wide = original.convertTo<wchar_t>();
    REQUIRE(wide.size() == original.size());
    for (size_t i = 0; i < original.size(); ++i) {
        CHECK(wide[i] == static_cast<wchar_t>(original[i]));
    }

    TString<char> backToNarrow = wide.convertTo<char>();
    REQUIRE(backToNarrow.size() == original.size());
    CHECK(std::memcmp(backToNarrow.toPtr(), original.toPtr(), original.size()) == 0);
}

TEST_CASE("the converting constructor (not just convertTo()) doesn't read uninitialized state") {
    // Regression test: TString<T>::TString(const TString<U>&) had no member-initializer list,
    // leaving _data/_size/_capacity indeterminate before append() read them inside its body --
    // this only ever manifested through this constructor specifically (convertTo() itself, used
    // internally by append(), was and is fine), showing up as a bad_array_new_length exception
    // from a garbage size feeding resize()/reserve() -- but could just as easily have silently
    // corrupted memory instead, since it's undefined behavior either way.
    TString<char> narrow("hello");
    TString<wchar_t> viaConvertingCtor(narrow);
    CHECK(viaConvertingCtor == TString<wchar_t>(L"hello"));

    TString<wchar_t> wide(L"world");
    TString<char> backToNarrow(wide);
    CHECK(backToNarrow == TString<char>("world"));
}

TEST_CASE("convert<T>() round-trips Korean, Japanese, and accented Latin text under a UTF-8 locale") {
    LocaleGuard locale(".UTF8");
    if (!locale.active) {
        MESSAGE("UTF-8 locale (\".UTF8\") not available on this platform/CRT; skipping");
        return;
    }

    // Codepoints as plain hex integers, not \u string escapes -- this file must stay pure ASCII
    // on disk (see coding-conventions.md), and \u escapes risk being decoded into raw UTF-8
    // bytes before they ever reach the compiler. Each array is the wchar_t ground truth; the
    // UTF-8 bytes are produced by convert<char>() itself and checked by converting back.
    const wchar_t korean[] = { 0xC548, 0xB155 };                        // Korean "an-nyeong" (informal "hi")
    const wchar_t japanese[] = { 0x3053, 0x3093, 0x306B, 0x3061, 0x306F }; // Japanese hiragana "konnichiwa"
    const wchar_t latin[] = { 0x00E0, 0x00E9, 0x00EE, 0x00F5, 0x00FC };  // accented Latin vowels

    struct Case { const char* name; const wchar_t* wide; size_t count; };
    const Case cases[] = {
        { "Korean", korean, sizeof(korean) / sizeof(wchar_t) },
        { "Japanese", japanese, sizeof(japanese) / sizeof(wchar_t) },
        { "Latin", latin, sizeof(latin) / sizeof(wchar_t) },
    };

    for (const auto& c : cases) {
        CAPTURE(c.name);

        TString<wchar_t> original(c.wide, c.count);
        TString<char> narrow = original.convertTo<char>();

        // Every codepoint here needs more than 1 UTF-8 byte, so the byte count must exceed
        // the character count.
        CHECK(narrow.size() > original.size());

        TString<wchar_t> roundTripped = narrow.convertTo<wchar_t>();
        REQUIRE(roundTripped.size() == c.count);
        for (size_t i = 0; i < c.count; ++i) {
            CHECK(roundTripped[i] == c.wide[i]);
        }
    }
}

TEST_CASE("convert<T>() round-trips a single string mixing Korean, Japanese, Latin, and ASCII") {
    LocaleGuard locale(".UTF8");
    if (!locale.active) {
        MESSAGE("UTF-8 locale (\".UTF8\") not available on this platform/CRT; skipping");
        return;
    }

    // "Seoul(<Hangul>)-Tokyo(<Kanji>) caf<e-acute>" -- ASCII, Hangul, a CJK ideograph compound,
    // and accented Latin in one string, built from hex codepoints for the same reason as above.
    const wchar_t mixed[] = {
        'S', 'e', 'o', 'u', 'l', '(', 0xC11C, 0xC6B8, ')', '-',
        'T', 'o', 'k', 'y', 'o', '(', 0x6771, 0x4EAC, ')', ' ',
        'c', 'a', 'f', 0x00E9
    };
    const size_t mixedLen = sizeof(mixed) / sizeof(wchar_t);

    TString<wchar_t> original(mixed, mixedLen);
    TString<char> narrow = original.convertTo<char>();
    CHECK(narrow.size() > original.size());

    TString<wchar_t> roundTripped = narrow.convertTo<wchar_t>();
    REQUIRE(roundTripped.size() == mixedLen);
    for (size_t i = 0; i < mixedLen; ++i) {
        CHECK(roundTripped[i] == mixed[i]);
    }
}

// ---------------------------------------------------------------------------
// TUtf8Encoding / IStringEncoding
// ---------------------------------------------------------------------------

TEST_CASE("TUtf8Encoding<wchar_t> round-trips plain ASCII (locale-independent)") {
    IStringEncoding<wchar_t>& enc = TUtf8Encoding<wchar_t>::get();

    const wchar_t text[] = L"Hello, World! 123";
    const size_t len = std::wcslen(text);
    TReadOnlySpan<wchar_t> src(text, len);

    size_t needed = enc.measure(src);
    REQUIRE(needed == len); // ASCII: exactly 1 UTF-8 byte per character.

    uint8_t bytes[64];
    SByteSpan dst(bytes, sizeof(bytes));
    size_t written = enc.encodeTo(dst, src);
    REQUIRE(written == needed);

    wchar_t back[64];
    TSpan<wchar_t> backSpan(back, 64);
    size_t decoded = enc.decodeFrom(backSpan, SReadOnlyByteSpan(bytes, written));
    REQUIRE(decoded == len);
    CHECK(std::memcmp(back, text, len * sizeof(wchar_t)) == 0);
}

TEST_CASE("TUtf8Encoding<wchar_t> round-trips Korean, Japanese, and accented Latin text") {
    // Locale-independent (uses std::codecvt_utf8<wchar_t> directly), so no LocaleGuard needed --
    // codepoints as hex integers for the same file-encoding-safety reason as the convert<T>() tests above.
    IStringEncoding<wchar_t>& enc = TUtf8Encoding<wchar_t>::get();

    const wchar_t korean[] = { 0xC548, 0xB155 };
    const wchar_t japanese[] = { 0x3053, 0x3093, 0x306B, 0x3061, 0x306F };
    const wchar_t latin[] = { 0x00E0, 0x00E9, 0x00EE, 0x00F5, 0x00FC };

    struct Case { const char* name; const wchar_t* wide; size_t count; size_t expectedBytes; };
    const Case cases[] = {
        { "Korean", korean, 2, 6 },     // 3 UTF-8 bytes per Hangul syllable
        { "Japanese", japanese, 5, 15 }, // 3 UTF-8 bytes per kana
        { "Latin", latin, 5, 10 },       // 2 UTF-8 bytes per accented letter
    };

    for (const auto& c : cases) {
        CAPTURE(c.name);

        TReadOnlySpan<wchar_t> src(c.wide, c.count);
        size_t needed = enc.measure(src);
        CHECK(needed == c.expectedBytes);

        uint8_t bytes[64];
        SByteSpan dst(bytes, sizeof(bytes));
        size_t written = enc.encodeTo(dst, src);
        REQUIRE(written == needed);

        wchar_t back[64];
        TSpan<wchar_t> backSpan(back, 64);
        size_t decoded = enc.decodeFrom(backSpan, SReadOnlyByteSpan(bytes, written));
        REQUIRE(decoded == c.count);
        for (size_t i = 0; i < c.count; ++i) {
            CHECK(back[i] == c.wide[i]);
        }
    }
}

TEST_CASE("TUtf8Encoding<char> round-trips plain ASCII") {
    IStringEncoding<char>& enc = TUtf8Encoding<char>::get();

    const char* text = "Hello, World! 123";
    const size_t len = std::strlen(text);
    TReadOnlySpan<char> src(text, len);

    size_t needed = enc.measure(src);
    REQUIRE(needed == len); // ASCII maps 1:1 regardless of the active locale.

    uint8_t bytes[64];
    SByteSpan dst(bytes, sizeof(bytes));
    size_t written = enc.encodeTo(dst, src);
    REQUIRE(written == needed);
    CHECK(std::memcmp(bytes, text, len) == 0);

    char back[64];
    TSpan<char> backSpan(back, 64);
    size_t decoded = enc.decodeFrom(backSpan, SReadOnlyByteSpan(bytes, written));
    REQUIRE(decoded == len);
    CHECK(std::memcmp(back, text, len) == 0);
}

TEST_CASE("TUtf8Encoding<char> round-trips Korean, Japanese, and accented Latin text under a UTF-8 locale") {
    // char is treated as native-locale text (see Utf8EncodingForChar's comment in utf8.cpp), so
    // this needs the same UTF-8 locale as the mbsrtowcs-based tests above. Ground-truth UTF-8
    // bytes come from the already-verified, locale-independent wchar_t-side encoder, not from
    // a hand-written literal, sidestepping the same file-encoding hazard noted above.
    LocaleGuard locale(".UTF8");
    if (!locale.active) {
        MESSAGE("UTF-8 locale (\".UTF8\") not available on this platform/CRT; skipping");
        return;
    }

    IStringEncoding<wchar_t>& wideEnc = TUtf8Encoding<wchar_t>::get();
    IStringEncoding<char>& charEnc = TUtf8Encoding<char>::get();

    const wchar_t korean[] = { 0xC548, 0xB155 };
    const wchar_t japanese[] = { 0x3053, 0x3093, 0x306B, 0x3061, 0x306F };
    const wchar_t latin[] = { 0x00E0, 0x00E9, 0x00EE, 0x00F5, 0x00FC };

    struct Case { const char* name; const wchar_t* wide; size_t count; };
    const Case cases[] = {
        { "Korean", korean, 2 },
        { "Japanese", japanese, 5 },
        { "Latin", latin, 5 },
    };

    for (const auto& c : cases) {
        CAPTURE(c.name);

        TReadOnlySpan<wchar_t> wideSrc(c.wide, c.count);
        uint8_t utf8Bytes[64];
        SByteSpan utf8Dst(utf8Bytes, sizeof(utf8Bytes));
        size_t utf8Len = wideEnc.encodeTo(utf8Dst, wideSrc);
        REQUIRE(utf8Len > 0);

        // Decode those UTF-8 bytes into "native" char -- under a UTF-8 locale, native IS UTF-8,
        // so this should reproduce the same bytes exactly (not some other native encoding).
        char native[64] = {};
        TSpan<char> nativeSpan(native, sizeof(native) - 1); // leave native[nativeLen] as a NUL terminator
        size_t nativeLen = charEnc.decodeFrom(nativeSpan, SReadOnlyByteSpan(utf8Bytes, utf8Len));
        REQUIRE(nativeLen == utf8Len);
        CHECK(std::memcmp(native, utf8Bytes, utf8Len) == 0);

        // And back to UTF-8 bytes again; must reproduce the original bytes exactly. Utf8EncodingForChar
        // requires its input to be null-terminated (see its class comment), same as mbsrtowcs().
        native[nativeLen] = '\0';
        uint8_t roundTripped[64];
        SByteSpan roundTrippedDst(roundTripped, sizeof(roundTripped));
        size_t roundTrippedLen = charEnc.encodeTo(roundTrippedDst, TReadOnlySpan<char>(native, nativeLen));
        REQUIRE(roundTrippedLen == utf8Len);
        CHECK(std::memcmp(roundTripped, utf8Bytes, utf8Len) == 0);
    }
}

TEST_CASE("TUtf8Encoding handles empty input without crashing") {
    IStringEncoding<char>& charEnc = TUtf8Encoding<char>::get();
    IStringEncoding<wchar_t>& wideEnc = TUtf8Encoding<wchar_t>::get();

    CHECK(charEnc.measure(TReadOnlySpan<char>(nullptr, 0)) == 0);
    CHECK(wideEnc.measure(TReadOnlySpan<wchar_t>(nullptr, 0)) == 0);

    uint8_t buf[8];
    SByteSpan dst(buf, sizeof(buf));
    CHECK(charEnc.encodeTo(dst, TReadOnlySpan<char>(nullptr, 0)) == 0);
    CHECK(wideEnc.encodeTo(dst, TReadOnlySpan<wchar_t>(nullptr, 0)) == 0);

    char cback[8];
    TSpan<char> cdst(cback, 8);
    CHECK(charEnc.decodeFrom(cdst, SReadOnlyByteSpan(nullptr, 0)) == 0);

    wchar_t wback[8];
    TSpan<wchar_t> wdst(wback, 8);
    CHECK(wideEnc.decodeFrom(wdst, SReadOnlyByteSpan(nullptr, 0)) == 0);
}

TEST_CASE("TUtf8Encoding<wchar_t>::encodeTo clamps to the destination size instead of overflowing") {
    IStringEncoding<wchar_t>& enc = TUtf8Encoding<wchar_t>::get();

    const wchar_t text[] = L"Hello"; // 5 bytes of UTF-8
    TReadOnlySpan<wchar_t> src(text, 5);

    uint8_t small[3];
    SByteSpan dst(small, 3);
    size_t written = enc.encodeTo(dst, src);
    CHECK(written <= 3);
}

// ---------------------------------------------------------------------------
// TAsciiEncoding / IStringEncoding
// ---------------------------------------------------------------------------

TEST_CASE("TAsciiEncoding<char> round-trips plain ASCII") {
    IStringEncoding<char>& enc = TAsciiEncoding<char>::get();

    const char* text = "Hello, World! 123";
    const size_t len = std::strlen(text);
    TReadOnlySpan<char> src(text, len);

    CHECK(enc.measure(src) == len); // always 1:1, character count == byte count

    uint8_t bytes[64];
    SByteSpan dst(bytes, sizeof(bytes));
    size_t written = enc.encodeTo(dst, src);
    REQUIRE(written == len);
    CHECK(std::memcmp(bytes, text, len) == 0);

    char back[64];
    TSpan<char> backSpan(back, 64);
    size_t decoded = enc.decodeFrom(backSpan, SReadOnlyByteSpan(bytes, written));
    REQUIRE(decoded == len);
    CHECK(std::memcmp(back, text, len) == 0);
}

TEST_CASE("TAsciiEncoding<wchar_t> round-trips plain ASCII") {
    IStringEncoding<wchar_t>& enc = TAsciiEncoding<wchar_t>::get();

    const wchar_t text[] = L"Hello, World! 123";
    const size_t len = std::wcslen(text);
    TReadOnlySpan<wchar_t> src(text, len);

    CHECK(enc.measure(src) == len);

    uint8_t bytes[64];
    SByteSpan dst(bytes, sizeof(bytes));
    size_t written = enc.encodeTo(dst, src);
    REQUIRE(written == len);
    for (size_t i = 0; i < len; ++i) {
        CHECK(bytes[i] == static_cast<uint8_t>(text[i]));
    }

    wchar_t back[64];
    TSpan<wchar_t> backSpan(back, 64);
    size_t decoded = enc.decodeFrom(backSpan, SReadOnlyByteSpan(bytes, written));
    REQUIRE(decoded == len);
    CHECK(std::memcmp(back, text, len * sizeof(wchar_t)) == 0);
}

TEST_CASE("TAsciiEncoding<wchar_t>::encodeTo sanitizes non-ASCII codepoints to a space, not UB") {
    // Regression test: encodeTo() used to call isascii() directly on a wchar_t value. isascii()
    // (like every <ctype.h> classification function) is only defined for arguments representable
    // as unsigned char or EOF -- undefined behavior for a wchar_t like Korean/Japanese codepoints,
    // and a real out-of-bounds risk on CRT implementations that index a lookup table by the raw
    // argument. Using codepoints well outside the unsigned-char range specifically to exercise that.
    IStringEncoding<wchar_t>& enc = TAsciiEncoding<wchar_t>::get();

    const wchar_t korean[] = { 'A', 0xC548, 'B', 0xB155, 'C' };      // Korean "an-nyeong" interleaved with ASCII
    const wchar_t japanese[] = { 'X', 0x3053, 0x3093, 'Y' };          // Japanese hiragana "ko" "n"
    const wchar_t latin[] = { 'Z', 0x00E9, 0x00FC };                  // e-acute, u-diaeresis (< 256, still non-ASCII)

    struct Case { const char* name; const wchar_t* wide; size_t count; };
    const Case cases[] = {
        { "Korean", korean, 5 },
        { "Japanese", japanese, 4 },
        { "Latin", latin, 3 },
    };

    for (const auto& c : cases) {
        CAPTURE(c.name);

        TReadOnlySpan<wchar_t> src(c.wide, c.count);
        CHECK(enc.measure(src) == c.count);

        uint8_t bytes[16];
        SByteSpan dst(bytes, sizeof(bytes));
        size_t written = enc.encodeTo(dst, src);
        REQUIRE(written == c.count);

        for (size_t i = 0; i < c.count; ++i) {
            bool asciiExpected = static_cast<unsigned long>(c.wide[i]) <= 127;
            if (asciiExpected) {
                CHECK(bytes[i] == static_cast<uint8_t>(c.wide[i]));
            } else {
                CHECK(bytes[i] == ' '); // sanitized, not garbage or a crash
            }
        }
    }
}

TEST_CASE("TAsciiEncoding<char>::encodeTo sanitizes non-ASCII bytes to a space") {
    IStringEncoding<char>& enc = TAsciiEncoding<char>::get();

    const char data[] = { 'A', char(0x80), 'B', char(0xFF), 'C' };
    TReadOnlySpan<char> src(data, sizeof(data));

    uint8_t bytes[16];
    SByteSpan dst(bytes, sizeof(bytes));
    size_t written = enc.encodeTo(dst, src);
    REQUIRE(written == sizeof(data));

    CHECK(bytes[0] == 'A');
    CHECK(bytes[1] == ' '); // 0x80 sanitized
    CHECK(bytes[2] == 'B');
    CHECK(bytes[3] == ' '); // 0xFF sanitized
    CHECK(bytes[4] == 'C');
}

TEST_CASE("TAsciiEncoding<wchar_t>::decodeFrom sanitizes non-ASCII bytes to a space") {
    IStringEncoding<wchar_t>& enc = TAsciiEncoding<wchar_t>::get();

    const uint8_t data[] = { 'A', 0x80, 'B', 0xFF, 'C' };
    SReadOnlyByteSpan src(data, sizeof(data));

    wchar_t back[16];
    TSpan<wchar_t> dst(back, 16);
    size_t decoded = enc.decodeFrom(dst, src);
    REQUIRE(decoded == sizeof(data));

    CHECK(back[0] == L'A');
    CHECK(back[1] == L' ');
    CHECK(back[2] == L'B');
    CHECK(back[3] == L' ');
    CHECK(back[4] == L'C');
}

TEST_CASE("TAsciiEncoding handles empty input without crashing") {
    IStringEncoding<char>& charEnc = TAsciiEncoding<char>::get();
    IStringEncoding<wchar_t>& wideEnc = TAsciiEncoding<wchar_t>::get();

    CHECK(charEnc.measure(TReadOnlySpan<char>(nullptr, 0)) == 0);
    CHECK(wideEnc.measure(TReadOnlySpan<wchar_t>(nullptr, 0)) == 0);

    uint8_t buf[8];
    SByteSpan dst(buf, sizeof(buf));
    CHECK(charEnc.encodeTo(dst, TReadOnlySpan<char>(nullptr, 0)) == 0);
    CHECK(wideEnc.encodeTo(dst, TReadOnlySpan<wchar_t>(nullptr, 0)) == 0);

    char cback[8];
    TSpan<char> cdst(cback, 8);
    CHECK(charEnc.decodeFrom(cdst, SReadOnlyByteSpan(nullptr, 0)) == 0);

    wchar_t wback[8];
    TSpan<wchar_t> wdst(wback, 8);
    CHECK(wideEnc.decodeFrom(wdst, SReadOnlyByteSpan(nullptr, 0)) == 0);
}

TEST_CASE("TAsciiEncoding::encodeTo clamps to the destination size instead of overflowing") {
    IStringEncoding<char>& enc = TAsciiEncoding<char>::get();

    const char* text = "Hello";
    TReadOnlySpan<char> src(text, 5);

    uint8_t small[3];
    SByteSpan dst(small, 3);
    size_t written = enc.encodeTo(dst, src);
    CHECK(written == 3);
    CHECK(std::memcmp(small, text, 3) == 0);
}
