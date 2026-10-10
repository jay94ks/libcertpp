#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/name.hpp>
#include <clocale>
#include <cwchar>
#include <cstring>
#include <string>
#include <utility>

using namespace certpp;

namespace {
    /* Puts the process into a UTF-8 locale and restores it on scope exit.
     *
     * --> TString's narrow <-> wide leg goes through mbsrtowcs()/wcsrtombs(), which read the
     * *process* locale. Under the C or POSIX locale -- the default for a bare Linux process, and
     * what WSL runs -- a UTF-8 lead byte is not a valid multibyte sequence and the conversion
     * fails outright. Windows begins in a UTF-8-capable locale, which is why these cases only
     * ever failed on the GCC side. Each test binary defines this for itself rather than sharing
     * one, so no test file depends on another's include order. */
    struct ScopedUtf8Locale {
        std::string _previous;

        ScopedUtf8Locale() {
            const char* current = std::setlocale(LC_CTYPE, nullptr);
            if (current) {
                _previous = current;
            }

            // --> Only intervene when the process locale cannot actually represent the bytes
            // these tests use. Windows does not accept the "C.UTF-8" *name* but its default locale
            // already handles them, so replacing it unconditionally broke tests that passed
            // before: setlocale returning null is not the same as the locale being inadequate.
            // Probe instead of assuming -- and never fall back to "C", which cannot represent
            // 0xC3 at all and is what caused the original failure.
            const bool alreadyUsable = current != nullptr
                && std::mbrtowc(nullptr, "\xC3", 1, nullptr) != static_cast<size_t>(-1);

            if (!alreadyUsable) {
                std::setlocale(LC_CTYPE, "C.UTF-8");
                if (std::mbrtowc(nullptr, "\xC3", 1, nullptr) == static_cast<size_t>(-1)) {
                    std::setlocale(LC_CTYPE, "en_US.UTF-8");
                }
            }
        }

        ~ScopedUtf8Locale() {
            if (!_previous.empty()) {
                std::setlocale(LC_CTYPE, _previous.c_str());
            }
        }
    };
}

TEST_CASE("CName default construction is empty") {
    CName name;

    CHECK(name.empty());
    CHECK_FALSE(bool(name));
    CHECK(!name);
    CHECK(name.type() == ENAME_NONE);
    CHECK(name.toSpan().empty());
    CHECK(name.size() == 0);
}

TEST_CASE("CName construction from type + ASCII string") {
    CName name(ENAME_CN, "Test");

    REQUIRE_FALSE(name.empty());
    CHECK(bool(name));
    CHECK(name.type() == ENAME_CN);
    CHECK(name.size() == 4);

    TReadOnlySpan<char> span = name.toSpan();
    REQUIRE(span.size == 4);
    CHECK(std::memcmp(span.data, "Test", 4) == 0);

    CString str;
    name.toString(str);
    CHECK(str == CString("Test"));
    CHECK(name.toString<char>() == CString("Test"));
}

TEST_CASE("CName construction rejecting/degenerating to empty") {
    SUBCASE("ENAME_NONE explicitly requested stays empty regardless of str") {
        CName name(ENAME_NONE, "Test");
        CHECK(name.empty());
        CHECK(name.type() == ENAME_NONE);
    }

    SUBCASE("null string") {
        CName name(ENAME_CN, nullptr);
        CHECK(name.empty());
    }

    SUBCASE("zero limit") {
        CName name(ENAME_CN, "Test", 0);
        CHECK(name.empty());
    }

    SUBCASE("empty string (immediate NUL)") {
        CName name(ENAME_CN, "");
        CHECK(name.empty());
    }
}

TEST_CASE("CName construction stops at an embedded NUL within limit") {
    const char data[] = { 'a', 'b', '\0', 'c' };
    CName name(ENAME_OU, data, sizeof(data));

    REQUIRE_FALSE(name.empty());
    CHECK(name.type() == ENAME_OU);
    CString str;
    name.toString(str);
    CHECK(str == CString("ab"));
}

TEST_CASE("CName construction with a limit shorter than the string truncates") {
    CName name(ENAME_O, "HelloWorld", 5);

    REQUIRE_FALSE(name.empty());
    CString str;
    name.toString(str);
    CHECK(str == CString("Hello"));
}

TEST_CASE("CName non-ASCII bytes are escaped internally; toString() controls whether that's visible") {
    // 'a', a non-ASCII byte (0xC3), 'b' -- built from a hex literal rather than a literal
    // non-ASCII source byte, per this project's pure-ASCII-source convention.
    const char data[] = { 'a', static_cast<char>(0xC3), 'b' };
    CName name(ENAME_L, data, sizeof(data));

    REQUIRE_FALSE(name.empty());
    CHECK(name.type() == ENAME_L); // the escape flag must not leak into type()

    // Internally, the non-ASCII byte is stored with a leading backslash escape marker.
    TReadOnlySpan<char> span = name.toSpan();
    const char expectedEscaped[] = { 'a', '\\', static_cast<char>(0xC3), 'b' };
    REQUIRE(span.size == sizeof(expectedEscaped));
    CHECK(std::memcmp(span.data, expectedEscaped, sizeof(expectedEscaped)) == 0);

    // toString(out, false) (the default) reverses the escaping, back to the original bytes.
    CString unescaped;
    name.toString(unescaped, false);
    REQUIRE(unescaped.size() == sizeof(data));
    CHECK(std::memcmp(unescaped.toPtr(), data, sizeof(data)) == 0);

    // toString(out, true) instead returns the raw internal (escaped) form.
    CString escaped;
    name.toString(escaped, true);
    REQUIRE(escaped.size() == sizeof(expectedEscaped));
    CHECK(std::memcmp(escaped.toPtr(), expectedEscaped, sizeof(expectedEscaped)) == 0);
}

TEST_CASE("CName toString(escaped) is a no-op distinction when nothing needed escaping") {
    CName name(ENAME_CN, "plain");

    CString unescaped, escaped;
    name.toString(unescaped, false);
    name.toString(escaped, true);

    CHECK(unescaped == CString("plain"));
    CHECK(escaped == CString("plain"));
}

TEST_CASE("CName multiple non-ASCII bytes are each escaped and each unescaped correctly") {
    // Regression test: toString()'s un-escaping loop used to `continue` on a backslash marker
    // without advancing past it, hanging forever on any escaped content. This exercises more
    // than one escape in the same name to make sure the fix's advancement is correct throughout.
    const char data[] = { static_cast<char>(0xC3), 'x', static_cast<char>(0xB6), 'y', static_cast<char>(0x80) };
    CName name(ENAME_ST, data, sizeof(data));

    REQUIRE_FALSE(name.empty());
    CString str;
    name.toString(str);
    REQUIRE(str.size() == sizeof(data));
    CHECK(std::memcmp(str.toPtr(), data, sizeof(data)) == 0);
}

TEST_CASE("CName toString(CWideString&, bool) matches the narrow form") {
    // --> UTF-8 process locale, for the reason spelled out in ScopedUtf8Locale in
    // tests/asn1/roundtrip.cpp: TString's narrow <-> wide leg is mbsrtowcs(), which reads the
    // process locale, and 0xC3 is not a valid multibyte sequence under the C locale that a bare
    // Linux process starts in.
    const ScopedUtf8Locale utf8;

    // --> ASCII, deliberately. This test compares the narrow and wide *forms* of the same value,
    // and that only has a portable answer when every byte is one character wide in every locale.
    // The original data was { 'a', 0xC3, 'b' }, which is ambiguous rather than merely
    // locale-dependent: 0xC3 is a UTF-8 lead byte and the 'b' after it is a valid continuation
    // byte, so a UTF-8 locale consumes both as one character while the C locale takes 0xC3 alone
    // and leaves 'b' separate. Measured on Windows, that spelled out as one wide character against
    // three narrow ones.
    //
    // Both readings are *correct* for their locale -- that is what "the process locale" in
    // TString's narrow <-> wide leg means, and hard-coding UTF-8 would change what a caller who
    // has chosen a locale expects. What cannot hold across toolchains is a fixed character count
    // over bytes whose interpretation is locale-defined, so the data is ASCII here and the
    // non-ASCII escaping is covered by the tests that assert the escape sequence byte for byte
    // rather than converting through the wide form.
    const char data[] = { 'a', 'b', 'c' };
    CName name(ENAME_L, data, sizeof(data));

    CWideString wide;
    name.toString(wide, false);
    CHECK(wide == name.toString<wchar_t>(false));

    CString narrow;
    name.toString(narrow, false);

    // Both representations must agree on length character-for-character.
    //
    // --> TString::size() counts characters, not bytes, for both element types -- verified against
    // a wide literal, which reports 3 for L"abc" even though wchar_t is 2 bytes on MSVC and 4 on
    // Linux. So the two size() values are directly comparable and the wchar_t size difference is
    // not a factor here at all.
    CHECK(wide.size() == narrow.size());
}

TEST_CASE("CName::key/label and the static keyOf/labelOf") {
    CName name(ENAME_CN, "hello");

    CHECK(std::strcmp(name.key(), "CN") == 0);
    CHECK(std::strcmp(name.label(), "Common Name") == 0);
    CHECK(std::strcmp(CName::keyOf(ENAME_CN), "CN") == 0);
    CHECK(std::strcmp(CName::labelOf(ENAME_CN), "Common Name") == 0);

    CHECK(std::strcmp(CName::keyOf(ENAME_C), "C") == 0);
    CHECK(std::strcmp(CName::labelOf(ENAME_OU), "Organizational Unit") == 0);

    // Out-of-range/ENAME_NONE types are rejected by the static lookups.
    CHECK(CName::keyOf(ENAME_NONE) == nullptr);
    CHECK(CName::labelOf(ENAME_NONE) == nullptr);
    CHECK(CName::keyOf(ENameType(ENAME_MAX)) == nullptr);
    CHECK(CName::labelOf(ENameType(100)) == nullptr);
}

TEST_CASE("CName::hash is stable for identical content and used by equals()") {
    CName a(ENAME_CN, "hello");
    CName b(ENAME_CN, "hello");
    CName c(ENAME_CN, "world");

    CHECK(a.hash() == b.hash());
    CHECK(a.hash() != c.hash());
}

TEST_CASE("CName copy construction/assignment makes an independent deep copy") {
    CName original(ENAME_CN, "hello");

    CName copy(original);
    REQUIRE(copy.type() == original.type());
    CHECK(copy == original);
    CHECK(copy.toSpan().data != original.toSpan().data);

    CName assigned;
    assigned = original;
    CHECK(assigned == original);
    CHECK(assigned.toSpan().data != original.toSpan().data);

    CName empty;
    CName copiedEmpty(empty);
    CHECK(copiedEmpty.empty());
}

TEST_CASE("CName copy construction/assignment of non-ASCII content does not re-escape it") {
    // Regression test: the copy constructor/assignment used to call reset(other.type(),
    // other._data, other._len) -- but other._data is already-escaped internal storage (it may
    // already contain backslash escape markers from a previous reset()/copy), and reset()'s
    // escaping logic doesn't know that, so it would prepend a *new* backslash ahead of every
    // already-escaped non-ASCII byte it found, corrupting the content a little more with each
    // successive copy. Exercised through two copies in a row (like a CName passing through a
    // std::map, e.g. CDistinguishedName::trySet() then tryGet()) so a single-escape bug that
    // only shows up on the second copy wouldn't be missed.
    const char data[] = { 'a', static_cast<char>(0xC3), 'b' };
    CName original(ENAME_CN, data, sizeof(data));

    CName copy1(original);
    CHECK(copy1 == original);
    CHECK(copy1.size() == original.size());

    CName copy2;
    copy2 = copy1;
    CHECK(copy2 == original);
    CHECK(copy2.size() == original.size());

    CString str;
    copy2.toString(str);
    REQUIRE(str.size() == sizeof(data));
    CHECK(std::memcmp(str.toPtr(), data, sizeof(data)) == 0);
}

TEST_CASE("CName move construction transfers ownership and empties the source") {
    CName original(ENAME_CN, "hello");
    const char* originalPtr = original.toSpan().data;

    CName moved(std::move(original));
    REQUIRE(moved.type() == ENAME_CN);
    CHECK(moved.toSpan().data == originalPtr);

    CString str;
    moved.toString(str);
    CHECK(str == CString("hello"));

    CHECK(original.empty());
}

TEST_CASE("CName move assignment swaps state with the source, rather than emptying it") {
    CName source(ENAME_CN, "hello");
    CName dest(ENAME_OU, "widgets");

    const char* sourcePtr = source.toSpan().data;
    const char* destPtr = dest.toSpan().data;

    dest = std::move(source);
    CHECK(dest.type() == ENAME_CN);
    CHECK(dest.toSpan().data == sourcePtr);

    CHECK(source.type() == ENAME_OU);
    CHECK(source.toSpan().data == destPtr);
}

TEST_CASE("CName equals / operator== / operator!=") {
    CName a(ENAME_CN, "hello");
    CName b(ENAME_CN, "hello");
    CName differentContent(ENAME_CN, "world");
    CName differentType(ENAME_OU, "hello");
    CName empty1, empty2;

    CHECK(a == b);
    CHECK(a.equals(b));
    CHECK_FALSE(a != b);

    CHECK(a != differentContent);
    CHECK(a != differentType);
    CHECK(empty1 == empty2);
}

TEST_CASE("CName compare orders by type first, then by content") {
    CName cn(ENAME_CN, "hello");
    CName ou(ENAME_OU, "hello");

    CHECK(cn.compare(ou) < 0); // ENAME_CN(1) < ENAME_OU(2), regardless of content
    CHECK(ou.compare(cn) > 0);

    CName a(ENAME_CN, "abc");
    CName b(ENAME_CN, "abd");
    CHECK(a.compare(b) < 0);
    CHECK(b.compare(a) > 0);

    CName shortStr(ENAME_CN, "ab");
    CName longStr(ENAME_CN, "abc");
    CHECK(shortStr.compare(longStr) < 0);
    CHECK(longStr.compare(shortStr) > 0);

    CName same1(ENAME_CN, "same");
    CName same2(ENAME_CN, "same");
    CHECK(same1.compare(same2) == 0);

    CName empty1, empty2;
    CHECK(empty1.compare(empty2) == 0);
}

TEST_CASE("CDistinguishedName default construction is empty") {
    CDistinguishedName dn;

    CHECK(dn.empty());
    CHECK_FALSE(bool(dn));
    CHECK(!dn);
    CHECK(dn.size() == 0);
    CHECK_FALSE(dn.has(ENAME_CN));

    CName out;
    CHECK_FALSE(dn.tryGet(ENAME_CN, out));

    TArray<ENameType> keys;
    dn.keys(keys);
    CHECK(keys.empty());
}

TEST_CASE("CDistinguishedName trySet / tryGet / has round-trip") {
    CDistinguishedName dn;

    REQUIRE(dn.trySet(CName(ENAME_CN, "example.com")));
    CHECK_FALSE(dn.empty());
    CHECK(dn.size() == 1);
    CHECK(dn.has(ENAME_CN));
    CHECK_FALSE(dn.has(ENAME_OU));

    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));
}

TEST_CASE("CDistinguishedName trySet without overwrite fails on an existing key; with overwrite succeeds") {
    CDistinguishedName dn;
    REQUIRE(dn.trySet(CName(ENAME_CN, "first")));

    CHECK_FALSE(dn.trySet(CName(ENAME_CN, "second"), false));
    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "first")); // unchanged

    REQUIRE(dn.trySet(CName(ENAME_CN, "second"), true));
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "second"));
}

TEST_CASE("CDistinguishedName::keys reports every component type present") {
    CDistinguishedName dn;
    REQUIRE(dn.trySet(CName(ENAME_CN, "a")));
    REQUIRE(dn.trySet(CName(ENAME_OU, "b")));
    REQUIRE(dn.trySet(CName(ENAME_C, "c")));

    TArray<ENameType> keys;
    dn.keys(keys);
    REQUIRE(keys.size() == 3);

    bool hasCn = false, hasOu = false, hasC = false;
    for (ENameType k : keys) {
        hasCn |= (k == ENAME_CN);
        hasOu |= (k == ENAME_OU);
        hasC |= (k == ENAME_C);
    }
    CHECK(hasCn);
    CHECK(hasOu);
    CHECK(hasC);
}

TEST_CASE("CDistinguishedName copy construction/assignment makes an independent deep copy") {
    CDistinguishedName original;
    REQUIRE(original.trySet(CName(ENAME_CN, "example.com")));

    CDistinguishedName copy(original);
    CHECK(copy == original);

    // Mutating the copy must not affect the original.
    REQUIRE(copy.trySet(CName(ENAME_OU, "engineering")));
    CHECK(copy != original);
    CHECK(original.size() == 1);

    CDistinguishedName assigned;
    assigned = original;
    CHECK(assigned == original);
}

TEST_CASE("CDistinguishedName move construction/assignment transfer content") {
    CDistinguishedName original;
    REQUIRE(original.trySet(CName(ENAME_CN, "example.com")));

    CDistinguishedName moved(std::move(original));
    CHECK(moved.size() == 1);
    CHECK(moved.has(ENAME_CN));

    CDistinguishedName dest;
    REQUIRE(dest.trySet(CName(ENAME_OU, "widgets")));

    dest = std::move(moved);
    CHECK(dest.has(ENAME_CN));
}

TEST_CASE("CDistinguishedName compare / operator== / operator!=") {
    CDistinguishedName a, b, differentContent, extraComponent, empty1, empty2;

    REQUIRE(a.trySet(CName(ENAME_CN, "hello")));
    REQUIRE(b.trySet(CName(ENAME_CN, "hello")));
    REQUIRE(differentContent.trySet(CName(ENAME_CN, "world")));

    REQUIRE(extraComponent.trySet(CName(ENAME_CN, "hello")));
    REQUIRE(extraComponent.trySet(CName(ENAME_OU, "engineering")));

    CHECK(a == b);
    CHECK(a.compare(b) == 0);

    CHECK(a != differentContent);
    CHECK(a.compare(differentContent) != 0);

    // a has only CN; extraComponent additionally has OU -- a is "missing" a component
    // extraComponent has, so a sorts before it.
    CHECK(a.compare(extraComponent) < 0);
    CHECK(extraComponent.compare(a) > 0);

    CHECK(empty1 == empty2);
    CHECK(empty1.compare(empty2) == 0);
}

TEST_CASE("CDistinguishedName::toString renders key=value pairs") {
    CDistinguishedName dn;
    REQUIRE(dn.trySet(CName(ENAME_CN, "example.com")));
    REQUIRE(dn.trySet(CName(ENAME_C, "US")));

    CString str;
    dn.toString(str);

    // Order follows std::map<ENameType,...>'s key ordering (ascending ENameType), so C (6)
    // comes after CN (1).
    CHECK(str == CString("CN=example.com, C=US"));
    CHECK(dn.toString<char>() == str);
}

TEST_CASE("CDistinguishedName::toString on an empty DN yields an empty string") {
    CDistinguishedName dn;
    CString str;
    dn.toString(str);
    CHECK(str.empty());
}

TEST_CASE("CDistinguishedName::tryParse(CString) parses a single component with no trailing comma") {
    // Regression test: the parser used to compute `pos = comma + 1` unconditionally, so once
    // the last (comma-less) component was reached, `comma == -1` sent `pos` back to 0 instead
    // of terminating the loop -- an infinite loop on the single most common input shape (a DN
    // with no trailing comma). This must return promptly rather than hang.
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CString("CN=example.com")));

    REQUIRE(dn.size() == 1);
    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));
}

TEST_CASE("CDistinguishedName::tryParse(CString) parses multiple components") {
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CString("CN=example.com, OU=Engineering, C=US")));

    REQUIRE(dn.size() == 3);

    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));

    REQUIRE(dn.tryGet(ENAME_OU, out));
    CHECK(out == CName(ENAME_OU, "Engineering"));

    REQUIRE(dn.tryGet(ENAME_C, out));
    CHECK(out == CName(ENAME_C, "US"));
}

TEST_CASE("CDistinguishedName::tryParse(CString) round-trips through toString") {
    CDistinguishedName original;
    REQUIRE(original.trySet(CName(ENAME_CN, "example.com")));
    REQUIRE(original.trySet(CName(ENAME_C, "US")));

    CString rendered;
    original.toString(rendered);

    CDistinguishedName parsed;
    REQUIRE(CDistinguishedName::tryParse(parsed, rendered));
    CHECK(parsed == original);
}

TEST_CASE("CDistinguishedName::tryParse(CString) key lookup is case-insensitive") {
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CString("cn=example.com")));

    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));
}

TEST_CASE("CDistinguishedName::tryParse(CString) trims whitespace around keys and values") {
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CString("  CN  =  example.com  ")));

    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));
}

TEST_CASE("CDistinguishedName::tryParse(CString) a later component overwrites an earlier one with the same key") {
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CString("CN=first, CN=second")));

    REQUIRE(dn.size() == 1);
    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "second"));
}

TEST_CASE("CDistinguishedName::tryParse(CString) rejects malformed input and leaves out empty") {
    SUBCASE("empty string") {
        CDistinguishedName dn;
        REQUIRE(dn.trySet(CName(ENAME_OU, "leftover"))); // pre-populate to verify it gets cleared
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CString("")));
        CHECK(dn.empty());
    }

    SUBCASE("missing '=' in a component") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CString("CN=example.com, Engineering")));
        CHECK(dn.empty());
    }

    SUBCASE("unrecognized key") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CString("XX=example.com")));
        CHECK(dn.empty());
    }

    SUBCASE("empty key after trimming") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CString("  =example.com")));
        CHECK(dn.empty());
    }

    SUBCASE("trailing comma") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CString("CN=example.com,")));
        CHECK(dn.empty());
    }

    SUBCASE("failed component clears output populated by earlier successful ones") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CString("CN=example.com, XX=bad")));
        CHECK(dn.empty());
    }
}

TEST_CASE("CDistinguishedName::tryParse(CWideString) parses a single component with no trailing comma") {
    // Same infinite-loop hazard as the narrow overload -- verify the wide overload terminates too.
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CWideString(L"CN=example.com")));

    REQUIRE(dn.size() == 1);
    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));
}

TEST_CASE("CDistinguishedName::tryParse(CWideString) parses multiple components") {
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CWideString(L"CN=example.com, OU=Engineering, C=US")));

    REQUIRE(dn.size() == 3);

    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));

    REQUIRE(dn.tryGet(ENAME_OU, out));
    CHECK(out == CName(ENAME_OU, "Engineering"));

    REQUIRE(dn.tryGet(ENAME_C, out));
    CHECK(out == CName(ENAME_C, "US"));
}

TEST_CASE("CDistinguishedName::tryParse(CWideString) round-trips through toString") {
    CDistinguishedName original;
    REQUIRE(original.trySet(CName(ENAME_CN, "example.com")));
    REQUIRE(original.trySet(CName(ENAME_C, "US")));

    CWideString rendered;
    original.toString(rendered);

    CDistinguishedName parsed;
    REQUIRE(CDistinguishedName::tryParse(parsed, rendered));
    CHECK(parsed == original);
}

TEST_CASE("CDistinguishedName::tryParse(CWideString) agrees with the narrow overload on the same content") {
    CDistinguishedName narrowResult, wideResult;
    REQUIRE(CDistinguishedName::tryParse(narrowResult, CString("CN=example.com, OU=Engineering")));
    REQUIRE(CDistinguishedName::tryParse(wideResult, CWideString(L"CN=example.com, OU=Engineering")));

    CHECK(narrowResult == wideResult);
}

TEST_CASE("CDistinguishedName::tryParse(CWideString) key lookup is case-insensitive") {
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CWideString(L"cn=example.com")));

    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));
}

TEST_CASE("CDistinguishedName::tryParse(CWideString) trims whitespace around keys and values") {
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn, CWideString(L"  CN  =  example.com  ")));

    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "example.com"));
}

TEST_CASE("CName::attributeOid / attributeTypeOf round-trip for every recognized name type") {
    // Every enumerator between ENAME_NONE and ENAME_MAX, so a type appended to ENameType without
    // a matching TYPE_OIDS/TYPE_KEYS/TYPE_LABELS entry fails here rather than silently reading a
    // zeroed one -- a C++ array with fewer initializers than its declared size compiles without
    // a word, leaving the remainder default-constructed.
    for (int i = ENAME_NONE + 1; i < ENAME_MAX; ++i) {
        const ENameType type = ENameType(i);
        CAPTURE(i);

        uint32_t arcs[CName::MAX_OID_ARCS] = {};
        size_t arcCount = 0;
        REQUIRE(CName::attributeOid(type, TSpan<uint32_t>(arcs, CName::MAX_OID_ARCS), arcCount));

        if (type == ENAME_DC) {
            // domainComponent is the one recognized attribute outside the X.520 arc: it lives
            // under RFC 4519's 0.9.2342.19200300.100.1.25, which is 7 arcs rather than 4.
            // --> The 7 is the true OID's arc count, and it was once 10 here, with three zero
            // arcs padded onto the end of the table to fill it. A DC encoded from that table
            // did not match the same DC decoded out of a certificate, because the encoder
            // wrote the zeros as real subidentifiers. Checked against COid::DN_DOMAIN_COMPONENT
            // in tests/oid.cpp as well, so the two tables cannot drift apart again unnoticed.
            REQUIRE(arcCount == 7);
            CHECK(arcs[0] == 0);
            CHECK(arcs[1] == 9);
            CHECK(arcs[2] == 2342);
            CHECK(arcs[3] == 19200300);
            CHECK(arcs[4] == 100);
            CHECK(arcs[5] == 1);
            CHECK(arcs[6] == 25);
        }
        else {
            // Every X.520 DN attribute OID is under the joint-iso-ccitt.ds.attributeType arc.
            REQUIRE(arcCount == 4);
            CHECK(arcs[0] == 2);
            CHECK(arcs[1] == 5);
            CHECK(arcs[2] == 4);
        }

        CHECK(CName::attributeTypeOf(TReadOnlySpan<uint32_t>(arcs, arcCount)) == type);

        REQUIRE(CName::keyOf(type));
        REQUIRE(CName::labelOf(type));
        CHECK(CName::keyOf(type)[0] != '\0');
        CHECK(CName::labelOf(type)[0] != '\0');
        CHECK(CName::typeOf(CName::keyOf(type)) == type);
    }
}

TEST_CASE("CName::attributeOid known values match X.520") {
    uint32_t arcs[4] = {};
    size_t arcCount = 0;

    REQUIRE(CName::attributeOid(ENAME_CN, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 3)); // 2.5.4.3

    REQUIRE(CName::attributeOid(ENAME_OU, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 11)); // 2.5.4.11

    REQUIRE(CName::attributeOid(ENAME_O, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 10)); // 2.5.4.10

    REQUIRE(CName::attributeOid(ENAME_L, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 7)); // 2.5.4.7

    REQUIRE(CName::attributeOid(ENAME_ST, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 8)); // 2.5.4.8

    REQUIRE(CName::attributeOid(ENAME_C, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 6)); // 2.5.4.6

    REQUIRE(CName::attributeOid(ENAME_OI, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 97)); // 2.5.4.97

    REQUIRE(CName::attributeOid(ENAME_SERIAL, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 5)); // 2.5.4.5

    REQUIRE(CName::attributeOid(ENAME_TITLE, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 12)); // 2.5.4.12

    REQUIRE(CName::attributeOid(ENAME_GN, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 42)); // 2.5.4.42

    REQUIRE(CName::attributeOid(ENAME_SURNAME, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 4)); // 2.5.4.4

    REQUIRE(CName::attributeOid(ENAME_PSEUDONYM, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 65)); // 2.5.4.65

    REQUIRE(CName::attributeOid(ENAME_DNQ, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK((arcs[0] == 2 && arcs[1] == 5 && arcs[2] == 4 && arcs[3] == 46)); // 2.5.4.46

    // domainComponent's OID is 7 arcs, so a 4-arc span is genuinely too small for it.
    CHECK_FALSE(CName::attributeOid(ENAME_DC, TSpan<uint32_t>(arcs, 4), arcCount));

    uint32_t dcArcs[CName::MAX_OID_ARCS] = {};
    REQUIRE(CName::attributeOid(ENAME_DC, TSpan<uint32_t>(dcArcs, CName::MAX_OID_ARCS), arcCount));
    REQUIRE(arcCount == 7);

    // --> 0.9.2342.19200300.100.1.25 -- the true domainComponent, with no zero arcs padded on
    // the end. It was once checked as ten arcs with three zeros, which is not the OID RFC
    // 4519 defines and would not have matched the same DC decoded from a certificate.
    const uint32_t expectedDc[7] = { 0, 9, 2342, 19200300, 100, 1, 25 };
    for (size_t i = 0; i < 7; ++i) {
        CAPTURE(i);
        CHECK(dcArcs[i] == expectedDc[i]);
    }
}

TEST_CASE("CName::typeOf matches a whole key, not a prefix of one") {
    // "organizationIdentifier" starts with "O": comparing only as many characters as the table's
    // own key is long made it resolve to ENAME_O, silently mislabelling the attribute.
    CHECK(CName::typeOf("organizationIdentifier") == ENAME_OI);
    CHECK(CName::typeOf("O") == ENAME_O);
    CHECK(CName::typeOf("OU") == ENAME_OU);
    CHECK(CName::typeOf("CN") == ENAME_CN);

    CHECK(CName::typeOf("CNX") == ENAME_NONE);
    CHECK(CName::typeOf("organization") == ENAME_NONE);
    CHECK(CName::typeOf("surnamed") == ENAME_NONE);
    CHECK(CName::typeOf("") == ENAME_NONE);

    // Still case-insensitive, as it always was.
    CHECK(CName::typeOf("organizationidentifier") == ENAME_OI);
    CHECK(CName::typeOf("cn") == ENAME_CN);
}

TEST_CASE("CName::attributeOid rejects ENAME_NONE, out-of-range types, and too-small outArcs") {
    uint32_t arcs[4] = {};
    size_t arcCount = 123;

    CHECK_FALSE(CName::attributeOid(ENAME_NONE, TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK(arcCount == 0);

    arcCount = 123;
    CHECK_FALSE(CName::attributeOid(ENameType(ENAME_MAX), TSpan<uint32_t>(arcs, 4), arcCount));
    CHECK(arcCount == 0);

    arcCount = 123;
    CHECK_FALSE(CName::attributeOid(ENAME_CN, TSpan<uint32_t>(arcs, 3), arcCount)); // too small
    CHECK(arcCount == 0);
}

TEST_CASE("CName::attributeTypeOf rejects an unrecognized OID and a non-4-arc span") {
    const uint32_t unrelated[4] = { 1, 2, 840, 113549 }; // arbitrary, unrelated to X.520
    CHECK(CName::attributeTypeOf(TReadOnlySpan<uint32_t>(unrelated, 4)) == ENAME_NONE);

    const uint32_t tooShort[3] = { 2, 5, 4 };
    CHECK(CName::attributeTypeOf(TReadOnlySpan<uint32_t>(tooShort, 3)) == ENAME_NONE);

    const uint32_t tooLong[5] = { 2, 5, 4, 3, 0 };
    CHECK(CName::attributeTypeOf(TReadOnlySpan<uint32_t>(tooLong, 5)) == ENAME_NONE);
}

TEST_CASE("CDistinguishedName::tryParse(CWideString) rejects malformed input and leaves out empty") {
    SUBCASE("empty string") {
        CDistinguishedName dn;
        REQUIRE(dn.trySet(CName(ENAME_OU, "leftover")));
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CWideString(L"")));
        CHECK(dn.empty());
    }

    SUBCASE("missing '=' in a component") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CWideString(L"CN=example.com, Engineering")));
        CHECK(dn.empty());
    }

    SUBCASE("unrecognized key") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CWideString(L"XX=example.com")));
        CHECK(dn.empty());
    }

    SUBCASE("empty key after trimming") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CWideString(L"  =example.com")));
        CHECK(dn.empty());
    }

    SUBCASE("trailing comma") {
        CDistinguishedName dn;
        CHECK_FALSE(CDistinguishedName::tryParse(dn, CWideString(L"CN=example.com,")));
        CHECK(dn.empty());
    }
}

// The strings below are the actual subject fields of well-known, publicly trusted root/
// intermediate CA certificates (or a stand-in leaf-certificate-style subject built from
// IANA-reserved documentation names, "example.com"/"Example Corp"), used as realistic
// production-style test fixtures rather than synthetic "CN=example.com" placeholders --
// exercising the exact field combinations, multi-word values, and punctuation (periods,
// hyphens, apostrophes) that show up in real deployed certificates. Each is written with its
// fields already in CDistinguishedName::toString()'s ascending-ENameType order
// (CN, OU, O, L, ST, C), so tryParse() -> toString() round-trips back to the identical string.
TEST_CASE("CDistinguishedName::tryParse / toString round-trip real-world CA subject strings") {
    const char* dn = nullptr;

    SUBCASE("DigiCert Global Root CA") {
        dn = "CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US";
    }

    SUBCASE("ISRG Root X1 (Let's Encrypt's root)") {
        dn = "CN=ISRG Root X1, O=Internet Security Research Group, C=US";
    }

    SUBCASE("Let's Encrypt R3 (intermediate) -- exercises an apostrophe in a value") {
        dn = "CN=R3, O=Let's Encrypt, C=US";
    }

    SUBCASE("GlobalSign Root CA") {
        dn = "CN=GlobalSign Root CA, O=GlobalSign nv-sa, C=BE";
    }

    SUBCASE("typical OV leaf certificate subject, all six supported fields") {
        dn = "CN=www.example.com, OU=IT Department, O=Example Corp, L=San Francisco, ST=California, C=US";
    }

    CAPTURE(dn);

    CDistinguishedName parsed;
    REQUIRE(CDistinguishedName::tryParse(parsed, CString(dn)));

    CString rendered;
    parsed.toString(rendered);
    CHECK(rendered == CString(dn));
}

TEST_CASE("CDistinguishedName::tryParse(CWideString) / toString round-trip the same real-world subjects") {
    const wchar_t* dn = nullptr;

    SUBCASE("DigiCert Global Root CA") {
        dn = L"CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US";
    }

    SUBCASE("Let's Encrypt R3") {
        dn = L"CN=R3, O=Let's Encrypt, C=US";
    }

    SUBCASE("typical OV leaf certificate subject, all six supported fields") {
        dn = L"CN=www.example.com, OU=IT Department, O=Example Corp, L=San Francisco, ST=California, C=US";
    }

    CDistinguishedName parsed;
    REQUIRE(CDistinguishedName::tryParse(parsed, CWideString(dn)));

    CWideString rendered;
    parsed.toString(rendered);
    CHECK(rendered == CWideString(dn));
}

TEST_CASE("CDistinguishedName holds every field of a realistic OV leaf certificate subject") {
    CDistinguishedName dn;
    REQUIRE(CDistinguishedName::tryParse(dn,
        CString("CN=www.example.com, OU=IT Department, O=Example Corp, L=San Francisco, ST=California, C=US")));

    REQUIRE(dn.size() == 6);

    CName out;
    REQUIRE(dn.tryGet(ENAME_CN, out));
    CHECK(out == CName(ENAME_CN, "www.example.com"));

    REQUIRE(dn.tryGet(ENAME_OU, out));
    CHECK(out == CName(ENAME_OU, "IT Department"));

    REQUIRE(dn.tryGet(ENAME_O, out));
    CHECK(out == CName(ENAME_O, "Example Corp"));

    REQUIRE(dn.tryGet(ENAME_L, out));
    CHECK(out == CName(ENAME_L, "San Francisco"));

    REQUIRE(dn.tryGet(ENAME_ST, out));
    CHECK(out == CName(ENAME_ST, "California"));

    REQUIRE(dn.tryGet(ENAME_C, out));
    CHECK(out == CName(ENAME_C, "US"));
}

TEST_CASE("CDistinguishedName built via trySet from real-world values round-trips through toString/tryParse") {
    // Same DigiCert Global Root CA subject as above, but built field-by-field via trySet()
    // rather than parsed from a string, then verified the other direction: toString() renders
    // it, and tryParse() on that rendering reconstructs an equal CDistinguishedName.
    CDistinguishedName original;
    REQUIRE(original.trySet(CName(ENAME_C, "US")));
    REQUIRE(original.trySet(CName(ENAME_O, "DigiCert Inc")));
    REQUIRE(original.trySet(CName(ENAME_OU, "www.digicert.com")));
    REQUIRE(original.trySet(CName(ENAME_CN, "DigiCert Global Root CA")));

    CString rendered;
    original.toString(rendered);
    CHECK(rendered == CString("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US"));

    CDistinguishedName reparsed;
    REQUIRE(CDistinguishedName::tryParse(reparsed, rendered));
    CHECK(reparsed == original);
}
