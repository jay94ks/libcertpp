#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/utils/djb.hpp>
#include <cstring>

using namespace certpp;

namespace {
    inline SDjbValue hashBytes(const char* text) {
        return CDjb::compute(TReadOnlySpan<uint8_t>(reinterpret_cast<const uint8_t*>(text), std::strlen(text)));
    }
}

TEST_CASE("compute of an empty span returns the seed/hash unchanged") {
    CHECK(CDjb::compute(TReadOnlySpan<uint8_t>(nullptr, 0)) == 5381);
    CHECK(CDjb::compute(SDjbValue(42), TReadOnlySpan<uint8_t>(nullptr, 0)) == 42);
}

TEST_CASE("compute is deterministic and content-sensitive") {
    const uint8_t a[] = { 'h', 'e', 'l', 'l', 'o' };
    const uint8_t b[] = { 'h', 'e', 'l', 'l', 'o' };
    const uint8_t c[] = { 'w', 'o', 'r', 'l', 'd' };

    SDjbValue hashA = CDjb::compute(TReadOnlySpan<uint8_t>(a, sizeof(a)));
    SDjbValue hashB = CDjb::compute(TReadOnlySpan<uint8_t>(b, sizeof(b)));
    SDjbValue hashC = CDjb::compute(TReadOnlySpan<uint8_t>(c, sizeof(c)));

    CHECK(hashA == hashB); // same content -> same hash
    CHECK(hashA != hashC); // different content -> (in practice) different hash
}

TEST_CASE("compute(span) defaults to the same seed as compute(SEED, span)") {
    const uint8_t data[] = { 'x', 'y', 'z' };
    SDjbValue withDefault = CDjb::compute(TReadOnlySpan<uint8_t>(data, sizeof(data)));
    SDjbValue withExplicitSeed = CDjb::compute(SDjbValue(5381), TReadOnlySpan<uint8_t>(data, sizeof(data)));
    CHECK(withDefault == withExplicitSeed);
}

TEST_CASE("compute chains correctly: hashing in two parts matches hashing the whole span at once") {
    // This is the whole point of exposing compute(hash, span): a caller should be able to hash
    // multiple fragments as one logical value by threading the partial hash through.
    const uint8_t part1[] = { 'f', 'o', 'o' };
    const uint8_t part2[] = { 'b', 'a', 'r' };
    const uint8_t whole[] = { 'f', 'o', 'o', 'b', 'a', 'r' };

    SDjbValue chained = CDjb::compute(TReadOnlySpan<uint8_t>(part1, sizeof(part1)));
    chained = CDjb::compute(chained, TReadOnlySpan<uint8_t>(part2, sizeof(part2)));

    SDjbValue direct = CDjb::compute(TReadOnlySpan<uint8_t>(whole, sizeof(whole)));

    CHECK(chained == direct);
}

TEST_CASE("computeAsUpper folds ASCII letters to uppercase before hashing") {
    const char lower[] = { 'h', 'e', 'l', 'l', 'o' };
    const char upper[] = { 'H', 'E', 'L', 'L', 'O' };
    const char mixed[] = { 'H', 'e', 'L', 'l', 'O' };

    SDjbValue hashLower = CDjb::computeAsUpper(TReadOnlySpan<char>(lower, sizeof(lower)));
    SDjbValue hashUpper = CDjb::computeAsUpper(TReadOnlySpan<char>(upper, sizeof(upper)));
    SDjbValue hashMixed = CDjb::computeAsUpper(TReadOnlySpan<char>(mixed, sizeof(mixed)));

    CHECK(hashLower == hashUpper);
    CHECK(hashLower == hashMixed);

    // Sanity check against the raw (non-folding) compute(): folding to uppercase should actually
    // hash the uppercase bytes, not silently pass the lowercase ones through unchanged.
    SDjbValue rawUpperBytes = CDjb::compute(TReadOnlySpan<uint8_t>(reinterpret_cast<const uint8_t*>(upper), sizeof(upper)));
    CHECK(hashLower == rawUpperBytes);
}

TEST_CASE("computeAsLower folds ASCII letters to lowercase before hashing") {
    const char lower[] = { 'h', 'e', 'l', 'l', 'o' };
    const char upper[] = { 'H', 'E', 'L', 'L', 'O' };
    const char mixed[] = { 'H', 'e', 'L', 'l', 'O' };

    SDjbValue hashLower = CDjb::computeAsLower(TReadOnlySpan<char>(lower, sizeof(lower)));
    SDjbValue hashUpper = CDjb::computeAsLower(TReadOnlySpan<char>(upper, sizeof(upper)));
    SDjbValue hashMixed = CDjb::computeAsLower(TReadOnlySpan<char>(mixed, sizeof(mixed)));

    CHECK(hashLower == hashUpper);
    CHECK(hashLower == hashMixed);

    SDjbValue rawLowerBytes = CDjb::compute(TReadOnlySpan<uint8_t>(reinterpret_cast<const uint8_t*>(lower), sizeof(lower)));
    CHECK(hashLower == rawLowerBytes);
}

TEST_CASE("computeAsUpper/computeAsLower leave non-letters (digits, punctuation, non-ASCII) untouched") {
    // Only 'a'-'z'/'A'-'Z' participate in case folding; everything else -- including a byte
    // outside the ASCII letter ranges entirely -- is hashed as-is by both functions.
    const char data[] = { '1', '2', '_', static_cast<char>(0xC3) };

    SDjbValue upper = CDjb::computeAsUpper(TReadOnlySpan<char>(data, sizeof(data)));
    SDjbValue lower = CDjb::computeAsLower(TReadOnlySpan<char>(data, sizeof(data)));
    SDjbValue raw = CDjb::compute(TReadOnlySpan<uint8_t>(reinterpret_cast<const uint8_t*>(data), sizeof(data)));

    CHECK(upper == raw);
    CHECK(lower == raw);
}

TEST_CASE("computeAsUpper(span) / computeAsLower(span) default to the same seed as their 2-arg form") {
    const char data[] = { 'M', 'i', 'x', 'e', 'd' };

    CHECK(CDjb::computeAsUpper(TReadOnlySpan<char>(data, sizeof(data)))
        == CDjb::computeAsUpper(SDjbValue(5381), TReadOnlySpan<char>(data, sizeof(data))));

    CHECK(CDjb::computeAsLower(TReadOnlySpan<char>(data, sizeof(data)))
        == CDjb::computeAsLower(SDjbValue(5381), TReadOnlySpan<char>(data, sizeof(data))));
}

TEST_CASE("computeAsUpper/computeAsLower chain correctly across partial hashes") {
    const char part1[] = { 'F', 'o' };
    const char part2[] = { 'O', 'b', 'A', 'r' };
    const char whole[] = { 'F', 'o', 'O', 'b', 'A', 'r' };

    SDjbValue chainedUpper = CDjb::computeAsUpper(TReadOnlySpan<char>(part1, sizeof(part1)));
    chainedUpper = CDjb::computeAsUpper(chainedUpper, TReadOnlySpan<char>(part2, sizeof(part2)));
    SDjbValue directUpper = CDjb::computeAsUpper(TReadOnlySpan<char>(whole, sizeof(whole)));
    CHECK(chainedUpper == directUpper);

    SDjbValue chainedLower = CDjb::computeAsLower(TReadOnlySpan<char>(part1, sizeof(part1)));
    chainedLower = CDjb::computeAsLower(chainedLower, TReadOnlySpan<char>(part2, sizeof(part2)));
    SDjbValue directLower = CDjb::computeAsLower(TReadOnlySpan<char>(whole, sizeof(whole)));
    CHECK(chainedLower == directLower);
}

TEST_CASE("combine matches its documented formula") {
    CHECK(CDjb::combine(0, 0) == 0);
    CHECK(CDjb::combine(1, 0) == (SDjbValue(1) << 5));
    CHECK(CDjb::combine(0, 7) == 7);

    const SDjbValue h1 = hashBytes("hello");
    const SDjbValue h2 = hashBytes("world");
    CHECK(CDjb::combine(h1, h2) == ((h1 << 5) ^ h2));

    // Order matters -- combine() is not commutative.
    CHECK(CDjb::combine(h1, h2) != CDjb::combine(h2, h1));
}
