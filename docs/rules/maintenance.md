# Versioning and tests

[한국어](maintenance.ko.md)

## Versioning

← [Project rules](../RULES.md)

- `HEADER_VERSION` (in `version.hpp`) is the single number to bump when the
  ABI/API changes. `LIBRARY_VERSION` (in `version.cpp`, returned by
  `GetLibraryVersion()`) is defined *as* `HEADER_VERSION`, so it needs no
  separate edit — the point is that the value gets baked into the binary at
  the version of the header the binary was compiled against, while a
  consumer's `HEADER_VERSION` is whatever header *they* compiled against.
  Comparing the two at runtime is therefore how a consumer detects a
  header/binary mismatch, and it works precisely because only one of them
  is ever written by hand.
- `CMakeLists.txt`'s `project(certpp VERSION ...)` (which drives the shared
  library's `VERSION`/`SOVERSION`) is a second, independent copy of the same
  number, with nothing keeping it in step. Bump it alongside
  `HEADER_VERSION`.

## Tests

← [Project rules](../RULES.md)

- All test cases live under `tests/`, not next to the code they test. A
  test file mirrors the `include/certpp/`/`src/` path of what it exercises
  (`tests/asn1/decoder.cpp` tests `asn1/decoder.hpp`/`decoder.cpp`); an
  integration/round-trip test spanning multiple headers still lives under
  the relevant module directory (`tests/asn1/roundtrip.cpp`), just without
  a 1:1 header match. `CMakeLists.txt` globs `tests/**/*.cpp` the same way
  it globs `src/**/*.cpp` (see [BUILDING.md](../BUILDING.md)), so a new test file
  needs no CMake changes.
- Tests use [doctest](https://github.com/doctest/doctest), vendored as a
  single header under `third-party/doctest/`. Each test file `#define`s
  `DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN` before `#include
  <doctest/doctest.h>` (every test file is its own executable, so this
  never collides across translation units) and writes one or more
  `TEST_CASE("description") { ... }` blocks using `CHECK(cond)` (keeps
  checking the rest of the test case after a failure) or `REQUIRE(cond)`
  (stops the test case immediately, for a precondition a later check would
  otherwise read invalid state from). See `tests/asn1/decoder.cpp` for the
  pattern, and `tests/asn1/roundtrip.cpp` for `SUBCASE`/`CAPTURE` use when
  the same body needs to run across several inputs with independent
  pass/fail reporting per input.
- Test code doesn't need the full Javadoc treatment public declarations get
  (see "Documentation comments" above) -- a short `/* ... */` above a
  `TEST_CASE` describing what's non-obvious about it (a regression it locks
  in, why a case is security-relevant, etc.) is enough; a self-descriptive
  `TEST_CASE` name needs no comment at all.
