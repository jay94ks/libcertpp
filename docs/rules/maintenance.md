# Versioning and tests

[한국어](maintenance.ko.md)

## Versioning, ABI, and releases

← [Project rules](../RULES.md)

The project follows Semantic Versioning. The current line is 1.1.0. Patch
releases contain compatible fixes, minor releases may add source and ABI
compatible public API, and a major release is required for a public ABI or
source compatibility break. The installed CMake package uses
`SameMajorVersion`; the library `SOVERSION` is the major version. Within a
major line:

- do not remove or change the type, order, ownership, or semantics of public
  function parameters and return values;
- append public enum values rather than reordering or renumbering existing
  ones;
- do not change public class layout or virtual tables without a major bump;
- keep installed headers, `CERTPP_API` exports, and transitive link
  requirements usable by `certpp::certpp` consumers.

`HEADER_VERSION` in `version.hpp` is the runtime header version. The binary's
`LIBRARY_VERSION` is compiled from it and returned by `GetLibraryVersion()`.
`CMakeLists.txt`'s `project(certpp VERSION ...)` is a separate copy and must
match. A release updates both values together.

### Release checklist

1. Classify public changes under the compatibility rules above and choose the
   SemVer increment. Update both version declarations.
2. Update the English and Korean maintained documentation, plans/history, and
   `docs/INDEX.md` when files are added, moved, or removed.
3. Run the full test suite in the default shared and static configurations;
   run the portable acceleration-disabled configuration when cryptographic or
   platform code changed.
4. Run `install_consumer` in the release configuration and confirm the
   installed `find_package(certpp)` project builds and executes.
5. Run the bounded parser fuzz smoke tests for parser/codec changes and the
   relevant audit tool for timing-sensitive changes.
6. Inspect `git diff --check`, repository status, public header diffs, and
   release notes. Commit, tag, and push only after an explicit user request.

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
