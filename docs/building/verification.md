# Tests and examples

[한국어](verification.ko.md)

## Tests

← [Build and verification](../BUILDING.md)

All test cases live under [`tests/`](../../tests), one CMake executable per
source file, mirroring the `include/certpp/` (and `src/`) path it exercises
(e.g. [`tests/asn1/decoder.cpp`](../../tests/asn1/decoder.cpp) tests
`asn1/decoder.hpp`). A file that doesn't map to one specific header (an
integration/round-trip check spanning several, like
[`tests/asn1/roundtrip.cpp`](../../tests/asn1/roundtrip.cpp)) still lives under
the matching module directory, just without a 1:1 header match.

Tests use [doctest](https://github.com/doctest/doctest), vendored as a
single header at [`third-party/doctest/doctest.h`](../../third-party/doctest/doctest.h)
(exposed as the CMake `doctest` INTERFACE target by
[`third-party/CMakeLists.txt`](../../third-party/CMakeLists.txt), only
`add_subdirectory`'d when `CERTPP_BUILD_TESTS=ON`). Each test file
`#define`s `DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN` before `#include
<doctest/doctest.h>` and writes plain `TEST_CASE(...)`/`CHECK(...)`/
`REQUIRE(...)` blocks; since every test file compiles to its own
executable (see below), there's no ODR conflict from each one generating
its own `main`.

Build and run:

```sh
cmake -S . -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

`CMakeLists.txt` globs `tests/**/*.cpp` the same way it globs `src/**/*.cpp`,
so a new test file is picked up automatically — no need to list it anywhere.
Set `-DCERTPP_BUILD_TESTS=OFF` to skip building tests entirely.

A test needing on-disk fixture data (e.g.
[`tests/x509/realcerts.cpp`](../../tests/x509/realcerts.cpp)'s `certs/`
subdirectory of real certificate files) can locate it via the
`CERTPP_TEST_DIR` compile definition every test target gets automatically:
the absolute path to that test's own `.cpp` file's directory, forward-slash
normalized (a raw Windows backslash would corrupt the string literal). This
lets a test find its fixtures reliably regardless of the working directory
it happens to run from — `ctest`'s default working directory differs from
running the `.exe` directly, and both differ depending on the caller's own
current directory.

Tests normally link the library and use its public headers. Tests that must
compare private implementations directly additionally compile an explicit set
of `src/` files into their executable and add `src/` to the include path. The
current cases are:

- tests under `tests/crypto/kems/`, which compile ML-KEM's private ring and
  codec units;
- the ML-DSA ring, rounding, codec, sampler, parameter, and ACVP tests, each
  with the subset of private ML-DSA units it exercises;
- direct tests for GHASH, StreebogCore, the SHA-512 byte-load fallback,
  Fe25519, and AesCore's portable/accelerated agreement.

Those units have no public API and so carry no `CERTPP_API` — they aren't
exported from the shared object, and linking cannot reach them. Compiling a
second copy into the test is safe *precisely because* they aren't exported, so
it can never collide with the library's own.

The lists are written out in `CMakeLists.txt` under
`CERTPP_TEST_PRIVATE_SOURCES`, not globbed. Exported implementations stay out
of these lists because the test already imports their symbols from `certpp`;
adding them again would create duplicate definitions. Adding a private unit is
therefore a deliberate CMake change. Everything else is tested through the
public surface.

## Examples

← [Build and verification](../BUILDING.md)

[`examples/`](../../examples) holds a small, runnable CA-hierarchy walkthrough
(issue a root, an intermediate and a leaf, then sign and verify data with
the leaf's key). It is built by default; set
`-DCERTPP_BUILD_EXAMPLES=OFF` to skip it.

```sh
cmake --build build --config Debug
./build/Debug/certpp_example_01_issue_ca_root
```

`CMakeLists.txt` globs `examples/*.cpp` (non-recursively — `common.hpp` is
shared support code, not an example), one executable per file, named
`certpp_example_<stem>`. Unlike tests, they are deliberately **not**
registered with CTest: each one writes a `.pem` the next one reads, so they
are ordered rather than independent. Every example target gets a
`CERTPP_EXAMPLE_OUTPUT_DIR` compile definition pointing at
`examples/output/` (created at configure time and gitignored), so the
programs find each other's output regardless of the working directory they
are run from. Delete that directory, or rerun from step 1, to regenerate
everything with fresh keys. See [`examples/README.md`](../../examples/README.md)
for what each one does.
