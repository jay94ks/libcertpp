# Tests, examples, and static analysis

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

CMake undefines `NDEBUG` for test targets and force-includes
[`tests/support/runtime.hpp`](../../tests/support/runtime.hpp) in every test
translation unit. Standard `assert` therefore remains active in Release and
prints the failed expression and source location to `stderr`. On Windows the
runtime shim routes CRT reports and aborts to the console while suppressing
modal error dialogs. A failed unattended CTest run therefore terminates and
leaves a log instead of waiting for a button click.

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

## Installed consumer, fuzzers, and audit tools

The regular CTest run includes `install_consumer`. It installs the selected
configuration, configures a separate project through `find_package(certpp)`,
builds and runs it, and checks that the public header and linked library report
the same version. Run only this release-facing check with:

```sh
ctest --test-dir build -C Debug -R install_consumer --output-on-failure
```

Build parser fuzzers with Clang in their own directory:

```sh
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ \
  -DCERTPP_BUILD_FUZZERS=ON -DCERTPP_BUILD_TESTS=OFF \
  -DCERTPP_BUILD_EXAMPLES=OFF
cmake --build build-fuzz --config Debug
./build-fuzz/certpp_fuzz_asn1_der -runs=1000
```

The other targets are `certpp_fuzz_containers`, `certpp_fuzz_dnssec`,
`certpp_fuzz_json_bson`, and `certpp_fuzz_x509_objects`. They use libFuzzer
with AddressSanitizer and UndefinedBehaviorSanitizer. A clean bounded run is a
smoke check; sustained campaigns should supply persistent corpora outside the
source tree.

The ML-DSA timing review tool is opt-in:

```sh
cmake -S . -B build-audit -DCERTPP_BUILD_AUDIT_TOOLS=ON \
  -DCERTPP_BUILD_TESTS=OFF -DCERTPP_BUILD_EXAMPLES=OFF
cmake --build build-audit --config Release
./build-audit/certpp_mldsa_timing_audit
```

It reports per-outcome timing distributions so reviewers can compare rejection
classes. It is evidence for manual review, not a constant-time certification or
a stable benchmark threshold.

## Cppcheck static analysis

The maintained FLOSS static-analysis baseline was refreshed on 2026-10-16 with Cppcheck
2.13.0 from Ubuntu 24.04 under WSL 2. The primary pass uses CMake's GCC compile
database so that Cppcheck sees the same source files, include paths, language
standard, and project definitions as the library build. Install and reproduce
that pass with:

```sh
sudo apt-get update
sudo apt-get install -y cppcheck
cmake -S . -B build-cppcheck \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCERTPP_BUILD_SHARED=OFF \
  -DCERTPP_BUILD_TESTS=OFF \
  -DCERTPP_BUILD_EXAMPLES=OFF
mkdir -p build-cppcheck/cppcheck-cache
cppcheck --project=build-cppcheck/compile_commands.json \
  --cppcheck-build-dir=build-cppcheck/cppcheck-cache \
  --enable=all --inconclusive --check-level=exhaustive \
  --inline-suppr --suppress=missingIncludeSystem \
  --suppress=unmatchedSuppression \
  --xml --xml-version=2 \
  2> build-cppcheck/cppcheck-library.xml
```

The pass covered all 121 library translation units and the public and private
headers reachable from them. Its post-remediation result was 529 diagnostics:

| Severity | Count | Review result |
| --- | ---: | --- |
| error | 0 | No Cppcheck error remained. |
| warning | 15 | All were reviewed as false positives caused by initialization through helpers or by a guarded first read. |
| performance | 60 | Suggestions, principally constructor initializer lists; no correctness defect was established. |
| style | 453 | Mostly public API reported as unused, intentional implicit conversions, and broad refactoring suggestions. |
| information | 1 | Checker coverage report: 172 of 592 checkers active for this configuration. |

The 15 residual warnings have three causes. Ten point at `TString` fields that
are initialized explicitly in the converting constructor or, for
`TStringConverter::_state`, by `memset`. Four claim that `CBuffer` and `COctet`
copy assignment omit their storage fields; both operators delegate to
`store()`, which updates or clears those fields. The remaining warning concerns
`ChaCha20Transformer::_keystream`; `_keystreamPos` starts at the block size, so
the first attempted read generates a block before reading that array.

The audit fixed every actionable warning found in the reviewed scope:

- `SDateTime::now()` no longer contains a second `asUtc` branch that was
  unreachable after the UTC early return;
- `ISymmetricKey` now initializes its algorithm to `ESYM_UNKNOWN`, so future
  derived key types cannot expose an indeterminate algorithm before setting it;
- the three certificate-issuing examples check SHA-1 hasher creation before
  dereferencing the result. Their six possible-null warnings are gone.

An additional compile-database pass over the 16 compiled examples reported no
errors and ten warnings, all the same reviewed `TString` false positives. The
ML-DSA timing audit tool and the standalone Fe25519 squaring generator reported
no error or warning. Generated wiki snippets were not analyzed independently;
their maintained C++ example sources were included in the example pass.

The opt-in radix-51 source was also checked directly with the x86-64 GCC
`__int128` capability macros and reported no error or warning. Cppcheck 2.13.0
does not infer GCC's `__SIZEOF_INT128__` built-in from the compile database, so
an unqualified project pass with `CERTPP_ENABLE_FE25519_RADIX51=ON` reaches the
header's intentional unsupported-target `#error`. That is an analyzer model
limitation rather than a source finding.

This baseline is Linux-specific because the requested analysis ran in WSL. It
does not cover branches selected only by MSVC or the Windows CRT. Test sources
are excluded from the exhaustive pass because expanding the vendored doctest
header for every test translation unit makes Cppcheck 2.13.0 impractically
slow; compiler builds and CTest remain the validation owners for those files.
Raw XML and Cppcheck caches belong under an ignored build directory and are not
maintained documentation.

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
