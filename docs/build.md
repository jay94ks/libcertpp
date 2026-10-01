# Building

`libcertpp` builds with CMake (3.15+) and requires a C++17 compiler.

## Configure & build

Shared library (default):

```sh
cmake -S . -B build
cmake --build build --config Debug
```

Static library:

```sh
cmake -S . -B build -DCERTPP_BUILD_SHARED=OFF
cmake --build build --config Debug
```

On single-config generators (Makefiles, Ninja), set the build type instead
of `--config`:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## CMake options

| Option                | Default | Effect                                                        |
|------------------------|---------|----------------------------------------------------------------|
| `CERTPP_BUILD_SHARED`  | `ON`    | Builds `certpp` as a shared library (`.dll`/`.so`) instead of a static one (`.lib`/`.a`). |
| `CERTPP_BUILD_TESTS`   | `ON`    | Builds the test executables under `tests/` and registers them with CTest. |
| `CERTPP_RNG_FALLBACK`  | `OFF`   | Lets `crypto::CRng::fill()` fall back to `std::random_device` if the OS CSPRNG (`BCryptGenRandom` on Windows; `getrandom(2)` falling back to `/dev/urandom` on Linux; `/dev/urandom` on other POSIX platforms) is unavailable; default `OFF` compiles the fallback out and `fill()` returns `ERET_NOTSUP` in that case instead -- turn it on only as a stopgap for an environment that genuinely lacks an OS-level CSPRNG, since `std::random_device` is not guaranteed to be cryptographically secure on every standard library. |
| `CERTPP_DISABLE_HWACCEL_SIMD` | `OFF` | Disables `CBigNum`'s ADX/BMI2 and `CGf2m`'s PCLMULQDQ acceleration (and, transitively, every asymmetric algorithm built on them), always using the portable loop instead. x86-64-only either way -- has no effect on other architectures, where the portable loop is the only one that ever exists. |
| `CERTPP_DISABLE_HWACCEL_SHA` | `OFF` | Disables `SHA1`/`SHA256`'s SHA-NI acceleration, always using the portable compression loop instead. x86-64-only either way; `MD5`/`SHA384`/`SHA512`/`SHAKE256` have no hardware-accelerated path regardless of this option (no mainstream x86 extension covers them), so it has no effect on those. |
| `CERTPP_DISABLE_HWACCEL_AES` | `OFF` | Disables `AES`'s AES-NI acceleration, always using the portable round functions instead. x86-64-only either way; `DES`/`TripleDES`/`ChaCha20` have no hardware-accelerated path regardless of this option (no mainstream x86 extension covers them), so it has no effect on those. |

## Install

```sh
cmake --install build --prefix <install-prefix>
```

Installs the `certpp` library, public headers (`include/`), and a
`certpp-targets.cmake` export under `<prefix>/lib/cmake/certpp`, so a
downstream CMake project can `find_package` on it and link `certpp::certpp`.
There is no versioned `certpp-config.cmake` yet — add one if/when the
project needs `find_package(certpp)` to work without `CMAKE_PREFIX_PATH`
pointing straight at the targets file.

## Notes on `CERTPP_API`

`include/certpp/common.hpp` defines `CERTPP_API` for MSVC dllexport/
dllimport based on two preprocessor switches:

- `__COMPILES_LIBCERTPP__` — defined only while compiling `certpp`'s own
  translation units (set `PRIVATE` in `CMakeLists.txt`). Never define this
  in consumer code.
- `__SHARED_LIBCERTPP__` — defined when certpp is built/consumed as a
  shared library. `CMakeLists.txt` propagates this as a `PUBLIC` compile
  definition automatically when `CERTPP_BUILD_SHARED=ON`, so consumers
  linking against `certpp::certpp` pick it up without doing anything
  themselves.

## Tests

All test cases live under [`tests/`](../tests/), one CMake executable per
source file, mirroring the `include/certpp/` (and `src/`) path it exercises
(e.g. [`tests/asn1/decoder.cpp`](../tests/asn1/decoder.cpp) tests
`asn1/decoder.hpp`). A file that doesn't map to one specific header (an
integration/round-trip check spanning several, like
[`tests/asn1/roundtrip.cpp`](../tests/asn1/roundtrip.cpp)) still lives under
the matching module directory, just without a 1:1 header match.

Tests use [doctest](https://github.com/doctest/doctest), vendored as a
single header at [`third-party/doctest/doctest.h`](../third-party/doctest/doctest.h)
(exposed as the CMake `doctest` INTERFACE target by
[`third-party/CMakeLists.txt`](../third-party/CMakeLists.txt), only
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
[`tests/x509/realcerts.cpp`](../tests/x509/realcerts.cpp)'s `certs/`
subdirectory of real certificate files) can locate it via the
`CERTPP_TEST_DIR` compile definition every test target gets automatically:
the absolute path to that test's own `.cpp` file's directory, forward-slash
normalized (a raw Windows backslash would corrupt the string literal). This
lets a test find its fixtures reliably regardless of the working directory
it happens to run from — `ctest`'s default working directory differs from
running the `.exe` directly, and both differ depending on the caller's own
current directory.
