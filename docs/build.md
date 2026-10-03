# Building

[한국어](build.ko.md)

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
| `CERTPP_BUILD_EXAMPLES` | `ON`   | Builds the programs under `examples/` as `certpp_example_<name>` executables. They are not registered with CTest (they write certificates to `examples/output/` and are meant to be run by hand, in order); see [`examples/README.md`](../examples/README.md). |
| `CERTPP_RNG_FALLBACK`  | `OFF`   | Lets `crypto::CRng::fill()` fall back to `std::random_device` if the OS CSPRNG (`BCryptGenRandom` on Windows; `getrandom(2)` falling back to `/dev/urandom` on Linux; `/dev/urandom` on other POSIX platforms) is unavailable; default `OFF` compiles the fallback out and `fill()` returns `ERET_NOTSUP` in that case instead -- turn it on only as a stopgap for an environment that genuinely lacks an OS-level CSPRNG, since `std::random_device` is not guaranteed to be cryptographically secure on every standard library. |
| `CERTPP_DISABLE_HWACCEL_SIMD` | `OFF` | Disables `CBigNum`'s ADX/BMI2, `CGf2m`'s and `Ghash`'s PCLMULQDQ and `ChaCha20`'s four-block SSE2 keystream (and, transitively, every asymmetric algorithm built on the first two, plus the ChaCha20-Poly1305, XChaCha20-Poly1305 and AES-GCM AEADs), always using the portable loop instead. x86-64-only either way -- has no effect on other architectures, where the portable loop is the only one that ever exists. Unlike the ADX/BMI2 and PCLMULQDQ paths, the SSE2 one needs no runtime CPU check, since SSE2 is part of the x86-64 ABI. |
| `CERTPP_DISABLE_HWACCEL_SHA` | `OFF` | Disables `SHA1`/`SHA256`'s SHA-NI acceleration, always using the portable compression loop instead. x86-64-only either way; `MD5`/`SHA384`/`SHA512`/`SHAKE128`/`SHAKE256` have no hardware-accelerated path regardless of this option, so it has no effect on those. SHA-NI itself covers only SHA-1 and SHA-256; Intel's separate SHA512 extension does exist but is recent enough that it cannot be relied on, and this library does not use it. |
| `CERTPP_DISABLE_HWACCEL_AES` | `OFF` | Disables `AesCore`'s AES-NI acceleration -- so both the `AES` block cipher and the AES-GCM AEAD built on it -- always using the portable round functions instead. x86-64-only either way; `DES`/`TripleDES` have no hardware-accelerated path regardless of this option (no mainstream x86 extension covers them), so it has no effect on those. `ChaCha20` does have one, but it is SSE2 rather than an AES extension and so is governed by `CERTPP_DISABLE_HWACCEL_SIMD` instead. |

## Install

```sh
cmake --install build --prefix <install-prefix>
```

Installs the `certpp` library, the public headers (`include/`), and a full
CMake package under `<prefix>/lib/cmake/certpp` — `certpp-targets.cmake`
plus `certpp-config.cmake` and `certpp-config-version.cmake`. A downstream
project consumes it the ordinary way:

```cmake
find_package(certpp REQUIRED)
target_link_libraries(myapp PRIVATE certpp::certpp)
```

with `-DCMAKE_PREFIX_PATH=<prefix>` if the prefix is not already searched.
The version file is `SameMajorVersion`, matching the shared object's
`SOVERSION`.

Note that a *static* certpp must be consumed with a matching MSVC runtime —
installing a Release build and linking it into a Debug consumer produces
`_ITERATOR_DEBUG_LEVEL`/`RuntimeLibrary` mismatch errors at link time, which
is an MSVC rule rather than anything specific to this library.

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

A few tests are an exception to "every test links the library and uses it
through its public headers": they additionally get a listed set of `src/`
sources compiled into their own executable, plus `src/` on the include path.
Two groups qualify today:

- a test under `tests/crypto/kems/` gets `src/crypto/kems/mlkemring.cpp` and
  `mlkemcodec.cpp` — ML-KEM's lattice arithmetic and wire encoding;
- `tests/crypto/asyms/mldsaring.cpp` gets `src/crypto/asyms/mldsaring.cpp`,
  scoped to that one test rather than to `crypto/asyms/`, which holds two
  dozen others with no business compiling ML-DSA's ring in.

Those units have no public API and so carry no `CERTPP_API` — they aren't
exported from the shared object, and linking cannot reach them. Compiling a
second copy into the test is safe *precisely because* they aren't exported, so
it can never collide with the library's own.

The lists are written out in `CMakeLists.txt` rather than globbed, and
`src/crypto/kems/mlkem.cpp`/`mlkemsampler.cpp` are deliberately left out:
those implement the exported `CMlKem`/`CMlKemSampler`/`MLKEM`, so compiling
them here too would define symbols the test already imports from `certpp`.
Adding a new private unit to a list is therefore a manual step — which is the
point, since the alternative fails at link time in a way that takes a while to
read. Everything else in the library is tested through the public surface, as
`DesCore`, `KeccakCore` and `CbcTransformer` are (via `ISymmetric`/`IHasher`).

## Examples

[`examples/`](../examples/) holds a small, runnable CA-hierarchy walkthrough
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
everything with fresh keys. See [`examples/README.md`](../examples/README.md)
for what each one does.

## AddressSanitizer build

MSVC supports ASan directly, in a separate build directory so the
instrumented objects never mix with the ordinary ones:

```sh
cmake -S . -B build-asan -DCMAKE_CXX_FLAGS="/fsanitize=address /EHsc"
cmake --build build-asan --config Debug
ctest --test-dir build-asan -C Debug --output-on-failure
```

`build-asan/` (like `build/` and any `build-*`/`build_*` directory) is
gitignored. Note that MSVC's ASan does **not** include a leak detector, so
this catches out-of-bounds and use-after-free but not leaks — a leak in
`TString`'s destructor survived exactly such a run (see
[`changelog.md`](changelog.md)).
