# Configuration and installation

[한국어](configuration.ko.md)

## CMake options

| Option                | Default | Effect                                                        |
|------------------------|---------|----------------------------------------------------------------|
| `CERTPP_BUILD_SHARED`  | `ON`    | Builds `certpp` as a shared library (`.dll`/`.so`) instead of a static one (`.lib`/`.a`). |
| `CERTPP_WITHOUT_JSON`  | `OFF`   | Excludes the JSON utility implementation and umbrella-header include, omits its header from installation, skips its test executable, and propagates `CERTPP_WITHOUT_JSON` to consumers. |
| `CERTPP_BUILD_TESTS`   | `ON`    | Builds the test executables under `tests/` and registers them with CTest. |
| `CERTPP_BUILD_EXAMPLES` | `ON`   | Builds the programs under `examples/` as `certpp_example_<name>` executables. They are not registered with CTest (they write certificates to `examples/output/` and are meant to be run by hand, in order); see [`examples/README.md`](../../examples/README.md). |
| `CERTPP_RNG_FALLBACK`  | `OFF`   | Lets `crypto::CRng::fill()` fall back to `std::random_device` if the OS CSPRNG (`BCryptGenRandom` on Windows; `getrandom(2)` falling back to `/dev/urandom` on Linux; `/dev/urandom` on other POSIX platforms) is unavailable; default `OFF` compiles the fallback out and `fill()` returns `ERET_NOTSUP` in that case instead -- turn it on only as a stopgap for an environment that genuinely lacks an OS-level CSPRNG, since `std::random_device` is not guaranteed to be cryptographically secure on every standard library. |
| `CERTPP_ENABLE_FE25519_RADIX51` | `OFF` | Selects the five-limb radix-2^51 `Fe25519` layout instead of the default ten-limb radix-2^25.5 layout. It requires native 64x64-to-128 multiplication and is off because the supported GCC measurement was not faster end to end. |
| `CERTPP_DISABLE_HWACCEL_SIMD` | `OFF` | Disables the non-AES/SHA-extension paths: ADX/BMI2 in `CBigNum`, PCLMULQDQ in `CGf2m` and `Ghash`, GFNI reflection in `Ghash`, SSE2/AVX2 ChaCha20, BMI1 ANDN in Keccak, BMI2 RORX in SHA-384/SHA-512, and AVX512-IFMA in Poly1305. Portable implementations remain available. |
| `CERTPP_DISABLE_HWACCEL_SHA` | `OFF` | Disables only the SHA-NI compression paths for SHA-1 and SHA-224/SHA-256. SHA-384/SHA-512's BMI2 RORX and SHA-3/SHAKE's BMI1 ANDN paths are governed by `CERTPP_DISABLE_HWACCEL_SIMD`. |
| `CERTPP_DISABLE_HWACCEL_AES` | `OFF` | Disables `AesCore`'s AES-NI acceleration -- so both the `AES` block cipher and the AES-GCM AEAD built on it -- always using the portable round functions instead. x86-64-only either way; `DES`/`TripleDES` have no hardware-accelerated path regardless of this option (no mainstream x86 extension covers them), so it has no effect on those. `ChaCha20` uses SSE2 and AVX2 instead and is governed by `CERTPP_DISABLE_HWACCEL_SIMD`. |

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
[project history](../HISTORY.md)).
