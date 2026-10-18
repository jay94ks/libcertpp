# Configuration and installation

[한국어](configuration.ko.md)

## CMake options

| Option                | Default | Effect                                                        |
|------------------------|---------|----------------------------------------------------------------|
| `CERTPP_BUILD_SHARED`  | `ON`    | Builds `certpp` as a shared library (`.dll`/`.so`) instead of a static one (`.lib`/`.a`). |
| `CERTPP_WITHOUT_JSON`  | `OFF`   | Excludes the JSON utility implementation and umbrella-header include, omits its header from installation, skips its test executable, and propagates `CERTPP_WITHOUT_JSON` to consumers. |
| `CERTPP_BUILD_TESTS`   | `ON`    | Builds the test executables under `tests/` and registers them with CTest. |
| `CERTPP_BUILD_EXAMPLES` | `ON`   | Builds the programs under `examples/` as `certpp_example_<name>` executables. They are not registered with CTest (they write certificates to `examples/output/` and are meant to be run by hand, in order); see [`examples/README.md`](../../examples/README.md). |
| `CERTPP_BUILD_FUZZERS` | `OFF` | Builds the five Clang/libFuzzer parser targets under `fuzz/` with AddressSanitizer and UndefinedBehaviorSanitizer. |
| `CERTPP_BUILD_AUDIT_TOOLS` | `OFF` | Builds manual security-review tools, currently `certpp_mldsa_timing_audit`. These are measurements, not pass/fail unit tests. |
| `CERTPP_RNG_FALLBACK`  | `OFF`   | Lets `crypto::CRng::fill()` fall back to `std::random_device` if the OS CSPRNG (`BCryptGenRandom` on Windows; `getrandom(2)` falling back to `/dev/urandom` on Linux; `/dev/urandom` on other POSIX platforms) is unavailable; default `OFF` compiles the fallback out and `fill()` returns `ERET_NOTSUP` in that case instead -- turn it on only as a stopgap for an environment that genuinely lacks an OS-level CSPRNG, since `std::random_device` is not guaranteed to be cryptographically secure on every standard library. |
| `CERTPP_ENABLE_FE25519_RADIX51` | `ON` on supported 64-bit GCC/Clang targets; `OFF` otherwise | Selects the five-limb radix-2^51 `Fe25519` layout. It requires native 64x64-to-128 multiplication; unsupported compilers and targets use the ten-limb radix-2^25.5 fallback. Set it explicitly to exercise either path on a capable target. |
| `CERTPP_DISABLE_HWACCEL_SIMD` | `OFF` | Disables the non-AES/SHA-extension paths: ADX/BMI2 in `CBigNum`, BMI2/ADX-enabled targets for packed Montgomery exponentiation chains, AVX2/BMI2/ADX X25519 ladder tuning, PCLMULQDQ in `CGf2m` and `Ghash`, GFNI reflection in `Ghash`, AVX-512VL MD4 and SHA-384/SHA-512, BMI1 MD5, SSE2 BLAKE2s, SSE2/AVX2/AVX-512F ChaCha20, AVX-512VL and BMI1 in Keccak, BMI2 RORX in SHA-384/SHA-512, and AVX512-IFMA in Poly1305. Portable implementations remain available. |
| `CERTPP_DISABLE_HWACCEL_AVX512` | `OFF` | Disables AVX-512VL MD4, SHA-384/SHA-512, and Keccak, AVX-512F ChaCha20, AVX512-IFMA Poly1305, and the exact Tiger Lake X25519 and packed Montgomery targets while retaining narrower or generic SIMD paths. Use this to compare narrower paths against AVX-512 or to support an environment that saves only the narrower vector state. |
| `CERTPP_DISABLE_HWACCEL_SHA` | `OFF` | Disables only the SHA-NI compression paths for SHA-1 and SHA-224/SHA-256. SHA-384/SHA-512's BMI2 RORX and SHA-3/SHAKE's BMI1 ANDN paths are governed by `CERTPP_DISABLE_HWACCEL_SIMD`. |
| `CERTPP_DISABLE_HWACCEL_AES` | `OFF` | Disables `AesCore`'s AES-NI and VAES acceleration -- so both the `AES` block cipher and the AES-GCM AEAD built on it -- always using the portable round functions instead. The VAES path encrypts eight independent GCM counters at a time after runtime CPU and OS-state checks. `DES`/`TripleDES` have no hardware-accelerated path regardless of this option. `ChaCha20` uses SSE2, AVX2, and AVX-512F instead and is governed by the SIMD switches. |

## Supported build contract

The maintained build contract is CMake 3.15 or newer, C++17, Windows with
MSVC, and Linux with GCC. Clang is also required for the optional libFuzzer
targets. A change that touches public headers, exports, platform branches, or
installed metadata must keep the default shared build, the static build, the
portable hardware-acceleration-disabled build, and the installed consumer
test working. Automated CI and a broader platform matrix remain future work;
see [Plans](../PLANS.md).

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

When tests are enabled, the `install_consumer` CTest case installs the current
build into a temporary prefix, configures a separate `find_package(certpp)`
project, links and runs it, and compares `HEADER_VERSION` with
`GetLibraryVersion()`. This is the release-facing check for missing installed
headers, exports, transitive link requirements, and version skew.

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
