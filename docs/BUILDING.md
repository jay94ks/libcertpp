# Build and verification

[한국어](BUILDING.ko.md)

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

## Detailed pages

- [Configuration and installation](building/configuration.md)
- [Tests and examples](building/verification.md)
