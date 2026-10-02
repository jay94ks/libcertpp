# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`libcertpp` is an early-stage C++17 certificate-handling library. Beyond the
foundational scaffolding (type aliases, the `CERTPP_API` export macro, a
version struct), it now has: top-level `STimeSpan`/`SDateTime` calendar-time
types (`time.hpp`); an `io` layer (`TSpan`/`TReadOnlySpan`, `TArray`,
`CBuffer`, `COctet`, `CBase64`, the `IStream` interface with a
memory-backed implementation); an `asn1` module
(`CTag` tag encode/decode, `CDecoder`/`CEncoder` for reading/writing
BER/CER/DER TLVs plus per-type codecs for BOOLEAN, INTEGER, ENUMERATED,
NULL, OCTET STRING, BIT STRING/NamedBitList, OBJECT IDENTIFIER, character
strings, UTCTime/GeneralizedTime, and SEQUENCE/SET OF); a `crypto` module
(hashing, a CSPRNG, asymmetric algorithms -- RSA, DSA, ECDSA over prime
and binary curves, Ed25519, Ed448, X25519 -- symmetric ones -- AES,
DES, TripleDES, ChaCha20 -- and post-quantum ML-KEM (FIPS 203,
`crypto/pq/mlkem.hpp`), all from scratch); and an `x509` module that
both parses and builds DER/PEM X.509 `Certificate`s
(`CCert`/`CCertBuilder`), CRLs (`CCrlReader`/`CCrlWriter`) and OCSP
request/response (RFC 6960), including ten concrete extension types
(BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName,
SubjectKeyIdentifier, AuthorityKeyIdentifier, CRLDistributionPoints,
AuthorityInformationAccess, CertificatePolicies, NameConstraints) under
`x509/exts/`, each with a parse/build pair, and single-link signature
verification (`CCert::verifyBy()`, `CCrlReader::verifyBy()`). What it
deliberately does *not* have is chain building or path validation, and
CSR (PKCS#10) support. See
[`docs/architecture.md`](docs/architecture.md) for the full module
breakdown.

## Documentation

Detailed, longer-lived documentation lives under [`docs/`](docs/), not in
this file:

- [`docs/architecture.md`](docs/architecture.md) — module responsibilities and how the pieces fit together.
- [`docs/coding-conventions.md`](docs/coding-conventions.md) — naming, header-guard, formatting, buffer-handling, and doc-comment conventions derived from the existing code.
- [`docs/build.md`](docs/build.md) — full CMake build/install reference, plus the examples and AddressSanitizer builds.
- [`docs/changelog.md`](docs/changelog.md) — why things are the way they are: the work, and the bugs found and fixed, that predate this repository's git history.
- [`docs/pqc-review.md`](docs/pqc-review.md) — post-quantum cryptography review and the roadmap the `IKem` interface came from.

When you add a new subsystem or change a convention, update the relevant
file under `docs/` (or add a new one) rather than expanding this file.

## Build

```sh
cmake -S . -B build
cmake --build build --config Debug
```

Builds a shared library by default; pass `-DCERTPP_BUILD_SHARED=OFF` to
build static instead. See [`docs/build.md`](docs/build.md) for the full
option list, install instructions, and the `CERTPP_API` export-macro
mechanics (`__COMPILES_LIBCERTPP__` / `__SHARED_LIBCERTPP__`).

`CMakeLists.txt` collects `src/**/*.cpp` via `file(GLOB_RECURSE ... CONFIGURE_DEPENDS)`,
so a new `.cpp` under `src/` is picked up automatically — no need to list it
in `CMakeLists.txt`.

Test cases go under [`tests/`](tests/), one file per test executable,
mirroring the `include/certpp/`/`src/` path it exercises (globbed into
CMake/CTest automatically, same as `src/`). Tests use
[doctest](https://github.com/doctest/doctest), vendored as a single header
under `third-party/doctest/`. See [`docs/build.md`](docs/build.md) for how
to build/run them. There are no lint commands configured yet.

## Architecture

- `include/certpp.hpp` is the umbrella header consumers include; it
  re-`#include`s the public headers under `include/certpp/`. When adding a
  new public header, add its include here.
- `include/certpp/common.hpp` is the foundation every other header
  includes: it defines `CERTPP_API` and the `certpp::` fixed-width type
  aliases (`uint32_t`, `size_t`, `float32_t`, ...) used throughout instead
  of global-namespace types.
- Each non-template public header under `include/certpp/` has a matching
  `.cpp` under `src/` (e.g. `version.hpp` <-> `src/version.cpp`), created as
  an empty stub up front even before there's out-of-line code to put in it.
  A header that's entirely templates (e.g. `io/span.hpp`) has no `.cpp`.
- Each submodule has its own `include/certpp/<name>/` and `src/<name>/`
  directory, but only some get a nested namespace: `asn1`, `crypto` and
  `x509` nest (`certpp::asn1`, `certpp::crypto`, `certpp::x509`), while
  `io` and `utils` put their types directly in `certpp::`. See
  [`docs/coding-conventions.md`](docs/coding-conventions.md) for the rule
  behind that split and the closing-brace style each form uses.
- An implementation detail that has no place in the public API (e.g. the
  `MemStream` backing `IStream::createMemory`) gets a private header+source
  pair under `src/` instead of `include/certpp/` — see
  [`docs/coding-conventions.md`](docs/coding-conventions.md) for its guard
  and include-path conventions, which differ from public headers.
- `third-party/` vendors dependencies, one subdirectory each, exposed as
  CMake targets by `third-party/CMakeLists.txt` (currently just `doctest`,
  used only by `tests/`, so the root `add_subdirectory(third-party)` is
  gated behind `CERTPP_BUILD_TESTS`). A future non-test dependency (e.g. a
  TLS/crypto backend) follows the same vendor-and-expose-a-target pattern,
  but gets linked from `certpp` itself instead of gated behind that option.

See [`docs/architecture.md`](docs/architecture.md) for the full picture.

## Coding conventions (summary)

Full detail in [`docs/coding-conventions.md`](docs/coding-conventions.md).
Key points that are easy to get wrong by defaulting to generic C++ style:

- Header guards are `#ifndef`/`#define`, not `#pragma once`, named
  `__INCLUDE_CERTPP_<PATH>_HPP__` — use the `kh` snippet in
  `.vscode/my.code-snippets` when creating a new header.
- Type prefixes (public API under `include/certpp/` only — see below):
  `S` for non-template value-type structs (`SVersion`), `T` for *template*
  value-type structs (`TSpan<T>` — don't use `S` just because it's
  otherwise a plain aggregate), `C` for classes with private state (`CTag`),
  `I` for pure-virtual interfaces (`IStream`), `E` for plain enums
  (`ETagClass`), whose enumerators repeat an abbreviation of the enum name
  (`EATAG_*`). The abbreviation isn't a fixed formula — check sibling enums
  in the same header for the one already in use. A concrete instantiation
  that's part of the public API still gets a regular `S`-prefixed alias
  (`SByteSpan = TSpan<uint8_t>`).
- An internal implementation class that lives under `src/` rather than
  `include/certpp/` (e.g. `MemStream`, implementing the `IStream`
  interface) is plain `PascalCase` with **no** type prefix — the
  S/T/C/I/E prefixes mark the public API surface, not every type in the
  codebase.
- Free functions are `PascalCase` (`GetLibraryVersion`); class member
  methods, including simple accessors, are `camelCase` (`isValid`,
  `tagClass`) — don't default one style for both. A `static` helper that's
  local to one header/TU (not part of the public API) may use `camelCase`
  instead (`checkEncodingRule` in `asn1/decoder.hpp`). Private fields get a
  leading underscore (`_flags`); public struct fields don't (`major`).
- A submodule gets its own `include/certpp/<name>/` and `src/<name>/`
  subdirectory. Only give it a nested `namespace certpp { namespace <name>
  { ... } }` block (closed with bare `}`, no trailing comment, unlike the
  single-level `namespace certpp { ... } // namespace certpp`) if it has its
  own naming identity distinct from the rest of the library, like `asn1` —
  `io` is a subdirectory but its types stay directly in `certpp::`.
- Every public declaration gets a Javadoc-style `/** ... */` block with
  `@param`/`@return`; `.cpp` definitions get a short one-line `/* ... */`
  restating the summary instead of repeating the full block.
- `CERTPP_API` is only needed on a type/function with an out-of-line
  definition in a `.cpp` (like `SVersion`) — a type fully defined inline in
  the header (like `CTag`) doesn't need it.
