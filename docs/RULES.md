# Project rules

[한국어](RULES.ko.md)

These reflect the conventions already established in the existing headers
and sources (`include/certpp/common.hpp`, `include/certpp/version.hpp`,
`include/certpp/asn1/tag.hpp`, `include/certpp/asn1/decoder.hpp`,
`include/certpp/io/span.hpp`, `include/certpp/io/stream.hpp`,
`src/version.cpp`, `src/common.cpp`, `src/asn1/tag.cpp`,
`src/asn1/decoder.cpp`, `src/io/stream.cpp`, `src/io/memstream.hpp`,
`src/io/memstream.cpp`). Follow them for new code rather than introducing
new styles.

## File layout

- Every header uses a header guard, not `#pragma once`:
  ```cpp
  #ifndef __INCLUDE_CERTPP_<PATH>_HPP__
  #define __INCLUDE_CERTPP_<PATH>_HPP__

  #endif
  ```
  The guard name is derived from the path relative to `include/`, uppercased,
  with non-alphanumeric characters replaced by `_`, wrapped in leading/
  trailing double underscores (e.g. `include/certpp/version.hpp` ->
  `__INCLUDE_CERTPP_VERSION_HPP__`, `include/certpp/asn1/tag.hpp` ->
  `__INCLUDE_CERTPP_ASN1_TAG_HPP__`). This matches the
  `.vscode/my.code-snippets` "C/C++ Default Header Form" snippet (`kh`
  prefix) already used in this repo — use that snippet when creating new
  headers.
- A `.cpp` file includes its matching header first, using the `certpp/...`
  angle-bracket path (e.g. `#include <certpp/version.hpp>`,
  `#include <certpp/asn1/tag.hpp>`), not a relative `"..."` include.
- All public code lives inside `namespace certpp { ... }`.
- Every non-template header under `include/certpp/` gets a matching `.cpp`
  stub under `src/` — the header's `#include` plus the (possibly empty)
  namespace scaffold — created up front even before there's any
  out-of-line code to put in it (see `src/common.cpp`, `src/asn1/tag.cpp`).
  This gives future non-inline additions a home without restructuring, and
  costs nothing since `CMakeLists.txt` globs `src/**/*.cpp` automatically.
  A header that is entirely templates (e.g. `io/span.hpp`'s `TSpan<T>`,
  `TReadOnlySpan<T>`) does **not** get a `.cpp`: template definitions must
  stay visible at the point of instantiation, so there's nothing to put in
  one.
- A submodule that uses a nested namespace (e.g. `asn1`) gets its own
  subdirectory under `include/certpp/` and `src/`. Open the namespace as a
  second top-level block rather than the C++17 `namespace certpp::asn1`
  shorthand:
  ```cpp
  namespace certpp {
  namespace asn1 {

      // ...

  } // namespace asn1
  } // namespace certpp
  ```
  Every close carries a trailing comment naming the namespace it ends, at
  every level — `} // namespace asn1` then `} // namespace certpp` (see
  [Formatting](rules/style.md#formatting)).
- Not every submodule needs a nested namespace. As it stands: **`asn1`,
  `crypto`, `x509`, and `dnssec` nest** (`certpp::asn1`, `certpp::crypto`,
  `certpp::x509`, `certpp::dnssec`), while **`io` and most `utils` types do
  not** — they put their types directly in `namespace certpp { ... }` like
  the top-level headers do. The JSON/BSON API in `utils/json.hpp` is the
  established exception and lives in `certpp::utils`. A
  nested namespace is reserved for a module with its own identity and
  naming scheme distinct from the rest of the library (`asn1`'s tag/enum
  names are ASN.1-specific; `crypto`, `x509`, and `dnssec` likewise), not just
  "lives in a subdirectory" — which is what `io` and most `utils` types are,
  general-purpose plumbing the whole library reaches for unqualified. Follow
  the namespace already established by sibling headers rather than creating
  another exception.
- A directory holding one concrete implementation per file, all of the same
  kind, may name each file by its subject's well-known short-hand instead of
  spelling the type name out in full — e.g. `x509/exts/bc.hpp` for
  `CBasicConstraintsExtension`, `ski.hpp` for
  `CSkiExtension` — when that abbreviation is the
  community-standard one (the same short names certificate-inspection
  tooling and RFCs' own running text use for these extensions), not an
  invented one. This is the exception, not the default: prefer a filename
  that spells out what it defines (see `crypto/asyms/rsa.hpp`) unless an
  established short-hand already exists and the full name would be
  needlessly long across many files in the same directory.

### Internal implementation headers

- A type that exists purely to implement a public interface, with no place
  in the public API, gets a private header+source pair under `src/` instead
  of `include/certpp/` — e.g. `src/io/memstream.hpp`/`.cpp` define
  `MemStream`, the concrete backing for `IStream::createMemory(...)`, which
  consumers only ever see through the `IStream` interface.
- Its header guard is `__SRC_<PATH>_HPP__` (path relative to `src/`), not
  `__INCLUDE_CERTPP_...` — e.g. `src/io/memstream.hpp` ->
  `__SRC_IO_MEMSTREAM_HPP__`. This keeps it visibly distinct from a public
  guard even if the two ever collided.
- Other files under `src/` include it with a relative, double-quoted path
  (`#include "memstream.hpp"`), not the `<certpp/...>` angle-bracket form —
  angle brackets are reserved for headers under `include/`.
- It still includes whichever public header it implements using the
  `<certpp/...>` form (`src/io/memstream.hpp` includes
  `<certpp/io/stream.hpp>`), since that part *is* public API.
- The public-API type-prefix rules (`S`/`T`/`C`/`I`/`E`, see
  [Types](rules/api.md#types)) do not apply to it — that page explains why.

## Detailed pages

- [API design rules](rules/api.md)
- [Source and documentation style](rules/style.md)
- [Versioning and tests](rules/maintenance.md)
