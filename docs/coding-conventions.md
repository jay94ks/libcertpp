# Coding Conventions

These reflect the conventions already established in the existing headers
and sources (`include/certpp/common.hpp`, `include/certpp/version.hpp`,
`include/certpp/asn1/tag.hpp`, `include/certpp/asn1/decoder.hpp`,
`include/certpp/io/span.hpp`, `include/certpp/io/stream.hpp`,
`src/version.cpp`, `src/common.cpp`, `src/asn1/tag.cpp`,
`src/asn1/decoder.cpp`, `src/io/stream.cpp`, `src/io/memstream.hpp`,
`src/io/memstream.cpp`). Follow them for new code rather than introducing
new styles.

## File layout

- Every header uses an include guard, not `#pragma once`:
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
- A submodule (e.g. `asn1`) gets its own subdirectory under `include/certpp/`
  and `src/`, and its own nested namespace, opened as a second top-level
  block rather than the C++17 `namespace certpp::asn1` shorthand:
  ```cpp
  namespace certpp {
  namespace asn1 {

      // ...

  }
  }
  ```
  Unlike a single-level `namespace certpp { ... }`, nested namespace closes
  are bare `}` with no trailing `// namespace ...` comment (see
  "Formatting" below).
- Not every submodule needs a nested namespace: `io` (`include/certpp/io/`,
  `src/io/`) puts its types directly in `namespace certpp { ... }` like the
  top-level headers do — a nested namespace is reserved for a module with
  its own identity/naming scheme distinct from the rest of the library
  (`asn1`'s tag/enum names are ASN.1-specific), not just "lives in a
  subdirectory."
- A directory holding one concrete implementation per file, all of the same
  kind, may name each file by its subject's well-known short-hand instead of
  spelling the type name out in full — e.g. `x509/exts/bc.hpp` for
  `CBasicConstraintsExtension`, `ski.hpp` for
  `CSubjectKeyIdentifierExtension` — when that abbreviation is the
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
- Its include guard is `__SRC_<PATH>_HPP__` (path relative to `src/`), not
  `__INCLUDE_CERTPP_...` — e.g. `src/io/memstream.hpp` ->
  `__SRC_IO_MEMSTREAM_HPP__`. This keeps it visibly distinct from a public
  guard even if the two ever collided.
- Other files under `src/` include it with a relative, double-quoted path
  (`#include "memstream.hpp"`), not the `<certpp/...>` angle-bracket form —
  angle brackets are reserved for headers under `include/`.
- It still includes whichever public header it implements using the
  `<certpp/...>` form (`src/io/memstream.hpp` includes
  `<certpp/io/stream.hpp>`), since that part *is* public API.
- The public-API type-prefix rules (`S`/`C`/`I`/`E`, see "Types" below) do
  not apply to it — see "Types" for why.

## Types

- Use the aliases from `common.hpp` (`certpp::uint32_t`, `certpp::size_t`,
  `certpp::float32_t`, ...) instead of reaching into the global namespace or
  using `int`/`unsigned` directly.
- `common.hpp` itself includes the C headers (`<stddef.h>`, `<stdint.h>`)
  because it's specifically defining aliases for those C types. Everywhere
  else, include the C++ form of a standard header (`<cstring>`, not
  `<string.h>`) and call through the `std::` namespace (`std::memcpy`,
  `std::memset`, `std::memcmp` in `io/span.hpp`), not the bare C name.
- Plain-data/value-type aggregates are declared `struct`. A non-template one
  is prefixed `S` (e.g. `SVersion`, `SDateTime`, `STimeSpan`); a **template**
  one is prefixed `T` instead (e.g. `TSpan<T>`, `TReadOnlySpan<T>` in
  `io/span.hpp`) — the prefix tells you at a glance whether you can name the
  type on its own or need to supply a type argument. Don't reuse `S` for a
  template just because it's otherwise a plain value-type aggregate.
  A concrete instantiation that's part of the public API still gets a
  regular `S`-prefixed alias (`using SByteSpan = TSpan<uint8_t>;`,
  `using SReadOnlyByteSpan = TReadOnlySpan<uint8_t>;`) — callers work with
  `SByteSpan`, not `TSpan<uint8_t>`, wherever a concrete alias exists.
- A lightweight, header-only value-type struct marks every trivial
  constructor/method `constexpr ... noexcept` (see `TSpan`/`TReadOnlySpan`):
  `constexpr` because it can be evaluated at compile time, `noexcept`
  because it can't throw. Reserve plain `inline` (no `constexpr`) for
  methods that call into non-`constexpr` code, e.g. the `std::memcpy`-based
  methods on `TSpan`.
- When a type has both an owning/mutable variant and a read-only view, name
  the read-only one `<Prefix>ReadOnly<Name>` (same `S`/`T` prefix the
  mutable variant uses) and give it an implicit converting constructor from
  the mutable variant (see `TReadOnlySpan(const TSpan<T>&)`).
- Types with private state and behavior are declared `class` and prefixed
  `C` (e.g. `CTag` in `asn1/tag.hpp`): private fields, accessed only through
  public constructors/methods.
- The `S`/`T`/`C`/`I`/`E` prefixes mark the **public API** surface under
  `include/certpp/` specifically — they signal to a consumer what kind of
  type they're looking at. A type that exists only to implement something
  internally and lives under `src/` (see "File layout" -> "Internal
  implementation headers") has no public consumer to signal to, so it's
  plain `PascalCase` with no prefix (`MemStream`, implementing `IStream`,
  in `src/io/memstream.hpp`) even though it has private state like a `C`
  type would.
- A pure-virtual abstract base is declared `class` and prefixed `I` (e.g.
  `IStream` in `io/stream.hpp`). Unlike `C` types, an `I` type typically:
  - exposes a `using <Name>Ptr = std::shared_ptr<I<Name>>;` alias next to it
    (`IStreamPtr`) since consumers hold it through a smart pointer, not by
    value;
  - has `static <Name>Ptr create...(...)` factory method(s) that return a
    concrete (often private, see "File layout" -> "Internal implementation
    headers") implementation, rather than exposing constructible
    implementation types;
  - marks operations that not every implementation supports as virtual
    methods with a default body returning `ERET_NOTIMPL` (e.g.
    `IStream::trimExcess()`, `IStream::flush()`) instead of pure virtual,
    reserving `= 0` for operations every implementation must provide
    (`seek`, `read`, `write`, `close`);
  - overloads a name across a getter and a setter rather than using
    separate `getX`/`setX` names, when both make sense (`IStream::length()
    const` returns the length, `IStream::length(SizeType)` tries to set it
    and returns an `ERetCode`; same for `position()`/`position(SizeType)`).
- Enums are declared as a plain `enum` (not `enum class`) and prefixed `E`
  (e.g. `ETagClass`, `EUniversalTags`). An enum whose values benefit from a
  compact/stable representation specifies an explicit underlying type
  (`enum ERetCode : uint8_t { ... }` in `common.hpp`); otherwise it's left
  to default `int`.
  Enumerators are prefixed with a short uppercase abbreviation of the enum
  name, and an `..._INVALID` sentinel is included where the type has an
  invalid/unset state:
  ```cpp
  enum ETagClass {
      EATAG_INVALID          = 0xFF,  // --> Invalid tag.
      EATAG_UNIVERSAL        = 0,
      EATAG_APPLICATION      = 1u << 6,
      // ...
  };
  ```
  The abbreviation isn't derived by a fixed formula — it's whatever reads
  clearly for that enum, and two enums in the same header can pick
  different lengths (`asn1/tag.hpp`: `ETagClass` -> `EATAG_*`,
  `EUniversalTags` -> `EAUTAG_*`; `asn1/decoder.hpp`: `EEncodingRule` ->
  `EAENC_*`, `EDecoderStatus` -> `EDEC_*`). Check sibling enums in the same
  header before inventing a new one. Give each enumerator a trailing
  `// --> Description.` comment when the value isn't self-explanatory,
  column-aligned with the surrounding entries; if every enumerator needs
  the same short explanation, a block comment above the `enum` listing them
  (see `EEncodingRule`) is fine instead of repeating it per line.
- A type or free function needs the `CERTPP_API` annotation (see
  `common.hpp`) only when it has members/definitions that live out-of-line
  in a `.cpp` file — e.g. `SVersion` (its comparison operators are defined
  in `version.cpp`). A type that is fully defined in the header, with every
  method inline (e.g. `CTag`), does not need `CERTPP_API`: there is no
  out-of-line symbol to export/import.

## Buffer handling

- Never fill or copy a `TArray`/`CBuffer`/raw-array byte-or-element range
  one element at a time in a loop. Get a raw pointer (`toPtr()`/`begin()`,
  whichever the type exposes) and use `std::memset` for a fill or
  `std::memcpy`/`std::memmove` for a copy instead — a sequential
  per-element loop is both slower and less obviously correct than one bulk
  call stating the same intent. Prefer building a small fixed-size array on
  the stack once and writing it in a single bulk call over repeated
  per-element container writes, for the same reason.
- The two halves of that rule are separable, and only the *bulk-call* half
  has exceptions. Where a loop genuinely has to stay a loop (the cases
  below), it still reaches its data through a raw pointer hoisted out of
  the loop rather than through `operator[]` on the container each
  iteration — `CbcTransformer::processBuffered()` is the worked example:
  its CBC XOR combines and its constant-time padding scan are still
  explicit per-byte loops, but every one of them indexes a `uint8_t*` taken
  once at the top.
- The bulk-call half does **not** apply to:
  - Constant-time/branch-free code (`CbcTransformer`'s PKCS#7 padding
    check, the EC/EdDSA scalar-multiplication ladders) — collapsing it into
    a data-dependent-length `memcpy`/early-exit comparison would reintroduce
    a timing side channel. These stay as explicit, unconditional loops.
  - Element-wise combines rather than fills or copies — a CBC
    `out[i] = in[i] ^ chain[i]` is neither a `memset` nor a `memcpy`, and
    splitting it into a copy followed by an in-place XOR pass would read
    the block twice to express the same thing.
  - Genuine reversals (`out[i] = in[N-1-i]`) or in-place swaps
    (`CBigNum::reverseBytesInPlace`) — `memcpy`/`memmove` are order-
    preserving only and can't express either.
  - Conditional/filtered copies, e.g. `CRng::fillNonZero()`'s
    reject-zero-bytes loop — not unconditional, so not a `memcpy`.
  - Per-round-indexed schedule data (AES/DES/3DES round-key arrays) when
    genuinely indexed by round rather than treated as a flat byte buffer;
    a straight index-for-index copy of such an array is still
    `memcpy`-eligible, but a *reordering* of it (DES/3DES's decrypt-side
    key-schedule reversal) is a reversal, per the point above.
  - A `TArray<uint8_t>&`/`TArray<uint8_t>` parameter required by an
    existing public-header-declared function signature (e.g.
    `CEcCurve::encodePoint`, `CGf2m::toBigEndian`, `CHex::decode`) — only
    file-local/private helper signatures get retyped freely; changing a
    public signature is a separate, larger decision.
- `TArray`, `CBuffer`, and `COctet` aren't interchangeable containers
  picked by habit — pick by the role the data plays at its actual call
  sites, not by which RFC/spec step name it happens to carry:
  - `CBuffer` is for a working byte buffer en route to a result: resize
    once (or a small, bounded number of times), fill/`memcpy` into it,
    read it back as a span. A `TArray<uint8_t>` being used this way — i.e.
    as a buffer, not as a logical sequence of distinct elements — should
    be retyped to `CBuffer`.
  - `COctet` is for fixed-length data that either *is* the deterministic
    result of an `encode`/`decode` operation, or gets stored/loaded as a
    unit (a key blob, a digest, a serialized TLV's content).
  - `TArray<T>` stays `TArray<T>` for an actual sequence of logically
    distinct elements (e.g. `TArray<SKeySizeSpec>`), not for a byte buffer.

## Naming

- Namespaces: lowercase (`certpp`, `certpp::asn1`).
- Types: `PascalCase` with a prefix (public API under `include/certpp/`
  only) — `S` for non-template structs (`SVersion`), `T` for template
  structs (`TSpan<T>`), `C` for classes (`CTag`), `I` for interfaces
  (`IStream`), `E` for enums (`ETagClass`); see "Types" above. An internal
  implementation type under `src/` (e.g. `MemStream`) is `PascalCase` with
  no prefix.
- Enumerators: `SCREAMING_SNAKE_CASE`, prefixed with the enum's `E`-stripped
  abbreviation (`EATAG_UNIVERSAL`, `EAUTAG_BOOLEAN`) — see "Types" above.
- Free functions: `PascalCase` (`GetLibraryVersion`). A `static` helper
  that's local to one header/translation unit rather than part of the
  public API may use `camelCase` instead (`checkEncodingRule` in
  `asn1/decoder.hpp`) — the `PascalCase` rule is about signaling "this is
  callable API," which doesn't apply to a file-private helper.
- Class member methods: `camelCase`, including simple accessors/predicates
  (`isValid`, `isConstructed`, `tagClass`, `value` on `CTag`) — this differs
  from the `PascalCase` used for free functions.
- Private member fields: `camelCase` with a leading underscore (`_flags`,
  `_value` on `CTag`). Public fields on plain `S`-structs have no prefix
  (`major`, `minor`, `patch` on `SVersion`).
- Constructor parameters / local variables: `camelCase`, often abbreviated
  consistently with the field they initialize (`maj` -> `major`).
- Constants: `SCREAMING_SNAKE_CASE` (`HEADER_VERSION`, `LIBRARY_VERSION`),
  including `private: static constexpr` bit-mask/flag constants on a class
  (`MASK_CLS`, `FLAG_INVALID` on `CTag`).
- A well-known OID a class exposes as a constant (e.g. a KeyPurposeId or
  access-method OID) is named `OID_<Name>` (`OID_SERVER_AUTH`,
  `OID_OCSP_METHOD`, `OID_ANY_POLICY`) — the `OID_` prefix, not a trailing
  `_OID` suffix. This doesn't apply to a class's *own* defining OID (the one
  `IExtension::create()` dispatches on): that one is simply named `OID`
  (`CBasicConstraintsExtension::OID`), since there's exactly one and no
  other name it could be confused with.
- A public constant whose natural `SCREAMING_SNAKE_CASE` name collides with
  a C/C++ standard library macro gets a trailing underscore instead of a
  different name, so it still reads as "the ASN.1 thing with that name"
  (`CTag::Shortcut`'s `NULL_` avoids `<cstddef>`'s `NULL`; `TIME_UTC_`
  avoids `<ctime>`'s `TIME_UTC`, used by `timespec_get`). This isn't
  theoretical: `TIME_UTC` compiled fine until a header that happens to
  transitively include `<ctime>` (doctest's timer, in `tests/`) got
  included first, and `TIME_UTC` silently expanded to the macro's `1`
  instead of naming the constant, breaking the declaration. Because the
  collision depends on include order, it can compile fine for a long time
  and then break from an unrelated change elsewhere -- rename proactively
  for any constant whose name might plausibly exist in a standard header.
- Macros: `SCREAMING_SNAKE_CASE` with a `CERTPP_` or `__...__` prefix
  depending on purpose — public feature macros use `CERTPP_` (`CERTPP_API`);
  build-configuration switches consumers/build scripts define use double
  underscores (`__SHARED_LIBCERTPP__`, `__COMPILES_LIBCERTPP__`).

## Formatting

- 4-space indentation, no tabs.
- Opening brace on the same line as the declaration (`struct Foo {`,
  `class Foo {`, `if (...) {`). The exception is a constructor whose body is
  empty/near-empty and whose initializer list already spans a line — the
  opening `{` for the body can go on its own line (see `CTag`'s private
  delegating constructor).
- One blank line between members/methods inside a struct or class.
- `namespace certpp { ... } // namespace certpp` — a single-level namespace
  closes with a trailing comment naming it. A nested namespace (submodule)
  closes each level with a bare `}` instead (see "File layout" above).
- Access specifiers (`private:`/`public:`) are repeated to group related
  members rather than written once each: e.g. `CTag` groups its constants
  under one `private:`, its fields under another, its public constructors
  under `public:`, its private delegating constructor under its own
  `private:`, then the rest of its public constructors/methods.
- Trivial single-expression accessor methods defined inline in the class
  body are marked `inline` explicitly, even though in-class definitions are
  implicitly inline (`inline bool isValid() const { ... }`).
- A class may expose a private, non-default constructor purely for other
  constructors to delegate to (`CTag(uint8_t flags, uint32_t value)`),
  keeping shared initialization/validation logic in one place.
- Source/header content is plain ASCII — no em-dash, curly quotes, or other
  non-ASCII punctuation. These files are saved as UTF-8 without a BOM, and
  MSVC's default (system-codepage) source encoding on a non-English Windows
  install misreads a stray non-ASCII byte, emitting a `C4819` warning; use a
  plain double-hyphen (`--`) where you'd otherwise reach for an em-dash.
- A bare `// --` line separates logical sub-groups within a declaration body
  (e.g. splitting `ERetCode`'s general-purpose codes from its more specific
  ones in `common.hpp`, or `CTag`'s tag-number constants from its
  continuation-flag constants in `tag.hpp`) — it groups without describing
  what follows, unlike the `// --> Description.` form below.
- A `// -->` comment placed directly above a statement explains a
  non-obvious *why* for that specific line (see `MemStream::reserve`'s
  `// --> Align the new capacity to the SIZE_ALIGN boundary.`, or
  `IStream`'s `// --> Forward declaration of the IStream interface.`) — the
  same marker used for enumerator descriptions (see "Types" above), reused
  here for inline statement comments.

## Documentation comments

- Every public struct, method, and free function gets a Javadoc-style block
  comment immediately above it:
  ```cpp
  /**
   * One-line summary of what this does.
   * @param name Description of the parameter.
   * @return Description of the return value.
   */
  ```
  Omit `@param`/`@return` for trivial declarations, but keep the one-line
  summary. This includes non-trivial `private:` members too (e.g. `CTag`'s
  private delegating constructor) — `private` doesn't exempt a declaration
  from a summary comment, only very short one-liner accessors do (`CTag`'s
  `isValid`/`value`/... getters use a one-line summary with no `@return`).
  A blank ` *` line between the summary and the first `@param`/`@return`
  tag is common in newer headers (`span.hpp`) though not required — earlier
  ones (`version.hpp`) run the summary straight into the tags.
- Inside `.cpp` implementation files, a short `/* ... */` restating the
  declaration's summary is placed directly above each definition (see
  `src/version.cpp`), rather than repeating the full Javadoc block.

## Versioning

- `HEADER_VERSION` (in `version.hpp`) and `LIBRARY_VERSION` (in
  `version.cpp`, returned by `GetLibraryVersion()`) must be bumped together
  when the ABI/API changes, so consumers can detect a header/binary
  mismatch by comparing the two.

## Tests

- All test cases live under `tests/`, not next to the code they test. A
  test file mirrors the `include/certpp/`/`src/` path of what it exercises
  (`tests/asn1/decoder.cpp` tests `asn1/decoder.hpp`/`decoder.cpp`); an
  integration/round-trip test spanning multiple headers still lives under
  the relevant module directory (`tests/asn1/roundtrip.cpp`), just without
  a 1:1 header match. `CMakeLists.txt` globs `tests/**/*.cpp` the same way
  it globs `src/**/*.cpp` (see [build.md](build.md)), so a new test file
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
