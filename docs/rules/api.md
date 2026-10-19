# API design rules

[한국어](api.ko.md)

## Types

← [Project rules](../RULES.md)

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

← [Project rules](../RULES.md)

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
  - Constant-time/branch-free code (`CSecure::equalsMask`/`select`,
    `CbcTransformer`'s PKCS#7 padding check, the EC/EdDSA scalar-
    multiplication ladders) — collapsing it into a data-dependent-length
    `memcpy`/early-exit comparison would reintroduce a timing side channel.
    These stay as explicit, unconditional loops. Reach for `CSecure`
    (`utils/secure.hpp`) before writing new mask arithmetic: comparing two
    buffers, choosing between two buffers, and clearing one are already
    there, and `std::memcmp` on anything secret-derived is a bug rather
    than a style question — it stops at the first mismatch, so its running
    time leaks the matching prefix's length.
  - Element-wise combines rather than fills or copies — a CBC
    `out[i] = in[i] ^ chain[i]` is neither a `memset` nor a `memcpy`, and
    splitting it into a copy followed by an in-place XOR pass would read
    the block twice to express the same thing.
  - Genuine reversals (`out[i] = in[N-1-i]`) or in-place swaps
    (`CBigNum::reverseBytesInPlace`) — `memcpy`/`memmove` are order-
    preserving only and can't express either.
  - Conditional/filtered copies, e.g. `IRng::fillNonZeroTo()`'s
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

## Span parameters

← [Project rules](../RULES.md)

- An output span is passed as `const SByteSpan&` unless the callee genuinely
  needs to shorten it. The span's `data` is a `uint8_t*`, so the buffer stays
  writable either way; `const` only prevents reassigning the span itself.
- `SByteSpan&` (non-const) is reserved for the callees that really do report a
  shorter length back by assigning `out = SByteSpan(out.data, written)` —
  `IAsymmetricContext::sign()` and `CBase64::finish()` are the examples. If a
  function never executes that assignment, its parameter should be `const`.
- This is not cosmetic. A non-const lvalue reference cannot bind to a
  temporary, so `hasher->finish(SByteSpan(buf, len))` is ill-formed in
  standard C++ — MSVC accepts it as an extension while GCC and Clang reject
  it. `IHasher::finish()` had exactly this problem across 13 call sites and
  broke every non-MSVC build; see `docs/HISTORY.md`'s portability entry.
- The same reasoning applies to input spans: take `const SReadOnlyByteSpan&`,
  never a non-const reference, since nothing can usefully be written back.

## Naming

← [Project rules](../RULES.md)

- Namespaces: lowercase (`certpp`, `certpp::asn1`).
- Types: `PascalCase` with a prefix (public API under `include/certpp/`
  only) — `S` for non-template structs (`SVersion`), `T` for template
  structs (`TSpan<T>`), `C` for classes (`CTag`), `I` for interfaces
  (`IStream`), `E` for enums (`ETagClass`); see "Types" above. An internal
  implementation type under `src/` (e.g. `MemStream`) is `PascalCase` with
  no prefix.
- Enumerators: `SCREAMING_SNAKE_CASE`, prefixed with a short uppercase
  abbreviation of the enum name, which keeps the leading `E`
  (`ETagClass` -> `EATAG_UNIVERSAL`, `EUniversalTags` -> `EAUTAG_BOOLEAN`).
  The abbreviation is not a formula -- check the sibling enums in the same
  header for the one already in use -- see "Types" above.
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
