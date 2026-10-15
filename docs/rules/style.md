# Source and documentation style

[한국어](style.ko.md)

## Formatting

← [Project rules](../RULES.md)

- 4-space indentation, no tabs.
- Opening brace on the same line as the declaration (`struct Foo {`,
  `class Foo {`, `if (...) {`). The exception is a constructor whose body is
  empty/near-empty and whose initializer list already spans a line — the
  opening `{` for the body can go on its own line (see `CTag`'s private
  delegating constructor).
- One blank line between members/methods inside a struct or class.
- `namespace certpp { ... } // namespace certpp` — every namespace close
  carries a trailing comment naming it, at a single level and at every
  level of a nested one:
  ```cpp
  } // namespace asn1
  } // namespace certpp
  ```
  The comment is the point: a bare `}` closing the wrong level still
  compiles, and nothing in the file says which namespace was meant. This
  rule changed — the convention was once a bare `}` for nested closes, and
  three quarters of the tree never followed it, so the tree's own practice
  won on the grounds that it is the one that can be checked.
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

← [Project rules](../RULES.md)

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
- An explicit `@brief` tag on the summary line is an accepted variant, not a
  deviation. All of `x509/` plus `utils/base64.hpp` (16 headers) use it
  consistently, and the older modules consistently don't; either is fine, but
  stay consistent *within a module* rather than mixing the two in one header.
- Inside `.cpp` implementation files, a short `/* ... */` restating the
  declaration's summary is placed directly above each definition (see
  `src/version.cpp`), rather than repeating the full Javadoc block.
