# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`libcertpp` is an early-stage C++17 certificate-handling library. Beyond the
foundational scaffolding (type aliases, the `CERTPP_API` export macro, a
version struct), it now has: top-level `STimeSpan`/`SDateTime` calendar-time
types (`time.hpp`); an `io` layer (`TSpan`/`TReadOnlySpan`, `TArray`,
`CBuffer`, `COctet`, the `IStream` interface with a
memory-backed implementation); a `utils` layer (`CBase64`, `CBigNum`,
`CGf2m`, `CMontgomery`); an `asn1` module
(`CTag` tag encode/decode, `CDecoder`/`CEncoder` for reading/writing
BER/CER/DER TLVs plus per-type codecs for BOOLEAN, INTEGER, ENUMERATED,
NULL, OCTET STRING, BIT STRING/NamedBitList, OBJECT IDENTIFIER, character
strings, UTCTime/GeneralizedTime, and SEQUENCE/SET OF); a `crypto` module
(hashing, including MD4 for NTLM/EAP-MSCHAPv2's NT hash, BLAKE2s with both its
native keyed MAC and HMAC-BLAKE2s, and GOST R 34.11-2012 ("Streebog") at both
digest lengths; `CSipHash`, SipHash-2-4 as RFC 9018's DNS server-cookie PRF;
MACs and key derivation (`CHmac`, `CBlake2sMac`, `CPoly1305`, `CHkdf`, and
`CPbkdf2` for the password-based case); a
CSPRNG; asymmetric algorithms -- RSA, DSA, ECDSA over prime and binary curves
plus ECDH key agreement over the prime ones (RFC 5903, on `CEcdsa`'s own
context), Ed25519, Ed448, X25519, and GOST R 34.10-2012 over its nine named
parameter sets -- symmetric ones -- AES, DES, TripleDES, ChaCha20 -- AEADs --
ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM -- and post-quantum ML-KEM
(FIPS 203, `crypto/kems/mlkem.hpp`, holding both the raw-span algorithm and
its `IKem` form), all from scratch); a `dnssec` module (DNSKEY/RRSIG/DS
conversion, RFC 4034); and an `x509` module that
both parses and builds DER/PEM X.509 `Certificate`s
(`CCert`/`CCertBuilder`), CRLs (`CCrlReader`/`CCrlWriter`), OCSP
request/response (RFC 6960) and PKCS#10 certification requests
(`CCertRequest`/`CCertRequestBuilder`, RFC 2986, including the PKCS#9
extensionRequest attribute), including ten concrete extension types
(BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName,
SubjectKeyIdentifier, AuthorityKeyIdentifier, CRLDistributionPoints,
AuthorityInformationAccess, CertificatePolicies, NameConstraints) under
`x509/exts/`, each with a parse/build pair, and single-link signature
verification (`CCert::verifyBy()`, `CCrlReader::verifyBy()`,
`CCertRequest::verify()`); plus certificate collections and the container
formats over them (`CCertCollection` and `IChainFormat` in `x509/chain.hpp`,
with `CPemChainFormat` and `CPfxFormat` -- PKCS#12 over PBES2/AES-256-CBC --
under `x509/chain/`).

What it deliberately does *not* have is **path validation**. The distinction
matters and is easy to lose: `CCertCollection::buildChain()` orders
certificates by who issued whom, and `verifyLinks()` checks each link's
signature, but neither checks validity periods, `basicConstraints`,
`keyUsage`, name constraints, policy constraints or revocation, and neither
decides whether the root is one the caller trusts. An ordered chain out of
this library is a validator's *input*, not its verdict.

See [`docs/architecture.md`](docs/architecture.md) for the full module
breakdown.

## Documentation

Detailed, longer-lived documentation lives under [`docs/`](docs/), not in
this file:

- [`docs/architecture.md`](docs/architecture.md) — module responsibilities and how the pieces fit together.
- [`docs/coding-conventions.md`](docs/coding-conventions.md) — naming, header-guard, formatting, buffer-handling, and doc-comment conventions derived from the existing code.
- [`docs/build.md`](docs/build.md) — full CMake build/install reference, plus the examples and AddressSanitizer builds.
- [`docs/changelog.md`](docs/changelog.md) — why things are the way they are: the work, and the bugs found and fixed, that predate this repository's git history.
- [`docs/pqc-review.md`](docs/pqc-review.md) — post-quantum cryptography review and the roadmap the `IKem` interface came from.
- [`docs/roadmap.md`](docs/roadmap.md) — requested algorithms not implemented yet, and the constant-time/performance work still outstanding.

When you add a new subsystem or change a convention, update the relevant
file under `docs/` (or add a new one) rather than expanding this file.

Two documentation surfaces live outside `docs/`, because they answer a
different question and have a different audience:

- [`specs/`](specs/) is written for someone — or something — *using* the
  library rather than working on it: [`api-map.md`](specs/api-map.md) (which
  header and type for which task), [`recipes.md`](specs/recipes.md) (working
  code for the common jobs), and [`pitfalls.md`](specs/pitfalls.md) (ways to
  call it wrongly that still appear to work). `pitfalls.md` is the one to keep
  current above the others: every entry in it exists because the wrong call
  produced a plausible-looking result.
- The **GitHub wiki** holds the per-type API reference and the things that
  outlive any one version of the code — the integration guide, FAQ and
  troubleshooting. See "The wiki" below; it is generated, not hand-written,
  and the rules for that are not optional.

### Bilingual documentation

Every document has an English original and a Korean translation beside it,
named `<name>.ko.md` — `README.md`/`README.ko.md`,
`docs/architecture.md`/`docs/architecture.ko.md`, and so on. The rules:

- **English is the source of truth.** Write and review changes in the
  English file first; the Korean file is a translation of it, never the
  other way round, and never the place a fact appears first.
- **Both move together.** A change to a document is not finished until its
  `.ko.md` counterpart carries the same change. A Korean file that
  describes an older state of the code is worse than no Korean file,
  because nothing signals that it is stale.
- **Each file links to its counterpart on line 3**, as the only content
  between the `# Title` heading and the opening paragraph:
  `[한국어](README.ko.md)` in the English file, `[English](README.md)` in
  the Korean one. Use the path relative to the file doing the linking.
- **Cross-document links stay inside their language.** A link from one
  Korean document to another points at the other document's `.ko.md`. Only
  link across languages where no translation exists, and then say so
  inline — the existing files use a trailing `(영문)` for that.
- **Translate the prose, not the identifiers.** Type names, function
  names, enumerators, file paths, CMake options, RFC numbers and shell
  commands stay exactly as they are. The same goes for anything inside a
  code fence: translate the comments around a block, never the code in it.
- **Gloss a technical term on first use and then use the English term.**
  The established pattern is `큰 수(big-number)`, `이진체(binary-field)`,
  `임의 정밀도 정수` — Korean gloss in parentheses after the English term,
  or a settled Korean rendering where one exists. Do not invent a Korean
  word for something that is normally written in English (`span`, `nonce`,
  `salt`, `padding`, `constant-time` stay as they are). Words that *do*
  have a settled Korean form are written in Korean: `바이트`, `비트`,
  `해시`, `서명`, `검증`, `인증서`. The test is whether a Korean developer
  would write it that way unprompted, not whether a translation exists.
- **Keep terminology consistent across the whole set.** The guard is a
  헤더 가드 in every file, not sometimes an 인클루드 가드; a byte is 바이트
  everywhere. When one document picks a rendering, the rest follow it — the
  point of the glossary above is that two translated files should never
  disagree about the same word.
- **Prose style is formal `-습니다`**, matching `README.ko.md`.

`examples/README.md` currently has no Korean counterpart; it is the one
exception, and adding one would be welcome.

### Doc comments in the headers

Every public declaration carries a Javadoc `/** ... */` block with
`@param`/`@return` — the coding conventions say so, and the wiki's API
reference is **generated from those blocks**, so a header comment is published
documentation whether or not it was written as such. Three consequences worth
keeping in mind while editing a header:

- **A wrong doc comment ships.** `CTag::ENUMERATED` was documented as the
  UTF8String tag; that line would have gone onto the wiki verbatim. When you
  change what a declaration does, change its block in the same edit.
- **Say the thing that is not obvious from the signature.** The blocks that
  earn their place explain *why* — why `extract()` takes the salt as HMAC's
  key, why `signsMessageDirectly()` is one function rather than four copies,
  why a non-zero NameConstraints `minimum` must be rejected rather than
  honoured. A block that restates the parameter names adds nothing.
- **A `.cpp` definition gets a one-line `/* ... */`** restating the summary,
  not a copy of the header's block. Two copies of a doc comment is two places
  for it to drift.

### The wiki

The wiki's API reference is one page per public class, struct and enum,
**generated** by [`tools/wikigen.py`](tools/wikigen.py) from the headers.
Never hand-edit a type's wiki page: the next regeneration overwrites it, and
the headers are the only copy that cannot be out of date. The design rests on
two things, and both matter:

- **The reference half is extracted, never retyped**, so a page cannot
  disagree with its header by having been written from memory.
- **Every page records the commit it was generated from.** A wiki is not
  versioned with the code, so this is the whole mitigation: a stale page can be
  regenerated, and says which commit it came from so a reader can tell it is
  stale.

The example half is written by hand, in
[`examples/wiki/`](examples/wiki/README.md), and is **compiled and linked** by
the `certpp_example_wiki` build target before publication — a published example
that has never been compiled is a guess. That target also links the way a
downstream consumer does, which is how a declaration missing `CERTPP_API` gets
caught; the test suite structurally cannot see that.

Regenerating, in order:

```sh
cmake --build build --config Debug --target certpp_example_wiki   # must pass first
python tools/exsplit.py                                           # -> examples/wiki/snippets/
python tools/wikigen.py emit <path to the wiki clone>
```

**A new public type needs an example before the wiki is regenerated.**
`wikigen.py` reports any type that has none, and a reference page with no
example is the one thing in this scheme that is worse than no page — it implies
the type was considered and found not worth demonstrating. See
[`examples/wiki/README.md`](examples/wiki/README.md) for the snippet format and
what a good example carries.

Pages that are *not* generated — `Home`, `Integration-Guide`, `FAQ`,
`Troubleshooting` — are hand-written and belong on the wiki precisely because
they outlive any one version of the code. Keep API signatures out of them.

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
  { ... } }` block if it has its own naming identity distinct from the rest
  of the library, like `asn1` — `io` is a subdirectory but its types stay
  directly in `certpp::`. **Every namespace close carries a trailing
  comment naming it**, at every level: `} // namespace asn1` then
  `} // namespace certpp`. A bare `}` can be mis-placed and still compile,
  whereas the comment makes the nesting checkable by eye.
- Every public declaration gets a Javadoc-style `/** ... */` block with
  `@param`/`@return`; `.cpp` definitions get a short one-line `/* ... */`
  restating the summary instead of repeating the full block.
- `CERTPP_API` is only needed on a type/function with an out-of-line
  definition in a `.cpp` (like `SVersion`) — a type fully defined inline in
  the header (like `CTag`) doesn't need it.
