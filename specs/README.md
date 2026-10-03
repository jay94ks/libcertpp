# specs/ — reference material for agents using libcertpp

[한국어](README.ko.md)

These documents are written for an AI agent (or any newcomer) that has to *use*
`libcertpp` to get a job done, as opposed to working on the library itself.
They answer "which header, which type, which call, and what will silently go
wrong".

If you are changing the library rather than calling it, you want
[`CLAUDE.md`](../CLAUDE.md), [`docs/architecture.md`](../docs/architecture.md)
and [`docs/coding-conventions.md`](../docs/coding-conventions.md) instead.

| Document | What it is for |
| --- | --- |
| [`api-map.md`](api-map.md) | "I need to do X — which header and type?" A task-to-API index. |
| [`recipes.md`](recipes.md) | Working code for the twenty-odd things callers actually do. |
| [`pitfalls.md`](pitfalls.md) | The ways this library can be used wrongly and still appear to work. Read this one. |

## How to trust what is written here

Every signature and type name in these files was read out of the headers, not
recalled. They can still drift, so:

- **The headers are the source of truth**, and they carry full Javadoc blocks
  with `@param`/`@return` on every public declaration. When a spec and a header
  disagree, the header is right and the spec is a bug.
- **`examples/` is the other source of truth**, and a stronger one in one
  respect: it is compiled by the build (`CERTPP_BUILD_EXAMPLES=ON`, on by
  default), so its idioms cannot rot silently the way a snippet in a Markdown
  file can. Where a recipe here and an example disagree, prefer the example.
- **`tests/` shows the contract under adversarial conditions.** If you need to
  know whether some edge case is handled, the test for that unit usually
  answers it directly, and it answers it in code that runs.

To re-verify a signature quickly: `grep -n "<name>" include/certpp/**/*.hpp`.

## Conventions you need to know before reading any snippet

These are not stylistic; misreading them produces code that does not compile or
quietly misbehaves.

- **Types live in `certpp::`, with `certpp::crypto::`, `certpp::asn1::`,
  `certpp::x509::` and `certpp::dnssec::` for those modules.** `io` and `utils`
  types sit directly in `certpp::`.
- **Include `<certpp.hpp>`** for everything, or the individual headers if you
  prefer; the umbrella pulls in all public headers.
- **Spans do not own memory.** `SReadOnlyByteSpan` is `{ const uint8_t* data;
  size_t size; }` and `SByteSpan` is the mutable form. You allocate; the
  library writes.
- **An output span is both an input and an output.** You pass in the buffer you
  have and its capacity; on success the callee *narrows* `size` to what it
  actually wrote. So read `out.size` after the call rather than assuming it is
  still your capacity. This is why output spans are passed as `SByteSpan&` in
  the places where the callee truncates.
- **`ERetCode` is the error type**, with `ERET_OK == 0`. Some newer APIs return
  `bool` instead; the header says which, and a `bool`-returning call never
  reports *why* it failed, so check the preconditions yourself.
- **Prefix letters are load-bearing**: `S` is a value struct, `T` a template
  struct, `C` a class with private state, `I` a pure-virtual interface, `E` a
  plain enum. `IFooPtr` is always `std::shared_ptr<IFoo>`.
- **`certpp::uint32_t`, `certpp::size_t`** and friends are the library's own
  fixed-width aliases from `common.hpp`. They are the same underlying types;
  you do not have to use them in your own code.

## What this library does not do

Worth knowing up front, so you do not go looking:

- **No certification-path validation.** `CCert::verifyBy()` checks one
  signature, one link. Validity periods, `basicConstraints`, name constraints,
  policy constraints, revocation and trust-anchor selection are all yours.
  `x509/chain.hpp` orders certificates into a chain and says plainly that
  ordering is not validating.
- **No revocation checking against a live responder.** CRLs and OCSP responses
  can be parsed and built; fetching and deciding is yours.
- **No audited constant-time guarantee.** Parts are constant-time by
  construction and say so in their doc comments (`Fe25519`, X25519's ladder,
  `CSecure`, GHASH, every tag comparison). Parts are explicitly not
  (`CBigNum`, and therefore prime-curve ECDSA/ECDH). No third-party timing
  audit has been done. See [`pitfalls.md`](pitfalls.md).
- **No third-party cryptography.** Everything is implemented in this
  repository, which is a design goal and also a reason to weigh the previous
  point carefully for adversarial deployments.
