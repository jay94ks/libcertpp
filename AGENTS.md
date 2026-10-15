# AGENTS.md

Repository instructions for AI coding agents working on `libcertpp`.

## Required reading

Read [`CONTRIB.md`](CONTRIB.md), especially
[For AI coding agents](CONTRIB.md#for-ai-coding-agents), before making a
change. It defines the shared workflow, agent-specific responsibilities,
documentation rules, validation expectations, and review checklist.

Use [`docs/README.md`](docs/README.md) to select the longer documents relevant
to the task. At minimum:

- code changes: [`docs/RULES.md`](docs/RULES.md);
- module or public-surface changes: [`docs/CONCEPTS.md`](docs/CONCEPTS.md);
- build, test, or installation work: [`docs/BUILDING.md`](docs/BUILDING.md);
- caller-visible behavior: [`specs/README.md`](specs/README.md), especially
  [`specs/pitfalls.md`](specs/pitfalls.md).

Do not copy long-lived project documentation into this file. Update the owning
document identified by `docs/README.md` and keep this file focused on rules an
agent must apply while editing the repository.

## Repository orientation

`libcertpp` is a C++17 certificate and cryptography library implemented from
scratch. Its major public areas are ASN.1, cryptography, DNSSEC, X.509,
container formats, and the top-level I/O and utility types. The current module
inventory and file map live in `docs/CONCEPTS.md`; verify details there and
in the headers instead of relying on a summary remembered from an earlier
revision.

The source layout has several rules that are easy to miss:

- `include/certpp.hpp` is the umbrella header. Add every new public header to
  it.
- A non-template public header under `include/certpp/` normally has a matching
  source under `src/`; a fully templated header does not need an empty source.
- Internal implementation types stay under `src/` and use plain `PascalCase`,
  without the public `S`/`T`/`C`/`I`/`E` prefixes.
- `asn1`, `crypto`, `x509`, and `dnssec` have nested namespaces. `io` and most
  `utils` types live directly in `certpp::`; the JSON/BSON API is the existing
  `certpp::utils` exception. Verify new placement against the coding
  conventions and sibling headers.
- CMake discovers ordinary source and test files through recursive globs. Some
  tests of private crypto units use explicit source lists; consult
  `docs/BUILDING.md` before changing those lists.

## Editing rules

- Inspect the worktree and nearby implementation before editing. Preserve
  pre-existing changes and follow the established local pattern.
- Use the naming, header guard, formatting, span, buffer, namespace-closing,
  and comment rules in `docs/RULES.md`.
- Public free functions use `PascalCase`; member functions use `camelCase`;
  private fields begin with `_`.
- Every public declaration needs an accurate Javadoc block. An out-of-line
  definition in a `.cpp` gets a short summary comment rather than a duplicate
  Javadoc block.
- Apply `CERTPP_API` only where an out-of-line public symbol must cross the
  shared-library boundary. Verify this against sibling declarations and the
  build reference.
- Keep changes narrow and complete. Update declarations, definitions, tests,
  examples, and caller documentation together when the contract changes.
- Do not create a Git commit or push to a remote unless the user explicitly
  requests that action. A request to edit, fix, validate, or finish work does
  not imply permission to commit or push. Treat committing and pushing as
  separate actions: a request to commit does not authorize a push, and a
  request to push does not authorize creating additional commits.

## Cryptographic and encoding changes

Round-trip tests against this library itself are insufficient. Use published
known-answer vectors, a second established implementation, or real third-party
artifacts. Add negative controls for malformed input, altered tags or
signatures, non-canonical encodings, and boundary lengths as appropriate.

Do not claim constant-time behavior from timing measurements alone. Preserve
the distinction documented in the headers and `specs/pitfalls.md` between code
that is structured to be constant-time and code, such as `CBigNum`, that is
not. Record any security or interoperability limit in the relevant public doc
comment and caller-facing specification.

Certificate chain ordering and link-signature checks are not certification
path validation. Describe a path as validated only after `CPathValidator`
checks it against an explicit `CTrustStore`. Its core result covers the policy
fields documented in `x509/validator.hpp`; it does not imply live revocation or
RFC 5280 policy-tree processing.

## Documentation and wiki

Both `docs/` and `specs/` are maintained documentation. Treat changes to either
tree as product changes: keep them accurate, review their links, and update
them when code changes invalidate their claims. `docs/` owns maintainer-facing
architecture, rules, build instructions, plans, and history; `specs/` owns the
caller-facing API map, recipes, and misuse guidance. A public API change must
audit both trees and update every affected owner in the same change.

Follow these documentation rules:

- English is the source of truth. Update its `.ko.md` counterpart in the same
  change and keep cross-document links within the same language.
- Keep `docs/` root files as high-level entry points. Put detail in a topical
  subdirectory and group related sections into a coherent page; do not create
  a separate file for every small subsection.
- Use short, stable filenames. When a maintained document is renamed or
  replaced, remove the old file and update every repository reference to the
  new page or its exact section.
- Give each fact one owning document. Other pages should summarize briefly and
  link to that owner instead of copying a second version that can drift.
- When adding, moving, or removing a maintained page, update the relevant
  `README.md` and `README.ko.md` index and verify all relative links and section
  anchors.
- Keep current behavior out of `HISTORY.md` when it belongs in `CONCEPTS.md`,
  and keep future work out of both when it belongs in `PLANS.md`.

Follow the document ownership map in `docs/README.md`. Generated files under
`examples/wiki/snippets/` are not part of either maintained tree and are not
translated or hand-edited.

The wiki API reference is generated from public-header Javadocs and compiled
examples under `examples/wiki/`. A new public type needs an example before wiki
generation. The publication sequence is documented in
`examples/wiki/README.md`; its essential order is:

```sh
cmake --build build --config Debug --target certpp_example_wiki
python tools/exsplit.py
python tools/wikigen.py emit <path-to-wiki-clone>
```

Do not publish or hand-edit a generated wiki API page as though it were the
source.

## Validation

For an ordinary code change, the baseline validation is:

```sh
cmake -S . -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Use targeted tests while iterating, then run the full suite when shared code,
public headers, build settings, or cross-module behavior changes. Use the
additional configurations in `docs/BUILDING.md` when the change affects static
linking, installation, hardware fallbacks, feature switches, or memory safety.

Report only commands that actually ran and distinguish test failures from
environmental or pre-existing failures.

## Special generated arithmetic

`tools/fe_square_gen.cpp` generates and verifies the merged factors used by
`Fe25519::square()`. The alternating radix applies asymmetric corrections, and
previous hand-derived factors were wrong. Change the generator and use its
self-checks; do not hand-edit the generated squaring expressions.
