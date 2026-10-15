# Documentation guide

[한국어](README.ko.md)

This page is the map for `libcertpp` documentation. Choose a route by what you
are trying to do; each fact should have one owning document so that summaries
can link to it instead of drifting into competing copies.

For an exhaustive file list, see the [documentation index](INDEX.md).

## Choose a route

| Goal | Start here | Then use |
| --- | --- | --- |
| Evaluate or build the project | [`README.md`](../README.md) | [`BUILDING.md`](BUILDING.md) |
| Review benchmark results | [`concepts/performance.md`](concepts/performance.md) | Remaining work in [`roadmap/performance.md`](roadmap/performance.md) |
| Use the C++ API | [`specs/README.md`](../specs/README.md) | API map, recipes, pitfalls, and compiled examples |
| Contribute a change | [`CONTRIB.md`](../CONTRIB.md) | Architecture, conventions, and build reference below |
| Work as an AI coding agent | [`AGENTS.md`](../AGENTS.md) | The AI section of `CONTRIB.md` and task-relevant documents |
| Understand why a design exists | [`HISTORY.md`](HISTORY.md) | Current state in `CONCEPTS.md` |
| Find planned work | [`PLANS.md`](PLANS.md) | PQ-specific review in `PQC.md` |

## Maintainer documentation

| Document | Owns | Does not own |
| --- | --- | --- |
| [`CONCEPTS.md`](CONCEPTS.md) | Current modules, boundaries, files, and supported behavior | Historical narrative or future work |
| [`RULES.md`](RULES.md) | Source layout, naming, formatting, public comments, and test conventions | Build commands or product usage |
| [`BUILDING.md`](BUILDING.md) | Configure, build, test, install, options, examples, and sanitizers | API recipes |
| [`PLANS.md`](PLANS.md) | Requested work that is still incomplete or explicitly out of scope | Completed feature inventory |
| [`HISTORY.md`](HISTORY.md) | Historical decisions, investigations, measurements, and completed fixes | The concise description of current architecture |
| [`PQC.md`](PQC.md) | PQ design review, validation sources, and implementation phases | General project roadmap |

## Caller documentation

The [`specs/`](../specs) directory is maintained alongside `docs/` and answers
task-oriented API questions:

- [`api-map.md`](../specs/api-map.md) maps a task to headers and types.
- [`recipes.md`](../specs/recipes.md) shows common calls in context.
- [`pitfalls.md`](../specs/pitfalls.md) records calls that look successful but
  are wrong or incomplete.

The [`examples/`](../examples) directory contains compiled walkthroughs.
[`examples/wiki/`](../examples/wiki) contains the compiled source snippets
used to generate one API-reference page per public type. Generated Markdown
under `examples/wiki/snippets/` is output, not maintained documentation.

## Authority when documents disagree

1. Public headers define the API contract and doc comments.
2. Compiled examples demonstrate supported usage.
3. Tests pin behavior and edge cases.
4. `CONCEPTS.md` describes the intended current structure.
5. Caller specs and summaries should be corrected when they disagree with the
   sources above.

Build behavior ultimately comes from `CMakeLists.txt`; `BUILDING.md` is its
maintained explanation. Historical statements in `HISTORY.md` may describe
an older state and should be read in that context.

## Language and generated content

English is the source language. Maintained reader-facing documentation has a
Korean counterpart named `<name>.ko.md`, linked on line 3; the operational
`AGENTS.md` and `CLAUDE.md` entrypoints are exceptions. For paired documents,
update both languages in the same change and keep cross-document links within
the reader's language when a translation exists.

Do not hand-edit generated wiki snippets or generated API pages. The source is
the public header Javadoc plus the matching compiled example; see
[`examples/wiki/README.md`](../examples/wiki/README.md).
