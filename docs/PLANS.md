# Roadmap

[한국어](PLANS.ko.md)

What `libcertpp` has been asked for and does not have yet. This file tracks
requested work and why it was requested; it is not a wish list. Anything
finished moves out of here and into
[`docs/CONCEPTS.md`](CONCEPTS.md), with the reasoning behind it in
[`docs/HISTORY.md`](HISTORY.md).

For the post-quantum track, which has its own review and phasing, see
[`docs/PQC.md`](PQC.md).

## Automated CI and platform matrix

Add repository CI that builds and tests every supported toolchain instead of
depending on a maintainer's local environment. The initial matrix should cover
Windows with MSVC, Linux with GCC and Clang, and macOS with Apple Clang when a
runner is available. It must exercise both shared and static libraries and
include representative configurations for `CERTPP_WITHOUT_JSON` and the
hardware-acceleration disable switches.

Keep the pull-request matrix bounded: run the primary build and full CTest
suite on every supported operating system, then use scheduled or manually
triggered jobs for the larger configuration matrix and sanitizers. At least
one job must install the library into a clean prefix and build a separate
consumer with `find_package(certpp REQUIRED)` and `certpp::certpp`; a successful
in-tree build alone does not verify the installed package.

This work is complete when the matrix is documented, required jobs gate
changes, sanitizer failures retain actionable logs, and the maintained build
commands in [`docs/BUILDING.md`](BUILDING.md) match the automation.

## Detailed pages

- [Security and performance](roadmap/performance.md), including protected
  payload migration, portable timing hardening, and build integration
- [Not planned](roadmap/not-planned.md)
