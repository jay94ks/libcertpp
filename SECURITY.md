# Security policy

[한국어](SECURITY.ko.md)

Report a suspected vulnerability privately to the repository owner through
GitHub's **Security > Report a vulnerability** form. Include the affected
version, a minimal reproducer or malformed artifact when possible, the
security impact, and whether the report may be acknowledged publicly. Do not
open a public issue for an undisclosed vulnerability.

The maintained release line is the latest published `1.x` release. Security
fixes are prepared against that line; older releases may require upgrading.
The project does not promise an embargo deadline, but the maintainer should
acknowledge a complete report, assess reproducibility and impact, prepare a
fix and regression test, and coordinate disclosure before publishing details.

Passing the test suite, interoperability vectors, fuzz targets, and timing
audit tools are engineering evidence rather than a third-party security
audit. The documented limitations in [`specs/pitfalls.md`](specs/pitfalls.md)
remain part of the security contract.
