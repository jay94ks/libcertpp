# Constant-time and performance work

[한국어](performance.ko.md)

This page contains only work that remains open. Current benchmark results and
methodology live in [Performance](../concepts/performance.md). Completed
optimizations, investigations, and negative results are recorded in
[History](../HISTORY.md) and [Not planned](not-planned.md).

## Security work

- **Finish constant-time prime-curve ECDH and ECDSA signing.** The ladder now
  processes the full group-order width, masked-swaps its registers, and uses no
  secret-indexed fixed-base table. The remaining blocker is `CBigNum` itself:
  it allocates and trims variable-width limbs and its arithmetic has
  operand-dependent cost. A shared fixed-width field strategy is still needed
  across the supported prime curves.
- **Audit ML-DSA signing for timing leakage.** The retry count in
  Fiat-Shamir-with-aborts is data-dependent by design. The current
  implementation zeroizes secret intermediates and avoids secret-indexed
  tables inside an iteration, but it has not had a dedicated timing-side-channel
  review against published Dilithium attacks. See [PQC engineering and
  risk](../pqc/engineering.md).

## Performance investigations

- **Profile DSA on GCC.** On the recorded WSL2 machine, DSA-2048 signing and
  verification were substantially slower under GCC than MSVC even though both
  use the same `CBigNum` backend. Reproduce the gap on bare-metal Linux before
  changing code, then profile the reproduced case.
- **Profile binary curves on GCC.** All ten GF(2^m) curves moved in the same
  direction in the WSL2 comparison, pointing to shared `CGf2m` code. Reproduce
  on bare-metal Linux and isolate the shared cost before proposing an
  optimization.
- **Evaluate a verify-time public-key table.** Signature verification uses a
  variable base, but a certificate issuer key is commonly reused. Measure
  whether caching a table per public key improves that workload without adding
  unacceptable memory or setup cost.

Any optimization begins with a reproducible baseline and a profile. Changes
smaller than the benchmark machine's run-to-run spread are not treated as
wins. Every accepted change must keep the relevant known-answer and negative
tests passing.
