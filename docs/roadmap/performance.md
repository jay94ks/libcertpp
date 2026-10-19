# Constant-time and performance work

[한국어](performance.ko.md)

This page contains only work that remains open. Current benchmark results and
methodology live in [Performance](../concepts/performance.md). Completed
optimizations, investigations, and negative results are recorded in
[History](../HISTORY.md) and [Not planned](not-planned.md).

## Security work

- **Finish the portable constant-time prime-curve fallback.** Native x86-64
  Clang/GCC builds now keep field coordinates in fixed-width Montgomery limbs,
  scan every private-window candidate, and process the full group-order width.
  The portable fallback still uses `CBigNum`, whose allocation, limb trimming,
  and arithmetic have operand-dependent cost. Replace that fallback or keep its
  variable-time boundary explicit before making a platform-independent claim.
- **Audit ML-DSA signing for timing leakage.** The retry count in
  Fiat-Shamir-with-aborts is data-dependent by design. The current
  implementation zeroizes secret intermediates and avoids secret-indexed
  tables inside an iteration, but it has not had a dedicated timing-side-channel
  review against published Dilithium attacks. See [PQC engineering and
  risk](../pqc/engineering.md).
