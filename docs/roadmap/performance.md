# Security and performance work

[한국어](performance.ko.md)

This page contains only work that remains open. Current implementation details
live in [Foundations and core utilities](../concepts/foundations.md), benchmark
results and methodology in [Performance](../concepts/performance.md), and
completed work in [History](../HISTORY.md).

## Security work

### Finish protected secret storage

Current protected-storage behavior, fallback switches, and limits are
documented in
[Foundations and core utilities](../concepts/foundations.md) and
[Security boundaries and pitfalls](../../specs/pitfalls.md). The remaining work
is to move secret payloads that still use ordinary container storage:

1. Audit remaining secret-bearing `COctet`, `CBuffer`, and default-allocator
   `TArray` instances. Move long-lived or reusable owners to `CSecureOctet`,
   `CSecureBuffer`, or `TSecureArray` as appropriate.
2. Add protected limb storage for long-lived private `CBigNum` components in
   RSA, DSA, ECDSA, and GOST without moving public arithmetic into the secure
   allocator.
3. Evaluate a reusable per-operation secure arena for nonces, seeds, derived
   secrets, and private arithmetic temporaries so page locking stays outside
   hot loops.
4. Add an injectable platform backend that verifies lock-before-use,
   wipe-before-unlock, and required-mode failures independently of host lock
   limits. Cover locked-byte accounting and fork behavior on Linux and the
   corresponding allocation, lock, unlock, and release sequence on Windows.

## Performance work

- **Encode the Windows thread dependency in CMake.** Clang/MinGW builds still
  need an explicit `-lwinpthread` for `SecurePool`'s `std::mutex`. Export and
  test that dependency through the maintained CMake package.
- **Finish the portable constant-time prime-curve fallback.** Native x86-64
  Clang/GCC builds use fixed-width Montgomery limbs and full-scan private
  windows. The portable fallback still relies on variable-cost `CBigNum`
  allocation, limb trimming, and arithmetic. Replace it or keep the
  platform-specific timing boundary explicit.
- **Audit ML-DSA signing against published timing attacks.** The existing audit
  tool measures retry behavior, but it does not replace a dedicated review of
  Fiat-Shamir-with-aborts and its data-dependent retry count. See
  [PQC engineering and risk](../pqc/engineering.md).
