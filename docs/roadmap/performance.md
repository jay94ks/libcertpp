# Security and performance work

[한국어](performance.ko.md)

This page contains only work that remains open. Current benchmark results and
methodology live in [Performance](../concepts/performance.md). Completed
optimizations, investigations, and negative results are recorded in
[History](../HISTORY.md) and [Not planned](not-planned.md).

## Security work

### Locked secret memory

`CSecure::zero()` currently prevents the compiler from removing an explicit
wipe, but it does not keep the containing page out of swap or the Windows page
file. Private keys and secret intermediates also occupy ordinary `COctet`,
`TArray`, and `CBigNum` allocations, so locking an arbitrary caller-provided
span would not provide a sound ownership boundary: memory locks operate on
whole pages, unrelated allocations can share a page, and operating-system lock
counts cannot safely represent independent object lifetimes.

Investigate a dedicated page-backed secure allocation layer rather than adding
`lock()` and `unlock()` calls to arbitrary buffers. The intended platform shape
is `VirtualAlloc` followed by `VirtualLock` on Windows and anonymous `mmap`
followed by `mlock` on Linux. Linux mappings should also use
`MADV_DONTDUMP` and, where supported, `MADV_WIPEONFORK`. Destruction must wipe
the full allocation before unlocking and releasing it. Copying should either
be disabled or make a deep copy directly into another protected allocation;
growth must never stage the secret through an ordinary heap buffer.

The protection contract must expose failure. A best-effort mode may preserve
compatibility by continuing with ordinary memory while reporting that the
allocation is not locked. A required mode must fail key generation or import
when the platform API, Windows working-set limit, or Linux `RLIMIT_MEMLOCK`
prevents locking. Documentation must claim non-pageability only for an
allocation whose lock operation succeeded.

Apply the mechanism in stages:

1. Move long-lived byte-oriented private material such as Ed25519, Ed448,
   X25519, ML-DSA, and ML-KEM keys into the protected buffer.
2. Add protected limb storage for the long-lived private `CBigNum` components
   used by RSA, DSA, ECDSA, and GOST without forcing public arithmetic into the
   secure allocator.
3. Evaluate a per-operation secure arena for nonces, seeds, derived secrets,
   and private arithmetic temporaries. Keep page locking out of the hot loop by
   preparing the arena or key storage once and reusing it.

Tests should use an injectable platform backend to verify lock-before-copy,
wipe-before-unlock, move and resize behavior, required-mode failures, and
best-effort status reporting. Linux integration coverage should check the
locked-byte accounting and fork behavior; Windows coverage should check the
corresponding allocation, lock, unlock, and release sequence.

This feature cannot promise that no secret byte ever reaches persistent
storage. Caller-owned copies, compiler spills outside the protected mapping,
hibernation images, full-memory dumps, debuggers, virtual-machine snapshots,
and storage created before a buffer enters the library remain outside the
allocation's control. Linux dump exclusion and Windows Error Reporting memory
exclusion can reduce dump exposure, but neither replaces host policy for full
dumps, hibernation, and encrypted swap or page files.

Platform references: Microsoft documents the page-file guarantee and resource
limits of [`VirtualLock`](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtuallock),
and the narrower Windows Error Reporting scope of
[`WerRegisterExcludedMemoryBlock`](https://learn.microsoft.com/windows/win32/api/werapi/nf-werapi-werregisterexcludedmemoryblock).
The Linux man-pages document [`mlock`](https://man7.org/linux/man-pages/man2/mlock2.2.html),
including `RLIMIT_MEMLOCK` and the hibernation limitation, and
[`madvise`](https://man7.org/linux/man-pages/man2/madvise.2.html), including
`MADV_DONTDUMP` and `MADV_WIPEONFORK`.

## Performance work

- **Close the Windows Clang full-inventory gaps.** The 2026-10-19 Release
  refresh against OpenSSL 3.6.4 measured RSA-2048 key generation/sign/verify
  at 0.398x/0.875x/0.700x, P-256 key generation at 0.676x, and SHA-384 at
  0.88x. Reproduce each row with focused pinned runs, compare the selected
  Windows kernels and ABI code generation with the faster WSL configurations,
  and bring every directly comparable row back to at least 0.90x. Keep
  randomized RSA key generation separate from steady-operation conclusions.

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
