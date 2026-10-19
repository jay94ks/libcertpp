# Security and performance work

[한국어](performance.ko.md)

This page contains only work that remains open. Current benchmark results and
methodology live in [Performance](../concepts/performance.md). Completed
optimizations, investigations, and negative results are recorded in
[History](../HISTORY.md) and [Not planned](not-planned.md).

## Security work

### Locked secret memory

`CSecure::alloc()` now provides the dedicated page-backed layer: aligned small
allocations share protected OS mappings. The default first tries the OS large-
page size (`MEM_LARGE_PAGES` on Windows and `MAP_HUGETLB` on Linux), then falls
back to standard pages protected by `VirtualLock` or `mlock` when the large-
page request lacks privilege or reserved pages. `CERTPP_DISABLE_LARGE_PAGE=ON`
uses standard pages directly. Linux applies `MADV_DONTDUMP` where the kernel
exposes it. A released block is wiped before reuse; the last release wipes the
complete page, unlocks a standard-page mapping when needed, and unmaps it.
There is no best-effort ordinary
heap fallback. Lock failure is `ERET_NOMEM`, and key generation or import
propagates that failure. All asymmetric and KEM private-key object shells now
use this allocator.

The remaining work is the storage those objects own indirectly. `COctet`,
`TArray`, and `CBigNum` still allocate their payloads on the ordinary heap, so
locking only the object shell does not protect those dynamic bytes. Copying
and growth of a future protected container must stay inside protected storage
and must never stage the secret through an ordinary heap buffer.

Apply the mechanism in stages:

1. Move dynamically allocated, long-lived byte-oriented private material such
   as ML-DSA and ML-KEM key payloads into a protected buffer. Audit other
   `COctet` and `TArray` members rather than assuming the locked object shell
   also locks their allocations.
2. Add protected limb storage for the long-lived private `CBigNum` components
   used by RSA, DSA, ECDSA, and GOST without forcing public arithmetic into the
   secure allocator.
3. Evaluate a per-operation secure arena for nonces, seeds, derived secrets,
   and private arithmetic temporaries. Keep page locking out of the hot loop by
   preparing the arena or key storage once and reusing it.

Add an injectable platform backend to verify lock-before-use,
wipe-before-unlock, and required-mode failures without depending on host lock
limits. Linux integration coverage should check locked-byte accounting and
fork behavior; Windows coverage should check the corresponding allocation,
lock, unlock, and release sequence.

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
