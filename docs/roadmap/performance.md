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
complete mapping. The pool retains at most one wiped standard page in the
locked state for reuse; excess standard pages and large-page mappings are wiped
immediately before they are unlocked when needed and unmapped.
There is no best-effort ordinary
heap fallback. Lock failure is `ERET_NOMEM`, and key generation or import
propagates that failure. All asymmetric and KEM private-key object shells now
use this allocator.

The first indirect owners have also moved to protected storage. ML-DSA and
ML-KEM retain encoded private keys in `CSecureOctet`; symmetric-key objects use
the same type for raw key bytes. Their generation buffers, CBC/RSA transform
buffers that can retain plaintext, and other byte-oriented secret workspaces
use `CSecureBuffer`. AES/ARIA key schedules and ML-DSA polynomial temporaries
use `TSecureArray<T>`. Copying and growth stay inside the selected allocator;
`wrap()` remains caller-owned storage.

The remaining work is the storage still owned by ordinary containers.
`CBigNum`, `COctet`, and default-allocator `TArray` instances allocate their
payloads on the ordinary heap. Locking their object shell does not protect
those dynamic bytes. `CERTPP_DISABLE_SECURE_MEM=ON` intentionally changes every
`CSecure` allocation back to ordinary aligned heap storage, without page
locking or wipe-on-release; this compatibility mode is exposed by
`GetLibraryVersion().isSecureMemory()`.

Apply the mechanism in stages:

1. Audit the remaining secret-bearing `COctet`, `CBuffer`, and default
   `TArray` instances and migrate each long-lived or reusable owner to
   `CSecureOctet`, `CSecureBuffer`, or `TSecureArray` as its role requires.
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

- **Encode the Windows thread dependency in CMake.** The benchmark build
  currently supplies `-lwinpthread` explicitly to executable and shared-library
  link steps because `SecurePool` uses `std::mutex`. Make that dependency part
  of the maintained CMake configuration before the next full inventory refresh.

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
