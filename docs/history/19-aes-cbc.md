# AES-CBC register chaining

[한국어](19-aes-cbc.ko.md)

## AES-CBC: the chaining value never needed to leave a register

← [History](../HISTORY.md)

Following the roadmap's P8. The result is the widest thing that has been closed
so far -- AES-256-CBC went from 0.53x OpenSSL to 0.94x -- and the reason it
closed is worth recording, because it is the opposite of the seven attempts that
came before it.

#### The gap was the interface, not the cipher

AES-256-CBC sat at 644 MiB/s on MSVC against OpenSSL's 1364, which is an odd
place for a cipher with its own hardware instruction to be. The temptation is
to assume the AES implementation is slow. It is not: `AesCore::encryptBlock()`
dispatches to AES-NI and the block arithmetic is a handful of instructions. The
cost is in what the caller does with the answer.

`ISymmetricTransformer` hands the transformer a block at a time, so
`CbcTransformer::processBuffered()` called `_blockFn` once per block. Each call
loaded the block, ran the rounds, stored the ciphertext into the output buffer
and returned -- after which `processBuffered()` `memcpy`'d that ciphertext into
`_chain` so the next block's XOR could read it back. Two loads and two stores
per block, every one of them on a value that is a pure function of registers:
the chain is `C_{i-1}`, which the AES instruction has just produced and which
the next block's XOR needs. It goes out to memory and comes back for no reason
except that the interface puts the cipher behind a function call.

On a serial chain that is the whole story. Block *i+1* cannot begin until block
*i*'s output exists, so those memory operations are not overlappable latency;
each one is added to the critical path directly. AES-NI's AESENC is 4 cycles
throughput on a serial chain and the load-to-use and store-to-load round trips
are the same order -- which is why the measured cost was 84 cycles a block
against the ~45 the instruction sequence itself needs.

#### Where the bulk path went, and the three shapes that were tried first

The change is `AesCore::encryptCbcBulk()`: one loop that holds the chaining
value in a `__m128i`, XORs each plaintext block in, runs the rounds, stores the
result, and moves the result back into the chain register without ever
touching memory. It is called through an optional `BulkBlockFn` that
`CbcTransformer` accepts alongside its per-block `BlockFn`, and empty for every
cipher that cannot supply one.

The deliberate design decision was to put the loop inside
`processBuffered()`'s existing whole-block loop rather than to build a second
transformer for AES. A `CbcTransformer` carries a surprising amount of
machinery: chunking independence across `transform()` calls, the output-space
pre-check that returns `ERET_NOSPC` only on a final call, remainder buffering
so a partial block waits for its tail, and constant-time PKCS#7 validation.
Duplicating any of that would mean two places to get it wrong, so instead the
bulk function replaces only the loop body's arithmetic. Everything above it --
the space check, the chain write-back, the remainder, the padding -- is exactly
where it was. A bulk run is indistinguishable from an equivalent run of single
blocks except in speed, and no caller can tell which one ran.

Three other shapes were tried and are not in the tree, all of them for the same
underlying reason:

- **Specializing `CbcTransformer` per cipher** so AES's transformer could hold
  the round keys and chain as members. Measured *slower* than the function
  pointer it replaced, because it added a call layer on top of the
  `std::function` boundary that already existed.
- **Templating the transformer on block size** to hoist the round-key loads out
  of the per-block loop. 7% slower, and reverted.
- Letting each cipher hand the transformer a whole cipher-mode function and
  moving the CBC chaining itself down there. Rejected before implementation:
  `AesCore` is documented as the raw block cipher with no mode, deliberately,
  because AES-GCM needs the same block function at arbitrary counter blocks and
  would otherwise have to build a CBC just to reach it.

#### Measured back-to-back, medians of three

The before/after was measured in the same build directory within the same
minutes, by stashing `src/crypto/syms/`, rebuilding, timing, unstashing,
rebuilding and timing again -- not taken from the README's earlier figures and
the new run. On a machine whose spread between runs of a single side is 11--25%,
comparing a number from one session against a number from another is not a
comparison.

| | before | after | |
|---|---|---|---|
| AES-128-CBC, MSVC | 673.3 MiB/s | 1442.4 MiB/s | 2.14x |
| AES-192-CBC, MSVC | 617.1 MiB/s | 1234.9 MiB/s | 2.00x |
| AES-256-CBC, MSVC | 574.0 MiB/s | 1111.9 MiB/s | 1.94x |
| AES-128-CBC, GCC | 847.2 MiB/s | 1717.9 MiB/s | 2.03x |
| AES-192-CBC, GCC | 775.0 MiB/s | 1515.3 MiB/s | 1.95x |
| AES-256-CBC, GCC | 717.2 MiB/s | 1319.9 MiB/s | 1.84x |

AES-256-GCM is untouched at 473 MiB/s on GCC, within noise of 465, which is the
expected result and worth having measured: GCM uses `AesCore`'s block function
but never enters the CBC path, and GHASH rather than the cipher is its
bottleneck. Nothing in `AesCore`'s per-block dispatch changed.

The portable build (`CERTPP_DISABLE_HWACCEL_AES`) offers no bulk path at all —
`AesCore::hasAesNi()` reports false there — and passes the same 129-test suite.

#### What the verification can and cannot see

`tests/crypto/syms/aes.cpp` now compiles `src/crypto/syms/aescore.cpp` in
directly and holds the bulk path against `AesCore::encryptBlockPortable()`,
which is the FIPS-197 round functions and shares no code, no intrinsics and no
helper with it. For all three key sizes, and for a length that is an exact
multiple of the block size and one that is not, it computes the CBC ciphertext
one block at a time through the portable path and compares the transformer's
output against it, both fed in a single call and fed in 7-byte pieces so the
transformer buffers a varying remainder.

The reason for the direct comparison rather than a round-trip: **a round-trip
proves the two directions agree with each other, not that the ciphertext is
right.** Two matching errors still round-trip, so a broken chain can pass every
round-trip test in the suite. The test was checked to actually have teeth by
temporarily freezing the register chain in the bulk loop — making every block
XOR against the same chaining value, so blocks stop depending on each other —
which failed five test cases including the new one, and restoring the line
returned the suite to 15 cases and 239 assertions all passing.

Two things recorded because they were almost not.

`AesCore::encryptCbcBulk()`'s documented behaviour was that it falls back to a
per-block loop when the CPU lacks AES-NI. The first implementation's non-AES-NI
branch was `(void)in; (void)out; ...` — it produced nothing at all. That is
unreachable as called, since the transformer only supplies the function after
`AesCore::hasAesNi()` passes, but a documented fallback that silently discards
the input would turn any future caller that forgets to check into silent data
loss. It now really does run the per-block path, chain and all.

The comments written along with this change claimed the existing AES tests
compared the two paths against each other. They did not, and at the time could
not — that test did not exist yet. The claim has been removed rather than
quietly kept, and the comments now say what actually covers the path. This is
the same failure mode as reporting a number that was reasoned rather than
measured, and it was in the codebase long enough to be worth naming.

#### One unrelated breakage found on the way

`src/oid.cpp` (untracked new work, `COid`/`SRawOid`) does not compile on either
toolchain — redefinition of `SRawOid::operator=(SRawOid&&)` on GCC and of
`COid::equals` on MSVC. It is not related to this change and was not modified;
it was moved aside for builds and restored immediately after. One consequence is
worth recording: the first after-measurement run reported numbers identical to
the before run, because the build had failed on that file and the script was
measuring the previous binary. Every measurement script used here now refuses
to time anything unless it has seen a clean build, and the after-run that
produced the table above reports `error lines: 0`.
