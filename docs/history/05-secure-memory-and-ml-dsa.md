# Secure memory and ML-DSA groundwork

[한국어](05-secure-memory-and-ml-dsa.ko.md)

## `CSecure`: zeroization and constant-time compare/select

← [History](../HISTORY.md)

Added `utils/secure.hpp` — `CSecure::zero()`, `equalsMask()`, `select()` — and
used it to close two gaps in ML-KEM, one of which was worse than the one
originally recorded.

#### The real finding: `memcmp` in the FO check

The previous entry noted ML-KEM's missing zeroization as a known gap. Looking
at `decapsulate()` again to fix that turned up something more serious a few
lines away:

```cpp
const bool matches = std::memcmp(reencrypted, ciphertext.data, ciphertext.size) == 0;
std::memcpy(sharedSecret.data, matches ? candidateSecret : rejectionSecret, 32);
```

`memcmp` stops at the first differing byte, so its running time reveals **how
long a prefix of the re-encrypted ciphertext matched** — far more information
than the single bit the Fujisaki-Okamoto transform exists to hide, and the
shape of the KyberSlash family of attacks. The ternary then branches on the
verdict, which *is* that single bit; FIPS 203 requires the implicit-reject
flag never be exposed "in any form", and a branch exposes it.

Both are now `CSecure::equalsMask` followed by `CSecure::select`: the
comparison reads every byte whatever the outcome and yields `0xFF`/`0x00`, and
the mask drives a byte-wise select, so nothing branches on anything secret.
The ACVP decapsulation vectors — including all the `modified ciphertext`
records, which are precisely the rejecting path — still pass byte-for-byte,
which is what confirms the rewrite preserved the output on both paths.

`equalsMask` returns a full mask rather than a bool on purpose, and the test
asserts the value is `0xFF` rather than merely truthy: `select` ANDs with it,
so a mask of `1` would silently keep only the low bit of each selected byte.
It also folds its accumulated difference to a mask arithmetically instead of
writing `diff == 0`, so correctness doesn't depend on the compiler choosing a
flag set over a branch there.

#### Zeroization that survives the optimizer

`CSecure::zero()` routes `memset` through a volatile function pointer. This was
verified rather than assumed, by reading MSVC's `/O2` output for two otherwise
identical functions: in the one using a plain `std::memset` the clear was
**deleted entirely** — no store, no call — while the `CSecure::zero` call
survived, and inside `zero` the compiler loads the pointer from memory and
tail-jumps through it rather than folding it back to a direct `memset`.

`decapsulate()` was restructured to a single exit so the clearing cannot be
skipped by an error path, since that one is a normative FIPS 203 requirement.
`kpkeKeyGen()`, `kpkeDecrypt()`, `encapsulate()` and `MLKEM`'s CSPRNG draws
clear at their success exit without being restructured — their early returns
all need a hasher or sampler to fail at a fixed, correct size, so none is
reachable, and threading a status through those loops would cost more clarity
than it buys. The difference is deliberate and noted in the code.

#### What this deliberately does not touch

The inline mask arithmetic in RSA's EME-PKCS1-v1_5 unpadding and
`CbcTransformer`'s PKCS#7 padding check stays as it is. Neither is "compare
two buffers" or "choose between two buffers" — both interleave masking with a
scan over the padding — so there is nothing in `CSecure` for them to call, and
rewriting working, tested constant-time code for the appearance of
consolidation would be a poor trade.

Still outstanding: no RSA, DSA or EC private-key operation scrubs its
intermediates. The primitive is now there for it.

## Scrubbing private-key intermediates

← [History](../HISTORY.md)

`CSecure` existed but was only used by ML-KEM. This applies it across the
pre-quantum algorithms, and adds the big-number counterpart it needed to be
able to.

#### `CBigNum::secureClear()`, and why the destructor doesn't do it

Private keys and signing nonces are `CBigNum` values, so clearing stack
buffers alone would have missed everything that matters. `secureClear()` wipes
the limb allocation — its whole capacity, so limbs above a trimmed length go
too — and resets the value to zero.

Making `~CBigNum()` do it unconditionally would be far more robust, so the
question was what it costs. Measured rather than guessed, and the guess was
wrong: I estimated 1–3% and it was **+22% across the asymmetric test suites,
+32% on X25519 alone**. A scalar multiplication creates a great many
short-lived temporaries, nearly all of them holding public intermediates, and
each clear is a non-inlinable indirect call. So it stayed opt-in. Applying it
only to named secrets is unmeasurable by comparison — the build without the
clears actually timed *faster* on one run than the build with them, which is
how far below the noise floor it sits.

That buys a real limitation, stated in the header rather than left implicit:
`secureClear()` reaches only the values a caller names. A temporary created
inside an expression, or inside `modExp()`/`modInverse()`, is freed uncleaned.
This narrows the window a secret sits in freed memory; it does not close it.

#### What got cleared, and why those

The criterion was "exposure is catastrophic", not "is secret":

- **ECDSA/ECDSA2/DSA signing**: the nonce `k`, and the `d*r`/`x*r` product
  beside it. Either one yields the private key outright from a published
  signature — `d = (s*k - z)/r mod n`, or `d = dr/r mod n`. Cleared on every
  path out of the retry loop, including the retry paths themselves, which need
  a zero `r` or a non-invertible `k` and so are unreachable short of a broken
  CSPRNG. Three lines each; worth it for not having to reason about it again.
- **Ed25519/Ed448 signing**: the nonce, and the expanded seed behind it. EdDSA
  publishes `S = r + k*s mod L` with `k` public, so learning `r` for one
  signature recovers `s` — the nonce is exactly as sensitive as the key, which
  makes `prefix` and `rHash` the same secret since they determine it. Also the
  `k*s` product, which hands over `s` because `k` is public. Each is cleared
  where it stops being needed, which leaves exactly one exit with anything
  live.
- **X25519**: the clamped scalar (the private key in all but encoding,
  recomputed on every scalar multiplication) and the shared secret.
- **RSA**: the CRT intermediates. These are *more* sensitive than the value
  being computed, not less: `m1` is `m mod p`, so `m - m1` is a multiple of `p`
  and `gcd(m - m1, n)` is `p` exactly — and when signing, `m` is the published
  signature. Also the padded plaintext buffer in `decryptBlock`, on all three
  of its exits, which keeps the paths doing the same work rather than adding a
  distinguisher to the constant-time unpadding above it.

#### Evidence it didn't break anything

The deterministic known-answer tests are the check that matters here: an
over-eager clear would corrupt a value still in use, and RFC 8032's EdDSA
vectors, CAVP's ECDSA/DSA vectors and the RSA KAT all reproduce exact expected
bytes. All of them still pass, along with the rest of the 95-test suite in
both Debug and Release.

## Post-quantum: ML-DSA's ring arithmetic

← [History](../HISTORY.md)

The start of Phase 5. `src/crypto/asyms/mldsaring.hpp`/`.cpp` hold `MlDsaRing`:
R_q = Z_q[X]/(X^256 + 1) with q = 8380417, the NTT over it, and the two
coefficient operations ML-DSA's signing loop depends on.

It is a separate unit from `MlKemRing`, not a parameterization of it, and the
reasons go deeper than the constants:

- **`int64_t` throughout.** q = 2^23 − 2^13 + 1, so a product of two
  coefficients reaches about 7.0e13 — four orders of magnitude past
  `int32_t`. In ML-KEM's ring the same product fits in `int32_t` comfortably,
  so carrying that habit across would be a silent wraparound rather than a
  style difference. It bites the twiddle-table builder too, where `ZETA * acc`
  reaches ~1.5e10; `MlKemRing`'s equivalent uses `int32_t` there quite safely,
  and copying it would have been wrong.
- **The NTT is complete.** ζ = 1753 has order exactly **512**, not 256, so
  X^256 + 1 splits all the way into 256 linear factors: eight layers, 256
  independent evaluation points. ML-KEM's transform stops one layer short,
  leaving 128 degree-1 blocks that need a base-case multiply and a second
  twiddle table. So `multiplyNtt()` here is plain pointwise multiplication and
  there is no `gammas()` at all.
- **`bitRev8`, not `bitRev7`.**

Also `centered()` (FIPS 204's `mod±`, the representative in (−q/2, q/2]) and
`infinityNorm()`. The norm belongs to the ring rather than to a caller because
ML-DSA's signing loop rejects on exactly that quantity — and it has to be
taken over *centered* representatives, so an implementation that skipped the
centering would see q−1 where the answer is 3, and would then either reject
everything or reject nothing.

#### Validated before any C++ was written

Same discipline as ML-KEM's ring, and it paid off the same way — the
implementation was correct on its first run. A Python reference built from the
specification text established, ahead of time:

- ζ = 1753 has order exactly 512 and ζ^256 = −1 (so the transform runs to
  completion);
- all 255 of FIPS 204 Appendix B's printed zetas match ζ^BitRev8(k) mod q
  — the table was extracted from the publication itself rather than
  transcribed;
- Algorithm 42's constant 8347681 is simply 256⁻¹ mod q, derived rather than
  copied;
- the NTT round-trips and its pointwise product agrees with a schoolbook
  negacyclic convolution, over 200 random polynomial pairs;
- and the transform agrees with dilithium-py 1.4.0 on 50 random polynomials.

#### The tests deliberately don't rest on round trips

FIPS 204 fixes the NTT's exact representation, not just its end-to-end
behaviour, so a transform that inverts itself while permuting coefficients
differently from the standard is self-consistent and interoperates with
nothing. The suite checks the table against Appendix B's printed values *and*
re-derives it by square-and-multiply (where the implementation uses repeated
multiplication), asserts X^256 = −1 directly, and checks the NTT-domain
multiply against the schoolbook convolution.

Two negative controls confirm it bites, since a test suite that cannot fail is
worth little:

- Making the transform **7 layers instead of 8** — ML-KEM's shape, which still
  round-trips perfectly — fails 4 assertions across 4 test cases.
- Storing the zetas **in Montgomery form**, which is what FIPS 204 Appendix A
  warns implementations usually do, fails 5.

13 test cases, 108,974 assertions.

## Consolidating ML-KEM into `crypto/kems`, and ML-DSA into `crypto/asyms`

← [History](../HISTORY.md)

A layout change, no behaviour change. `crypto/pq/` is gone.

`include/certpp/crypto/pq/mlkem.hpp` merged into
`include/certpp/crypto/kems/mlkem.hpp`, so one public header now declares
`SMlKemPoly`, `SMlKemParams`, `CMlKemSampler`, `CMlKem` and `MLKEM` — the
algorithm and its `IKem` form together. The two `.cpp` files merged to match,
since the convention is one `.cpp` per public header; `src/crypto/kems/mlkem.cpp`
is now ~1050 lines, split by a banner comment between the algorithm and the
wrapper. `mlkemsampler.cpp`, `mlkemring.*` and `mlkemcodec.*` moved alongside
it under `src/crypto/kems/`.

**ML-DSA went to `crypto/asyms/` rather than `crypto/kems/`.** The instruction
was to move everything out of `src/crypto/pq/`, and filing `mldsaring` under
`kems/` would have named a *signature* algorithm's ring after key
encapsulation — so it went where Phase 5's `mldsa.hpp` is headed, which
empties `crypto/pq/` just the same.

Knock-on changes:

- Private header guards renamed to match their new paths
  (`__SRC_CRYPTO_KEMS_MLKEMRING_HPP__`, `__SRC_CRYPTO_ASYMS_MLDSARING_HPP__`).
- Tests moved to mirror: `tests/crypto/kems/{mlkemring,mlkemcodec}.cpp` and
  `tests/crypto/asyms/mldsaring.cpp`. The ACVP vector test collided with the
  existing `IKem` test's name, so it became
  `tests/crypto/kems/kat_mlkem.cpp` — matching the `kat_rsa`/`kat_dsa`/
  `kat_ecdsa` naming already in `crypto/asyms/`.
- `CMakeLists.txt`'s private-test-sources rule no longer works off one
  directory, since those units now live in two. It builds a list from two
  conditions instead: anything under `tests/crypto/kems/` gets ML-KEM's ring
  and codec, and `crypto/asyms/mldsaring` alone gets ML-DSA's ring — scoped to
  that one test rather than to `crypto/asyms/`, which holds two dozen others
  that have no business compiling it in.

Verified by assertion count rather than just a green tick, since a silently
skipped test would also be green: all five affected executables report exactly
the totals they did before the move (kat_mlkem 2464, mlkem 232, mlkemring
1566, mlkemcodec 104056, mldsaring 108974), and the suite is 96/96.
