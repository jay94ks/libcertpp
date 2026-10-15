# Curve25519 and performance

[한국어](08-curve25519-and-performance.ko.md)

## Fe25519: a constant-time field for X25519

← [History](../HISTORY.md)

Raised downstream alongside the AEAD request: X25519's own test comments note
that the big-number arithmetic underneath it is not constant-time, which for an
online handshake with ephemeral keys is a live side channel rather than a
theoretical one. This is the substrate for fixing it; the ladder rewrite
follows.

`Fe25519` (`src/crypto/asyms/fe25519.hpp`) implements GF(2^255 − 19) in ten
signed limbs at radix 2^25.5, with no data-dependent branches, memory indices
or divisions.

#### Why `CBigNum` cannot be made to do this

`CBigNum` stores a *canonical* limb array — leading zero limbs are trimmed —
so the number of limbs, and therefore the work done, depends on the value.
Every add, multiply and reduction over it leaks something about its operands
through timing. For certificate verification that is tolerable; for a
handshake it is not. `Fe25519`'s limb count is fixed at ten regardless of the
value.

`CBigNum::condSwap` is the sharpest example: its own documentation admits it
is a plain branch. In a Montgomery ladder the swap condition *is* a bit of the
private scalar, so that branch leaks the key one bit per iteration.

#### Why radix 2^25.5 and not 2^51

A 51-bit radix is the faster layout and what most 64-bit implementations use,
but its products need 128-bit arithmetic and **MSVC has no `__int128`**. With
alternating 26- and 25-bit limbs every product fits `int64_t`: the worst-case
multiply accumulator is 10 × (2^26−1)² × 38 = **2^60**, three bits of headroom,
and the test asserts that bound so a future change to the radix cannot
silently overflow it.

Limbs are *signed*, which is load-bearing rather than incidental: `sub()` then
needs no borrow handling, since a limb simply goes negative and the next carry
pass propagates it through an arithmetic shift. Unsigned limbs would require
either adding a multiple of p before every subtraction or branching on the
sign — and the second is exactly what this class exists to avoid.

#### The error the Python pass caught

Validated against exact arithmetic before any C++ was written, and the first
version of the multiply was wrong on **every** input. Because the radix is not
a whole number of bits, `OFFSET[i] + OFFSET[j]` is one bit above
`OFFSET[i+j]` whenever *both* indices are odd — two half-bit offsets adding to
a whole one. I had applied that doubling only to the products that wrap past
2^255, where it is also needed, and not to the rest. Exact arithmetic found it
in one run; a round-trip test never would have, since a packer and unpacker
consistently wrong in the same way agree with each other.

#### Testing

`CBigNum` is the oracle — heavily tested, shares no code with this unit, and
exact. `add`/`sub`/`mul`/`square`/`mulA24`/`invert` are checked against it over
3000 random pairs, plus **every pair of ten edge values** (0, 1, 2, 19, 38,
p−1, p−2, 2^254, 2^128, (p−1)/2), where the carry chain and the 19× wrap are
most strained and where random sampling essentially never lands.

Two cases are checked specifically because they survive a round trip:

- `toBytes()`'s conditional subtraction of p only matters for values in
  [p, 2^255), which decode back to the same element either way. The test feeds
  unreduced representatives directly and requires the canonical bytes.
- `invert()` is checked by `x · x⁻¹ == 1` rather than against a reference
  inverse, so a wrong addition chain cannot agree with itself by construction —
  and then against `CBigNum::modInverse` as well.

7 test cases, 32,468 assertions. Checked under Clang with
`-fno-ms-compatibility` so it does not repeat the portability breakage fixed in
`d297767`.

## X25519: a constant-time ladder, and 5-7x faster as a side effect

← [History](../HISTORY.md)

`Curve25519`'s Montgomery ladder now runs on `Fe25519` instead of `CBigNum`,
which closes the timing channel a downstream consumer reported. Nothing in
`x25519.cpp` touches `CBigNum` any more, so there is no path by which a secret
scalar reaches variable-time arithmetic.

What changed, beyond swapping the field type:

- **The scalar bit is read from the bytes directly**, not through
  `CBigNum::testBit()`, whose cost depends on the value's limb count.
- **The conditional exchange is `Fe25519::condSwap` under an arithmetic mask**,
  replacing `CBigNum::condSwap`, which its own documentation admits is a plain
  branch. In a ladder that condition *is* a bit of the private scalar.
- **Clamping produces bytes, not a `CBigNum`**, and `scalarMult()` clears its
  clamped copy before returning.
- **`checkPrivateKey()`'s cofactor check calls `ladder()` rather than
  `scalarMult()`**, deliberately: its scalar is the small public constant 8 and
  must *not* be clamped, since clamping would turn it into a different scalar.
  That distinction was implicit before, when the check passed a raw `CBigNum`;
  it is now a visible difference between two named entry points.

One check became structural rather than tested. The old code verified the
derived u-coordinate was canonically reduced (`u >= p` rejected);
`Fe25519::toBytes()` emits the canonical representative in [0, p) by
construction, so that can no longer fail. The bit-255 mask is asserted in its
place, since that is the one thing a 32-byte encoding could still carry.

#### The measured effect

Not the point of the change, but worth recording, because `CBigNum` was
allocating per operation and reducing against a runtime-computed prime:

| | before | after |
|---|---|---|
| `generateKeyPair` | 4.7 ms | **0.907 ms** |
| `deriveSharedSecret` | 2.0 ms | **0.287 ms** |

All 12 X25519 test cases and 4217 assertions pass unchanged, RFC 7748's
vectors included — which is the check that matters, since a ladder that is
subtly wrong still produces consistent key agreement between two copies of
itself.

Still short of the 100 µs/operation the consumer asked for. Two causes are
identified and not yet addressed: `Fe25519::mul` carries two branches per
partial product inside a 10x10 loop that the compiler is unlikely to unroll,
and `generateKeyPair` runs three ladders (one to derive the public key, then
`checkPrivateKey` recomputing it plus the cofactor check) where it already has
the first result in hand.

## Performance pass, driven by a downstream report with numbers

← [History](../HISTORY.md)

cppskit's libcskcwk reported concrete figures and targets for the link-
encryption path. This records what moved, what did not, and the one place the
target turns out to be unreachable without work the report did not anticipate.

| | reported | now | target |
|---|---|---|---|
| X25519 `generateKeyPair` | 4.7 ms | **333 µs** | ≤100 µs |
| X25519 `deriveSharedSecret` | 2.0 ms | **167 µs** | ≤100 µs |
| AEAD seal, 64 KiB | ~300 MiB/s | 331 MiB/s | ≥1.5 GiB/s |
| AEAD seal, 64 B | 507 ns | ~440 ns | ≤150 ns |

#### Where the AEAD time actually goes

Isolated by subtraction, at 64 KiB: Poly1305 60.6 µs, ChaCha20 128.4 µs. So
the report's diagnosis was right that ChaCha20 dominates — but the arithmetic
has a consequence it did not reach:

- ChaCha20: **487 MiB/s**, about 5.9 cycles/byte.
- Poly1305: **1032 MiB/s**, about 2.8 cycles/byte.

2.8 cycles/byte is roughly what a scalar 26-bit-limb Poly1305 should cost, so
the MAC is already near its ceiling for this representation — and since the two
compose as `1/total = 1/cipher + 1/mac`, **Poly1305 alone caps the AEAD at
1032 MiB/s no matter how fast the cipher gets.** Reaching 1.5 GiB/s needs
*both*: with the MAC at 3 GiB/s the cipher must reach 3 GiB/s; with the MAC at
2 GiB/s the cipher must reach 6. That means SIMD on both sides, or Poly1305 in
64-bit limbs via `_umul128`. Worth knowing before anyone spends a week on
ChaCha20 alone and lands at 1 GiB/s.

#### What was done

**ChaCha20: prepared state, word-wise XOR.** The block function took the key
and nonce per call, so it re-parsed eleven little-endian words for every 64
bytes; `ChaCha20Core::SState` now hoists that to once per message.
`xorStream()` combines whole blocks 32 bits at a time instead of byte by byte,
and the `ISymmetric` transformer routes its block-aligned bulk through it while
keeping its cross-call cursor for the edges. Measured: 286 → 331 MiB/s.

That is a smaller gain than the change suggests, and the reason is the useful
part: neither the state setup nor the byte-wise XOR was dominant — **the twenty
rounds are**, at ~376 cycles per block. Further cipher gains need SIMD, not
bookkeeping.

**Fe25519: unrolled multiply.** The 10x10 loop carried two branches per
partial product (the odd/odd doubling and the wrap). Pre-scaling the operands
folds both constants out, leaving pure multiply-accumulate — and the expression
was *generated* from the same rule the Python reference validated, rather than
hand-typed, so the 100 terms cannot drift from it. Measured: derive 287 → 167 µs.

**X25519 keygen: one derivation instead of two.** `generateKeyPair` derived the
public key, then called `checkPrivateKey()`, which derived it again purely to
compare against the value just computed. The three validity checks moved into a
shared `validatePublicValue()` that both paths call, so nothing is weakened —
the comparison that was dropped was between a value and itself. Measured:
540 → 333 µs, consistent with three ladders becoming two.

#### What was tried and reverted

`carryPass()` was unrolled with literal shift amounts, on the theory that
`widthOf(i)`'s modulo was costing something across the ~50,000 calls a ladder
makes. It made **no** difference, inside a run-to-run spread of about 11% —
`widthOf()` is `constexpr` and the bound is fixed, so the compiler was already
doing it. The loop is back, with the negative result recorded in a comment so
nobody repeats it.

A dedicated squaring was *not* written at this point, deliberately. It would halve
the partial products of the four squarings per ladder iteration — perhaps 30% — but
it is a second 100-term expression with its own doubling rules interacting with
the radix's, and the ladder would still agree with itself if it were wrong.
Left until the gain can be attributed rather than assumed.

That reasoning turned out to be right and the conclusion drawn from it turned out
to be premature, which is a combination worth recording because the error was not
in the caution. The squaring was eventually written — see *`Fe25519`: a dedicated
squaring, generated rather than derived* below — and it is correct. What was
missing was not confidence but a mechanism: the merged factors had to come from
somewhere other than a human reading a 100-term expression, and until they came
from a program that checks itself against `mul()`, "deliberately not written" was
the only responsible option available. The negative result recorded here was
about the *method*, not about the operation.

#### What remains for 100 µs

derive is 1.7x off. The dominant remaining cost is that a 2^25.5 radix needs
**100** limb multiplies, where a 2^51 radix needs 25 — that is the real 4x, and
it is why 64-bit implementations use it. It needs 128-bit products, which MSVC
can do via `_umul128` even without `__int128`.

The squaring half of that is now done, at radix 2^25.5, so what remains is the
radix half — and the radix half is gated on `_umul128` measuring 6.5--7.0x the
native multiply, which makes a single 2^51 implementation everywhere *slower on
MSVC than the 2^25.5 code it would replace*. It is a gate rather than a
migration for that reason, and 100 µs is reachable on the native-`__int128`
toolchains by turning it on, not by rewriting it.
