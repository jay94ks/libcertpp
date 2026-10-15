# Field arithmetic and AEAD

[한국어](09-field-and-aead.ko.md)

## `Fe25519`: a dedicated squaring, generated rather than derived

← [History](../HISTORY.md)

`Fe25519::square()` called `mul(a, a)` from the day the field landed, and
`docs/PLANS.md` carried "the dedicated square half is still a negative result"
in two places — both of which this entry supersedes. A squaring is not half of a
multiplication, it is 55 products against 100, because each of the 45
off-diagonal pairs appears twice and can be computed once.

#### Why it took a generator

Two attempts at writing the merged factors by hand were both wrong, and the
reason is the interesting part. The 2^25.5 radix applies its corrections
**asymmetrically**: the odd-index doubling belongs to the first operand and the
19-fold to the second. The product matrix is therefore symmetric in value but
not in correction, so the merged factor for an off-diagonal pair is the **sum** of
the two single-term factors, not twice one of them — and every factor in the
expression depends on that distinction.

The part that is easy to get wrong even having noticed all of that: reading
`mul()`'s expressions, `f` is doubled when the index is odd **and the output limb
is even**. Both halves of the condition are load-bearing. `mul()`'s even output
limbs (t0, t2, t4, t6, t8) double f1..f9; its odd output limbs (t1, t3, t5, t7,
t9) double nothing at all. "Doubled when the index is odd" is true of half the
rows and yields a `square()` that is wrong for every input.

So `tools/fe_square_gen.cpp` transcribes `mul()`'s own per-term rule, checks that
the rule reproduces `mul()` on all ten limbs over 200 random inputs, checks the
merged form the same way over 20,000, and only then emits the expressions. A
wrong factor cannot pass either check, so it cannot reach the library. It is
documented in `CLAUDE.md` as a hand-edit-the-generator-never-the-squaring tool,
because the generated block and the tool are only useful together.

Three factors, so the shape is checkable by eye: `1*s0*s0` (diagonal, even, no
wrap), `38*s5*s5` (diagonal, odd, wraps at 2×5 = 10 → 2 × 19), `76*s1*s9` (both
odd → (2 + 2) × 19).

#### Measured

Same process, same operands:

    mul()               36.87 ns/call
    square()            29.48 ns/call     -20.0%
    products only       31.19 ns/call     84.6% of mul

End to end, by instruction count — this machine moves Ed25519 between 3.6x and
5.5x of OpenSSL across identical wall-clock runs, which cannot resolve a change
this size, so the count is the honest instrument:

    baseline   2,236,950 instructions per signature
    this       2,187,443                          -2.21%
    OpenSSL      602,948 (control, unchanged)

**The end-to-end wall-clock effect is not established** and is not claimed. It is
below this machine's noise floor.

#### Why `mul()` itself was left alone

At 31.19 ns for 100 `imul`s on a ~3.5 GHz part, the product accumulation is at
about **91% of the imul throughput floor** (100 cycles ≈ 28.6 ns). The remaining
15% is two carry passes, and two is structural: the first pass's limb-9 carry
folds back into limb 0 through ×19, so it cannot be folded into a single pass.
There is no headroom there to optimize, which makes the product *count* the only
lever — and that is what the squaring takes.

Karatsuba, which would take 100 products to 75, was considered and rejected on
arithmetic rather than taste. It would lower the floor to about 21 ns, roughly
10 ns saved, against 5-limb additions, subtractions and a materially wider carry
that would eat much of it. More seriously the accumulator bound goes to zero: the
`(a0+a1)(b0+b1)` middle term has 27-bit limbs, 54-bit products, and accumulates
into five positions, which is ≈2^63 — exactly `int64_t`'s limit. The current code
carries three bits of headroom (2^60) and the test asserts that bound. A MAC that
is wrong only for some inputs is worse than one that is wrong for all of them.

Radix 2^51 keeps `mul(a, a)`: merging 25 products to 10 is a small win for a
second generated form to keep correct.

Verified: 130/130 on the default build, and `fe25519`/`ed25519`/`x25519` also
pass under `CERTPP_ENABLE_FE25519_RADIX51`.

## AES-GCM and unpadded CBC, for an IKEv2 consumer

← [History](../HISTORY.md)

An IKEv2 implementation needs the two transforms RFC 7296/4106/5282 actually
negotiate: AES-GCM as an AEAD, and AES-CBC over a payload the protocol has
already padded itself.

- `CAesGcm` (`crypto/aeads/aesgcm.hpp`) — NIST SP 800-38D, AES-128/192/256, a
  96-bit IV, and a 96- to 128-bit tag. Its API matches
  `CChaCha20Poly1305`'s deliberately: the same consumer picks one or the other
  by negotiation and should not have to restructure around the choice.
- `Ghash` (`src/crypto/aeads/ghash.hpp`) — GHASH and GCM's `GF(2^128)`, private
  to `src/`.
- `AesCore` extracted from `crypto/syms/aes.cpp` into its own private unit, the
  way `DesCore` and `ChaCha20Core` already were.
- `ESymPaddings` on `ISymmetricContext` — `ESYMPAD_PKCS7` (the default,
  unchanged) or `ESYMPAD_NONE`.

#### Why GHASH is not `CGf2m`

`CGf2m` already multiplies in `GF(2^m)` with a PCLMULQDQ path, and GHASH's
modulus `x^128 + x^7 + x^2 + x + 1` would even fit its pentanomial
`SGf2mField`. It was still the wrong tool, for three independent reasons, and
the first is the one that matters:

**GCM's field is bit-reflected.** The most significant bit of a block's first
byte is the `x^0` coefficient (SP 800-38D 6.3) — the opposite of the
polynomial-basis convention `CGf2m` and the rest of this library use. Handing
`CGf2m` the bytes as they arrive produces a product that is commutative,
associative, distributive and perfectly self-consistent, and is not GHASH.
Nothing but a published vector catches that, which is this repository's
recurring failure mode (the transposed SHA-3 rotation table, the transcribed
P-521 digits, the ChaCha20 vector path no RFC vector was long enough to reach).

The other two: `H` is secret, so the multiply has to be constant-time, and
`CGf2m` documents that it is not hardened at all — the right trade for ECDSA's
public curve arithmetic, the wrong one for a MAC key. And `CGf2m` carries nine
limbs through a generic pentanomial reduction over an eighteen-limb product,
where GHASH is two 64-bit words with one fixed modulus, once per 16 bytes.

#### Python first, then C++

SP 800-38D was implemented in Python — AES included, so nothing was taken on
trust — and checked against the GCM specification's Appendix B test cases
before a line of C++ was written. All twelve of the cases that use a 96-bit IV
(1–4, 7–10, 13–16: three key sizes, an empty plaintext, an empty AAD, and a
60-byte plaintext with a 20-byte AAD) matched, including each case's published
subkey `H`. The same script also confirmed that those vectors *can* see each
error class before relying on them to. The C++ then passed all twelve on its
first run.

#### The accelerated path does not use the reflected convention

The textbook PCLMULQDQ GHASH multiplies in GCM's own reflected representation,
which needs a shift-by-one across the 256-bit product plus a reduction whose
constants (`slli_epi32` by 31, 30, 25, then 1, 2, 7) are easy to transcribe and
impossible to check by eye. This one instead converts both operands out of the
reflected convention with twelve SSE2 instructions — reversing the bits within
each byte, which is the whole of the conversion, since little-endian byte order
is what a load already gives — multiplies in the ordinary one, where the
reduction is the textbook `x^128 = x^7 + x^2 + x + 1` (`0x87`), and converts the
product back. Slower in principle than the mirrored form; derivable on paper,
which was worth more.

Published vectors cannot tell the two paths apart: the dispatch is a runtime
CPUID check, so whichever one this CPU takes is the only one they ever reach.
`tests/crypto/aeads/ghash.cpp` therefore compares them directly over 2048
random operand pairs plus every single-bit block, and pins the bit order down
with the field identities — in GCM's order the multiplicative identity is the
block `80 00 … 00`, so `X ⊗ 80 00 … 00 == X` fails for any unreflected
multiply however self-consistent it is elsewhere. `Ghash` has no public header
and no `CERTPP_API`, so that test compiles `ghash.cpp` into itself through
`CERTPP_TEST_PRIVATE_SOURCES`.

#### Negative controls

Each was introduced, built, and confirmed to fail a test before being reverted:

| break | caught by |
| --- | --- |
| payload counter starts at `J0`, not `J0 + 1` | `aesgcm` (the Appendix B ciphertexts) |
| length block in bytes, not bits | `aesgcm` |
| length block little-endian, not big-endian | `aesgcm` |
| reflection dropped in the portable multiply | `ghash` (identity + differential) |
| reflection dropped in the PCLMULQDQ multiply | `ghash` *and* `aesgcm` |
| AAD left out of the hash | `aesgcm` (the tampered-AAD subcase) |

The le64-vs-be64 one is worth noting: ChaCha20-Poly1305's otherwise analogous
length footer is little-endian (RFC 8439 2.8), and GCM's is big-endian. Two
AEADs in one directory with the same-shaped footer and opposite endianness is
exactly the kind of neighbour that invites a copy.

#### Unpadded CBC, without changing what already worked

`CbcTransformer` always padded, and the SP 800-38A tests plus every other
caller depend on that, so `ESYMPAD_NONE` is an opt-in rather than a change of
default. Unpadded, nothing is held back and nothing is stripped: every whole
block is emitted as it completes, and `transformFinal()` returns `ERET_BADREQ`
on a partial block rather than quietly rounding the length up.

`padding()` is deliberately *not* cleared by `reset()` or `key()`, unlike the
key, IV and block size. It is a mode choice, not key material, and clearing it
would make `padding(ESYMPAD_NONE)` followed by `key(...)` silently revert to
PKCS#7 — a very quiet way to emit a ciphertext the peer rejects.

A side benefit: unpadded CBC is the first thing in this library that can be
held against SP 800-38A F.2's *four-block* CBC vector. Padded CBC appends a
fifth all-16s block, so until now only the single-block, all-zero-IV reduction
of F.2 was checked, which exercises no chaining at all.
