# API gaps, key validation, and measurement

[한국어](17-api-and-measurement.ko.md)

## Three API gaps the wiki's example code exposed

← [History](../HISTORY.md)

Writing a compiled example for every public type turned out to be an audit as
much as a documentation job: an example is the first caller that has to obtain
a type the way a caller would, and three types could not be used that way.
Each was found by trying to write its example and failing.

#### `EDecoderStatus` was a public enum nothing public could produce

`asn1/decoder.hpp` exports seven status values. `decodeLength()`, the only
thing that produced them, was private, and every public `CDecoder` entry point
returned `bool`. So the one distinction the enum exists to carry — `EDEC_NEED_MORE`,
"truncated, send more bytes", against `EDEC_RESERVED`/`EDEC_TOO_BIG`/
`EDEC_PROHIBITED`, "malformed, give up" — was unavailable to the callers who
need it most, anyone decoding off a socket or a stream.

The status was being computed and then thrown away. `readIndefiniteContent()`
and the depth-tracking `readEncodedValue()` now return `EDecoderStatus` instead
of `bool`, so `EDEC_NEED_MORE` propagates out of a nested value rather than
flattening into the same failure as a malformed one, and a new public
`tryReadEncodedValue()` hands it to the caller. The `bool readEncodedValue()`
keeps its exact signature and is now `tryReadEncodedValue(...) == EDEC_OK`,
so there is one implementation rather than two that could drift apart.

Two places needed a judgement call rather than a mechanical conversion:

- **A tag that will not decode.** `CTag::decode()` folds "no bytes at all",
  "the high-tag-number form runs past the end of the span" and "not a tag"
  into one invalid tag, and only the first is distinguishable afterwards. An
  empty source reports `EDEC_NEED_MORE`; anything else reports
  `EDEC_BAD_ARGS`, because telling a caller to append bytes to a genuinely
  malformed tag is a promise that cannot be kept.
- **Indefinite-length nesting past `MAX_NESTING_DEPTH`** reports
  `EDEC_TOO_BIG` rather than `EDEC_PROHIBITED`: the encoding is legal BER, it
  is this decoder that declines to go deeper, and the two statuses say
  different things about whose fault it is.

The negative controls: collapsing a truncated value back into `EDEC_BAD_ARGS`,
dropping the end-of-contents case back to a generic failure, and discarding
`decodeLength()`'s own status as the old code did were each injected
separately, and each was caught.

The example this type carries on the wiki used to classify the length octets
by hand, because that was the only example possible. It now drives a real
read loop, which is the thing the enum was for.

#### `COctet` could not wipe its own secret without a `const_cast`

A `COctet`'s bytes are reachable only through the read-only `toPtr()`/
`toSpan()`, so `CSecure::zero()` could not be pointed at them. That bites
wherever one carries key material — a PKCS#9 `challengePassword` out of
`CCertRequest::attributeOf()`, a decoded private-key blob — and the workaround
a caller would reach for is a `const_cast`, which is not something to publish
as the house style for handling a secret.

`secureClear()` zeroizes and then releases, following `CBigNum::secureClear()`'s
precedent. A mutable `toPtr()` was the alternative and was rejected: it would
let anything rewrite an owned buffer piecemeal, which is exactly what
`store()`'s replace-the-whole-content design prevents. Naming the operation
keeps the capability to the one use that needs it.

Its doc comment states the limit rather than implying none: it reaches the
bytes *this* instance owns at the moment it is called, and not a copy an
earlier assignment made, nor the block `store()` frees when it replaces
content of a different size. It shortens the window a secret stays in freed
memory; it does not close it.

The test case says plainly what it cannot check. The zeroization is not
observable — the block is freed immediately after, and reading freed memory
would measure the allocator rather than the wipe — so the case covers the
observable contract and leans on `CSecure::zero()`'s own tests for the rest.
The negative control (wipe but never release) is caught.

#### `ParseFixedDigits`, `ValidateTimeFields`, `WriteFixedDigits`

Private static members in PascalCase, where
[RULES.md](../RULES.md) calls for `camelCase` on
members and reserves PascalCase for free functions. Renamed across 32 call
sites; no behaviour change.

## `RSA::checkPrivateKey` rejected every OpenSSL and BIND private key

← [History](../HISTORY.md)

Reported downstream: cppskit's cskdns_certpp imports DNSSEC keys produced by
BIND's `dnssec-keygen`, and `checkPrivateKey()` returned `ERET_KEY_PARAM` for
all of them — while a sign/verify probe on the very same key succeeded. The
workaround downstream was to validate with that probe instead, which is a
sound diagnosis of where the fault was.

The check computed `phi = (p-1)*(q-1)` and required `d == e^-1 mod phi`
exactly. But RFC 8017 3.2 defines `d` as the inverse of `e` modulo **either**
`lambda(n) = lcm(p-1, q-1)` or `phi(n)`, and the two values differ whenever
`gcd(p-1, q-1) > 2`. `lambda` divides `phi`, so the `lambda(n)` value is the
smaller one, and a check written against `phi` rejects it.

It is not a corner of the standard that nothing uses. Generating keys with
OpenSSL 3.2 and reading their parameters back shows the split directly:

| `openssl genrsa` | `d == e^-1 mod lambda` | `d == e^-1 mod phi` |
|---|---|---|
| 2048-bit | yes | **no** (3 of 4 sampled keys) |
| 1024-bit | — | yes |

At 2048 bits and up OpenSSL follows FIPS 186-4, which requires `d < lambda(n)`;
below that it keeps the historical `phi(n)` value. So `openssl genrsa 2048`,
the single most common way to produce an RSA key, was rejected, and only the
sizes nobody should still be using passed. `dnssec-keygen` and ldns produce the
`lambda(n)` form as well.

The fix checks the congruence rather than a specific representative:
`e*d ≡ 1 (mod p-1)` and `e*d ≡ 1 (mod q-1)`, which together are
`e*d ≡ 1 (mod lambda(n))`. That accepts both forms — and also a `d` offset by
any multiple of `lambda`, which is equally valid and equally functional — while
still rejecting a `d` that is not an inverse at all. The `gcd(e, phi) == 1`
test above it needs no change, since `phi` and `lambda` have the same prime
divisors. The CRT checks below it needed none either: `dP = d mod (p-1)` holds
for both forms, because that identity is what makes the CRT exponents work in
the first place.

#### What the test pins

A sign/verify round trip would not have caught this and did not: the bug was
in the validator, not the arithmetic. The regression test therefore carries one
real 1024-bit `openssl genrsa` key encoded as PKCS#1 `RSAPrivateKey` twice —
same `n`, `e`, `p`, `q`, with `d` in each form — chosen so that
`gcd(p-1, q-1) = 24` and the two `d` values are genuinely 24× apart rather
than coinciding, which they do about half the time when the gcd is 2. Both
must now validate, and the two imports must agree on their public half, which
is what proves they are the same key rather than two unrelated ones.

A third vector is the `lambda(n)` key's `d` plus one, with `dP`/`dQ`
recomputed to match so that the congruence is the only thing wrong. It must
still be rejected — a fix that simply dropped the `d` check would pass the
first two cases and leave nothing behind it.

Confirmed by negative control: with the one-line condition reverted, the
`lambda(n)` cases fail and the `phi(n)` and non-inverse cases still pass,
which is exactly the signature of the reported bug.

## Measuring the library on two toolchains, and what they disagree about

← [History](../HISTORY.md)

`README.md`'s Performance section carried a single set of figures, from one
Release/MSVC run. Re-running `examples/05_benchmark.cpp` on both toolchains in
one session -- MSVC 19.36 on Windows and GCC 13.3 on Ubuntu 24.04 under WSL2,
same 4-core i7-11370H -- turned that one column into two, and the second is not
a second copy of the first.

The methodology mattered more than usual here, because a comparison was the
whole point. The two toolchains ran one after the other rather than
concurrently: on eight cores, with a compiler that saturates them, running
both at once would have had each measuring the other's compiler. Each figure
remains the harness's own fastest-of-three-batches-of-20, best of three runs.

#### What the two toolchains disagree about

GCC is equal or faster on most of the library, by a lot in places -- SHA3-256
by 2.8x, Streebog-256 by 42%, ML-KEM by 30%, AES-256-GCM by 28%, Ed25519
signing by 18%. Two entries run the other way, and RSA is the one that
matters:

| | MSVC | GCC |
|---|---|---|
| RSA-2048 sign | **8.06 ms** | 19.1 ms |
| RSA-2048 verify | **0.145 ms** | 0.392 ms |
| MD5, 64 KiB | **593 MiB/s** | 455 MiB/s |

(The MD5 row is what P7 changed, to 572 and 718. The RSA rows are unchanged.)

RSA's two halves moving together, while every prime curve runs *faster* on
GCC, is a specific shape of result. It rules out the big-number backend being
slow in general, and points at RSA as the one place `mulMod()` dominates
enough for a codegen difference to be the whole result.

#### P7 -- MD5 on GCC, closed

The 64-step compression loop selected its round function with `if/else` and
computed the message-word index `g` with `% 16` in rounds 2--4. Both are
per-step costs that have nothing to do with the algorithm: the round schedule is
fixed, so the branches are perfectly predictable, and a modulo by 16 is an
integer division.

Writing the four rounds out explicitly removes both. `g` becomes a mask against
15, which is a single AND, and the round function is whichever loop body is
running. The per-round index expressions are the original ones re-based to the
round's own 16-step range, so the sequence is unchanged.

Measured on the compression function itself, min of 5x50 over 1 MiB, GCC:
**545 to 341 cycles per block, 8.5 to 5.3 per step, 1.60x**.

Project harness, same session, sequential toolchains:

| | before | after |
|---|---|---|
| GCC MD5, 64 KiB | 455 MiB/s | **718 MiB/s** |
| MSVC MD5, 64 KiB | 593 MiB/s | 572 MiB/s |

P7's goal was GCC being the slower toolchain on MD5. It is no longer: GCC now
leads MSVC, where before it was 23% behind. The MSVC figure is within this
machine's noise -- the 593 was measured under load, and the best of five
re-runs is 572.8.

128/128 tests pass on MSVC and under ASan on GCC.

#### The obvious explanation, and why it is wrong

The first thing to try was the one that would have made this a non-issue: GCC
cannot emit MSVC's `_mulx_u64`/`_addcarry_u64`, so it must be falling back to
the portable multiply. That is wrong, and `src/utils/bignum.cpp` says so
directly. `CBigNum::mul()` dispatches on `hasAdxBmi2()` (`bignum.cpp:531`), and
`mulAccelerated()` reaches the same MULX/ADCX path on both toolchains -- GCC
through the function-level `__attribute__((target("bmi2,adx")))`, MSVC through
its unconditional intrinsic use -- and this CPU reports both features. The one
type mismatch Linux ever found in that code, `uint64_t*` against
`unsigned long long*`, is fixed and in the changelog above.

So the difference lives in codegen, and it has not been profiled. Two
candidates worth measuring before anything is changed: the shape of the
Montgomery reduction, and whether GCC keeps `row[]`/`r64[]` resident across
`mulAccelerated()`'s Step A / Step B boundary. That is now open work in
`docs/PLANS.md`, with the exclusions recorded next to it so the ruled-out
hypothesis does not get re-derived.

#### Two limits on the comparison

Both are stated in `README.md` rather than left for the reader to infer:

- **WSL2 is a VM, not bare metal.** The harness is single-threaded CPU-bound
  cryptography, so the hypervisor's share of each measurement ought to be
  small -- but that is an argument that it ought to be, not a measurement
  showing that it is. The GCC column reads as "this toolchain in this setup",
  not as Linux performance in general.
- **"Both Release" is not "the same settings".** CMake's Release defaults are
  `/O2` for MSVC and `-O3` for GCC, so toolchain and optimization level are
  varied together. Calling the RSA gap a GCC bug would need a re-measurement
  on bare metal first.

#### The old numbers were measured under load

The MSVC column replaces figures published earlier, whose own text described
them as taken on a loaded machine. Re-measured, every row came in equal or
faster, most by 10--20%; the largest movement is ECDSA P-256 verify, 3.53 ms
to 2.44 ms, just outside the harness's own stated 20--30% spread. Nothing in
the code changed to account for that, which is the useful part of it: it
measures the conditions, not the library. So the tables now state those
conditions and the spread explicitly, and treat a difference smaller than
20--30% as not being a result.
