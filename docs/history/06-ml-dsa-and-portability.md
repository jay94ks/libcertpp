# ML-DSA internals and portability

[한국어](06-ml-dsa-and-portability.ko.md)

## Post-quantum: ML-DSA's rounding and hint machinery

← [History](../HISTORY.md)

FIPS 204 7.4, as `MlDsaRounding` (`src/crypto/asyms/mldsarounding.hpp`):
`power2Round`, `decompose`, `highBits`/`lowBits`, `makeHint` and `useHint`,
scalar and per-polynomial. Private to `src/`, like the ring beside it.

The hint mechanism is the reason any of it exists. A signature carries one bit
per coefficient rather than w1 itself, and the verifier reconstructs
`HighBits(w − c·s2 + c·t0)` from its own approximation plus those bits — which
works only if `useHint()` inverts `makeHint()` exactly, and only while the
perturbation stays within γ₂, a bound the signing loop has to enforce before
calling it. The Python pass confirmed the bound is load-bearing rather than
decorative: outside it, the identity fails about two thirds of the time.

#### A wrong assumption the validation caught

I had written, in a comment, that `decompose()`'s `(q−1)` carve-out "bites
nowhere else" than `r == q − 1`. The data said otherwise, and this is worth
recording because the mistake is an inviting one.

FIPS 204 Algorithm 36 branches on `r+ − r0 == q − 1`. That reads like a test
for the single value `q − 1`, and simplifying it to `r == q − 1` is the obvious
tidy-up. It is wrong: the condition holds across the whole top band of width
γ₂ — **95,232 values (1.14% of q)** at γ₂ = (q−1)/88, and **261,888 (3.1%)** at
(q−1)/32. Every coefficient in that band must land in bucket 0; the point
comparison would put 95,231 of them one bucket too high. Nothing but an
external vector or a bucket-range assertion would notice, since the result
stays self-consistent.

A second trap, documented in the header: `mod±` here is **not**
`MlDsaRing::centered()`. That one reduces modulo q, which is odd, so its split
sits at (q−1)/2. These reduce modulo 2^d and 2γ₂, both even, where the range is
(−m/2, m/2] and m/2 itself stays positive. Same definition (FIPS 204 2.3),
different modulus, different edge — so the unit carries its own `modPm()`
rather than reaching for the ring's. An off-by-one there misfiles one
coefficient value in every 2γ₂.

#### Validated first, then tested against the traps

All five operations agreed with dilithium-py 1.4.0 over 100,000 values per
parameter set, and the inversion identity over 200,000 random (r, z) pairs per
set, before any C++ was written — which is again why it was right on the first
run.

The test does not rely on random sampling for the fragile cases. It enumerates
every bucket boundary against z = ±γ₂ and ±1, walks the carve-out band, and
checks the `r0 == 0` tie explicitly (it counts as "not positive", so a set hint
steps *down*; splitting it the other way breaks exactly the coefficients
sitting on a boundary). Two negative controls confirm the suite bites:

- Simplifying the carve-out to `rp == q − 1` fails 4 assertions across 4 cases.
- Flipping the `r0 == 0` tie to step up fails 5 across 2.

9 test cases, 1,849,585 assertions.

## Post-quantum: ML-DSA's bit packing and hint encoding

← [History](../HISTORY.md)

FIPS 204 7.1–7.2, as `MlDsaCodec` (`src/crypto/asyms/mldsacodec.hpp`):
`simpleBitPack`/`simpleBitUnpack` for coefficients in [0, b],
`bitPack`/`bitUnpack` for [−a, b] (encoding `b − w_i`, which is what lets an
unsigned bit field carry a signed range), and `hintBitPack`/`hintBitUnpack`.

#### Decoding does not imply the range

FIPS 204 warns about this itself, in prose directly under Algorithm 17: for
some (a, b) there exist byte strings that decode to coefficients outside the
nominal range, and that is a concern for input from an untrusted source. The
Python pass worked out exactly which of ML-DSA's uses are affected, because
the answer decides where a caller must check:

| field | (a, b) | width | decodes to | safe? |
|---|---|---|---|---|
| `t1` | b = 2¹⁰−1 | 10 | [0, 1023] | yes |
| `t0` | 2¹²−1, 2¹² | 13 | [−4095, 4096] | yes |
| `z` | γ₁−1, γ₁ | 18 or 20 | exact | yes |
| `s1`/`s2`, η=2 | 2, 2 | 3 | down to **−5** | **no** |
| `s1`/`s2`, η=4 | 4, 4 | 4 | down to **−11** | **no** |
| `w1`, γ₂=(q−1)/88 | b = 43 | 6 | up to **63** | **no**, but never decoded |

So `skDecode` must range-check s1/s2 — which is why FIPS 204's own version
does — while t0/t1/z need no check at all, and w1 only ever gets encoded (it
feeds the hash; it never arrives from a peer). `inRange()` exists for the
cases that need it. Same shape of hazard as ML-KEM's `ByteDecode_12`.

#### The hint decoder, and why it has three separate rejections

`hintBitUnpack` is the sharpest decode trap in the standard. It must reject on
three *distinct* conditions, each of which exists to keep the encoding
injective — and an encoding that is not injective is a signature that can be
modified without being invalidated:

1. a cumulative index that moves backwards or exceeds ω;
2. positions not strictly increasing **within one polynomial** (equal counts as
   not increasing, or one coefficient could be named twice);
3. any non-zero byte left over in the first ω after the last position read —
   without this, arbitrary data can be stuffed into the unused tail.

The scope of (2) cuts both ways, which is the part worth internalising: the
comparison resets at each polynomial boundary, so positions legitimately
*decrease* from the end of `h[i]` to the start of `h[i+1]`. An implementation
that checks monotonicity across the whole array looks stricter and is simply
broken — it rejects valid signatures.

Four negative controls, each disabling one behaviour:

| change | result |
|---|---|
| (1) cumulative-index check removed | 1 assertion fails |
| (2) strictly-increasing check removed | 2 fail |
| (3) leftover-byte check removed | 4 fail |
| (2b) monotonicity across the whole array | 2 fail, and only 6339 of 14629 assertions pass — it rejects valid input |

A rejected decode also leaves the caller's polynomials untouched rather than
half-written, since the caller is about to treat `false` as "this signature is
invalid" and a partially filled hint vector is the kind of thing that later
gets used by accident.

#### Validation

Written in Python against the specification text first and cross-checked
against dilithium-py 1.4.0: packing agreed on 2400 polynomials across every
(a, b) ML-DSA uses, unpacking on 1500, and the hint round trip over 6000
random hint vectors spanning all three parameter sets' (k, ω). The byte layout
is additionally pinned in the C++ tests against hand-computed bytes, including
a 10-bit coefficient straddling a byte boundary — packing the bits big-endian
within each byte would still round-trip and interoperate with nothing.

9 test cases, 14,629 assertions; 98/98 in Debug and Release.

## Post-quantum: ML-DSA's rejection samplers

← [History](../HISTORY.md)

FIPS 204 7.3, as `MlDsaSampler`: `SampleInBall`, `RejNTTPoly`,
`RejBoundedPoly`, and the `ExpandA`/`ExpandS`/`ExpandMask` procedures built on
them, plus the two coefficient extractors from 7.1.

All three samplers consume a seed-dependent amount of XOF stream — that is
what rejection sampling means — so they read through `squeeze()` rather than
asking `finish()` for a fixed length. This is the second concrete consumer of
incremental squeezing, after ML-KEM's `SampleNTT`.

Three details that are invisible without an external vector:

- **The XOFs are not interchangeable.** `RejNTTPoly` and `ExpandA` use
  SHAKE128 (the standard's `G`); `SampleInBall`, `RejBoundedPoly`, `ExpandS`
  and `ExpandMask` use SHAKE256 (`H`).
- **`ExpandA`'s seed is transposed**: `rho || s || r` for `A[r][s]` — the
  *column* byte before the row byte, exactly as ML-KEM's
  `SampleNTT(rho || j || i)` is. Getting it backwards transposes the matrix
  and changes every key byte.
- **`CoeffFromHalfByte`'s two cases are not symmetric.** At η = 2 it is
  `2 − (b mod 5)` for b < 15 — fifteen inputs onto five outputs, three each —
  and at η = 4 it is `4 − b` for b < 9. Reading the first as "b < 5" would
  reject two thirds of valid inputs.

Pinned against known answers generated by a Python reference that was itself
cross-checked against dilithium-py 1.4.0, which agreed on SampleInBall, the
full ExpandA matrix and both ExpandS vectors for all three parameter sets. The
test also proves the ExpandA byte order directly rather than only through a
fingerprint, and checks that `s2[0]` differs from `s1[0]` — if ExpandS
restarted its index counter instead of continuing at `r + l`, those two would
be identical.

9 test cases, 8004 assertions.

## Portability: building on Linux/GCC, and `find_package` support

← [History](../HISTORY.md)

Reported from downstream — cppskit's libcskcwk consumes libcertpp as an
installed static package for P2P node-certificate authentication, and could
not build on Ubuntu 24.04 with GCC 13.3. Four distinct problems, all of which
MSVC had been hiding.

#### 1. Missing `template` on a dependent member template

`TString`'s converting constructor and its cross-type `append()` both call
`cStr.convertTo<T>()` where the object's type depends on a template
parameter. Standard C++ needs `cStr.template convertTo<T>()`; without it the
`<` parses as less-than. MSVC accepts the bare form, GCC and Clang reject it,
and since `string.hpp` is included almost everywhere this failed most
translation units. The report named one site; there were two.

#### 2. Temporaries bound to `SByteSpan&` (13 call sites)

`hasher->finish(SByteSpan(...))` passes a temporary to a non-const lvalue
reference, which MSVC allows as an extension and GCC/Clang reject.

Rather than name a local at each of the 13 sites, `IHasher::finish()` now
takes `const SByteSpan&`. That is the right fix rather than the expedient one:
no implementation ever reassigned the span, the sibling `SHAKE*::squeeze()` in
the same classes already took `const SByteSpan&`, and the newer APIs in this
library (`CSecure::zero`, `CMlKem`, `MlDsaCodec`) all use the const form. The
span's `data` is a `uint8_t*`, so the buffer is still writable; only
reassignment is prevented.

The distinction is principled, not blanket: `IAsymmetricContext::sign()` and
`CBase64::finish()` genuinely do truncate their span to the bytes written
(`out = SByteSpan(out.data, n)`), so those keep `SByteSpan&`.

This is an API change for anyone implementing `IHasher` outside the library —
an override's signature has to match.

It also turned out to fix more than was reported. The 13 sites in `src/` were
the ones the reporter hit, but `tests/` and `examples/` pass temporaries to
`finish()` at 7 more — invisible in their build, which had
`-DCERTPP_BUILD_TESTS=OFF -DCERTPP_BUILD_EXAMPLES=OFF`. Patching the 13 call
sites by hand would have left those broken and the next non-MSVC build would
have hit them. The signature change fixes all 20.

#### 3. `uint64_t*` vs `unsigned long long*` in the ADX/BMI2 path

`_mulx_u64`/`_addcarry_u64` are declared in terms of `unsigned long long*`. On
LP64 targets `uint64_t` is `unsigned long` — a *distinct* type of the same
width — so passing `&x` is a hard error there while compiling fine on Windows,
where the two coincide. The packed 64-bit arrays and locals in
`mulAccelerated()` are now declared `unsigned long long` outright, rather than
casting the pointers, which would compile but alias one integer type as
another.

#### 4. `find_package(certpp)` did not work after install

The install wrote only `certpp-targets.cmake`, and CMake looks for
`certpp-config.cmake` by name. Added that plus a `SameMajorVersion`
`certpp-config-version.cmake` via `CMakePackageConfigHelpers`. The config file
is deliberately minimal — it had a speculative `find_dependency(Threads)` in
its first draft, removed once a grep confirmed the library uses no threading
at all; the one real system dependency, `bcrypt`, is already carried in the
exported targets as `$<LINK_ONLY:bcrypt>`.

#### How these were verified

Not by inspection. Clang was run with `-fno-ms-compatibility
-fno-delayed-template-parsing`, which makes it reject the same constructs GCC
does, across *every* source file in the library — it reproduced exactly the 13
rvalue-binding errors reported, found the second `template` site the report
had not, and now reports nothing. Issues 1, 2 and 4 are additionally covered
end to end: the library was configured with the reporter's exact options
(`-DCERTPP_BUILD_SHARED=OFF -DCERTPP_BUILD_TESTS=OFF
-DCERTPP_BUILD_EXAMPLES=OFF`), installed to a prefix, and consumed by a
separate project through `find_package(certpp REQUIRED)` that hashes, signs
and verifies with a P-256 node key — including a `finish(SByteSpan(...))` call
with a temporary, the exact construct that used to fail.

Issue 3 cannot be reproduced on Windows, where `uint64_t` *is* `unsigned long
long`, so it rests on the type analysis plus the existing `mul()` cross-check
test against an independent reference multiply, which exercises that path.
