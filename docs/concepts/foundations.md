# Core and utilities

[한국어](foundations.ko.md)

## Core types

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`common.hpp`** is the foundation every other header includes. It defines:
  - `CERTPP_API`, the dllexport/dllimport macro switched by
    `__COMPILES_LIBCERTPP__` (set only while building the library itself)
    and `__SHARED_LIBCERTPP__` (set when building/consuming certpp as a
    shared library). Non-MSVC compilers get an empty macro since ELF/Mach-O
    default visibility already exports symbols.
  - Fixed-width integer aliases (`uint8_t` .. `int64_t`, `float32_t`,
    `float64_t`, `size_t`, `ptrdiff_t`, `nullptr_t`) inside `namespace certpp`,
    so the rest of the library uses `certpp::uint32_t` etc. instead of reaching
    into the global namespace.
  - `ERetCode`, the shared status/error-code enum (`ERET_OK`, `ERET_INVAL`,
    `ERET_NOTIMPL`, ...) that fallible operations across the library return,
    instead of each module inventing its own status enum.
  - `using std::swap;`, brought into `namespace certpp` so a hand-written
    move assignment operator anywhere in the library can call unqualified
    `swap(a, b)` per member and have it resolve to `std::swap`. This is
    deliberately a using-declaration, not a custom `certpp::swap<T>`
    template of its own (an earlier version of this file had exactly that,
    with a body identical to `std::swap`) -- an unconstrained template
    named `swap` in `certpp` becomes an argument-dependent-lookup candidate
    for *any* type built out of a `certpp::` type, including ones this
    codebase never declares itself. Concretely, `CDistinguishedName` holds
    a `std::map<ENameType, CName>`; merely moving, assigning, or `.swap()`-ing
    that map makes MSVC-STL's own `<xtree>` code do an unqualified `swap()`
    on internal types (a tree-node pointer, or the comparator
    `std::less<ENameType>`) that are parameterized by a `certpp::` type --
    with a competing `certpp::swap<T>` in scope, that's a hard, unfixable
    ambiguity error (proven by testing several workarounds: relocating the
    swap call only moved which internal STL swap collided, and a per-type
    specific overload -- the trick that fixed `TSpan<T>`/`TReadOnlySpan<T>`
    once for an unrelated `std::sort` collision -- doesn't apply, since the
    colliding type is a private STL implementation detail with no
    declaration to add an overload next to). Replacing the custom template
    with a using-declaration makes `certpp::swap` and `std::swap` the same
    entity, so there's nothing to be ambiguous with, for any type, anywhere.
- **`version.hpp` / `version.cpp`** define `SVersion` (major/minor/patch) and
  `certpp::GetLibraryVersion()`. `HEADER_VERSION` in the header and
  `LIBRARY_VERSION` in the `.cpp` are meant to be compared by consumers to
  detect a header/binary mismatch.
- **`time.hpp` / `time.cpp`** define `STimeSpan` (a millisecond duration,
  entirely inline/`constexpr`: `absolute()`, the `total*()`/unit accessors,
  arithmetic and comparison operators) and `SDateTime`, decomposed
  calendar-field time (year/month/day/hour/minute/second/millisecond + an
  `isUtc` flag). `SDateTime` lives at the top level (not under `asn1/`)
  since it's a general-purpose value type — `asn1/decoder.hpp`'s
  `decodeUtcTime()`/`decodeGeneralizedTime()` and `asn1/encoder.hpp`'s
  `encodeUtcTime()`/`encodeGeneralizedTime()` use it, but so will non-ASN.1
  code (e.g. a certificate's validity period once X.509 parsing exists).
  `now()`/`from()`/`toUtc()`/`toLocal()`/`toSeconds()` all convert through
  `<ctime>`: `gmtime`/`localtime` (via `_s` on MSVC, `_r` elsewhere for
  thread safety) for the tm-from-time_t direction, and `mkgmtimeSafe()`
  (`_mkgmtime` on MSVC, `timegm` elsewhere) for the reverse — `std::mktime`
  is deliberately never used on a UTC-valued `tm`, since it only ever
  interprets its argument as local time. `add()`/`subtract()`/`diff()`
  and the `+`/`-`/`+=`/`-=` operators (`STimeSpan` or millisecond-based)
  round-trip through `toMilliseconds()`/`from()`.
- **`string.hpp`** defines `TString<T>` (default `T = char`), an owning,
  growable, null-terminated string buffer — `TSpan<T>`'s owning counterpart.
  Capacity grows in `CAP_INC` (64-element) increments via `reserve()`;
  `trimExcess()` shrinks back down (freeing entirely when the string is
  empty). Provides `append()`/`erase()`/`find()`/`findLast()`/`subString()`/
  `trim()`/`toLower()`/`toUpper()`/`reverse()`, and converts to/from a
  `TSpan<T>`/`TReadOnlySpan<T>` via `toSpan()`. Entirely templates, so it
  has no meaningful `.cpp` (the stub exists only for consistency).

## Utilities

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`utils/djb.hpp` / `src/utils/djb.cpp`** define `CDjb`, a static-method-only
  DJB hash utility (`SDjbValue = uint32_t`): `compute()` hashes a byte span
  as-is, `computeAsUpper()`/`computeAsLower()` case-fold ASCII letters first
  (for case-insensitive hashing) -- each takes an optional starting `hash`
  so a caller can hash multiple spans as one logical value (`compute(a) `
  then `compute(that result, b)` equals `compute(a+b)` in one call). The
  case-folding functions widen each `char` through `uint8_t` before folding
  it into the hash, not directly to `SDjbValue` -- `char`'s signedness is
  implementation-defined, and a high-bit-set byte (e.g. an escaped
  non-ASCII byte from `CName`) would otherwise sign-extend on a
  signed-`char` platform (MSVC) and hash to a different value than
  `compute()` gives the identical byte on an unsigned-`char` one. Used by
  `CName` to give it a cheap equality pre-check ahead of a full `memcmp`.
- **`utils/hex.hpp` / `src/utils/hex.cpp`** define `CHex`, a single-method
  utility (`static bool decode(const char*, TArray<uint8_t>&)`) that parses
  a hex string (optionally `0x`/`0X`-prefixed) into raw bytes, rejecting
  malformed input. Factored out of what were previously near-duplicate
  hex-parsing helpers in `CBigNum`/`CGf2m` and several `crypto/asyms/`
  implementations; `CBigNum::fromHex()`/`CGf2m::fromHex()` are now thin
  wrappers over it.
- **`utils/secure.hpp` / `src/utils/secure.cpp`** define `CSecure`: the three
  operations on secret bytes that cannot be written the obvious way.
  `zero()` clears a buffer through a volatile function pointer to `memset`,
  so the call cannot be proven ineffective and therefore cannot be removed
  -- a plain `memset` over a local nothing reads again is dead code, and
  MSVC at `/O2` does delete it (checked by reading the generated assembly,
  not assumed). `equalsMask()` compares two spans reading every byte
  whatever the outcome, returning `0xFF`/`0x00` rather than a bool, because
  `std::memcmp` stops at the first mismatch and so leaks the matching
  prefix's length through its running time. `select()` copies one of two
  spans according to such a mask, so a caller can act on a comparison
  without branching on it. There is also a convenience `equals()` returning
  bool, for the cases where that one bit genuinely isn't sensitive.

  The first consumer, and the reason it exists, is ML-KEM's
  `decapsulate()`: the Fujisaki-Okamoto re-encryption check is exactly a
  comparison whose outcome must not be observable, and FIPS 203 separately
  requires the reject flag be destroyed before returning. `CSecure` does
  **not** subsume the inline mask arithmetic in RSA's EME-PKCS1-v1_5
  unpadding or `CbcTransformer`'s PKCS#7 check -- neither is "compare two
  buffers" or "choose between two buffers"; both interleave masking with a
  scan over the padding, so there is nothing here for them to call.

  `CBigNum::secureClear()` is the big-number counterpart, wiping the limb
  allocation (its whole capacity, so limbs above a trimmed length go too)
  and resetting the value to zero. It is opt-in rather than something
  `~CBigNum()` does, which was settled by measurement: clearing on every
  destruction cost 22% across the asymmetric suites and 32% on X25519
  alone, since a scalar multiplication creates a great many temporaries and
  nearly all of them hold public intermediates. Applying it only to named
  secrets costs nothing above the measurement noise. The limitation that
  buys is real and worth stating: temporaries created inside an expression,
  or inside `modExp()`/`modInverse()`, are freed uncleaned, so this narrows
  the window a secret sits in freed memory rather than closing it.

  The values it is applied to are the ones whose exposure is catastrophic
  rather than merely unwanted -- an ECDSA/DSA nonce `k` and the `d*r`/`x*r`
  product beside it (either yields the private key outright from a
  published signature), EdDSA's nonce and the expanded seed behind it,
  X25519's clamped scalar and shared secret, and RSA's CRT intermediates
  (`m1` is `m mod p`, so `gcd(m - m1, n)` is `p` exactly).
- **`utils/bignum.hpp` / `src/utils/bignum.cpp`** define `CBigNum`, an
  arbitrary-precision non-negative integer (little-endian 32-bit limbs,
  schoolbook algorithms throughout -- correctness and simplicity over
  performance, consistent with this library's early-stage priorities). It's
  the shared math type behind every `crypto/asyms/` implementation: `add`/
  `sub`/`mul`/`divMod`/`mod`/`mulMod`/`modSub`/`modNeg`/`shl`/`shr` for basic
  and modular arithmetic, `modExp`/`modInverse`/`gcd` for RSA/DSA/EC-style
  modular arithmetic, and `isProbablePrime` (Miller-Rabin, preceded by
  small-prime trial division)/`generatePrime` (via `crypto::CRng`) for
  RSA/DSA key generation. `fromHex`/`fromLittleEndian`/`toLittleEndian`/
  `fromBigEndianTruncated` round out construction/serialization (the hex
  parsing itself lives in the standalone `CHex` utility, see below);
  `condSwap` is a conditional swap for branch-based scalar-multiplication
  ladders (e.g. `crypto/asyms/x25519.cpp`'s Montgomery ladder). Lives under
  `utils/` rather than `crypto/`, since the type itself is generic math, not
  tied to any one algorithm (or even to `crypto/` specifically) -- only its
  callers are cryptographic.

  **`add`/`sub`/`mul`/`mod`/`mulMod`/`modSub`/`modNeg`/`shl`/`shr` mutate
  `*this` in place and return `CBigNum&` (a reference to `*this`), purely to
  allow chaining (`a.mulMod(b, m).add(c)`) -- they are NOT a
  functional/copy-returning API, unlike a first instinct from their names
  might suggest. A caller that still needs the pre-call value of the
  receiver must copy it explicitly first (`CBigNum saved(original);
  saved.add(x);`), including when the receiver is itself passed back in as
  the `other`/`modulus` argument to a *different* variable's call a few
  lines later (the classic bug this shape invites: mutating a curve's own
  domain parameter, a function's by-reference out-parameter, or a value
  still needed on a later loop iteration, because it happened to be the
  left-hand operand of an otherwise-innocuous-looking expression). Calling
  one of these on a fresh temporary or an rvalue chain (`CBigNum(1).shl(8)`,
  or `CBigNum::modExp(...).mulMod(x, m)`) is always safe, since nothing else
  can be holding a reference to a temporary. `divMod` is the one exception:
  it stays a `const` query reporting both results via out-parameters, since
  it never had a "return the changed value" shape to begin with. Static
  factories (`fromBigEndian`, `fromHex`, ...) and serializers (`toBigEndian`,
  `toLittleEndian`) are unaffected -- they don't operate on an existing
  instance's value, so there's nothing to alias.

  `divMod()` is Knuth's Algorithm D (TAOCP vol. 2, 4.3.1) in base 2^32: it
  normalizes the divisor so its top limb has its high bit set, then produces
  one quotient limb at a time from an estimate over the top two limbs of the
  running remainder, correcting the estimate down and -- rarely -- adding the
  divisor back when it was still one too high. The earlier implementation was
  a bit-serial restoring division: one shift, compare and conditional
  subtract across the whole divisor *per bit of the dividend*. Since every
  `modExp()` performs thousands of reductions, this one routine was the
  dominant cost in RSA, DSA and ECDSA alike -- replacing it took the full
  test suite from 1243s to 140s, with the asymmetric algorithms individually
  7-14x faster.

  Algorithm D's correctness hinges on two things that ordinary use never
  exercises, so both are tested deliberately in `tests/utils/divmod.cpp`:
  the estimate-correction loop, and the add-back branch, which fires on the
  order of once per 2^31 quotient limbs and is *impossible* for a two-limb
  divisor (the estimate is exact there, because the two-limb test then
  examines the whole divisor). Random testing reaches the branch zero times,
  so its inputs were constructed -- exercised exhaustively in a 4-bit-limb
  model of the same algorithm first, then scaled into the top nibble of each
  32-bit limb, which preserves every ratio the estimate depends on. The
  whole routine is also differentially fuzzed against a deliberately naive
  bit-serial reference written using nothing but `CBigNum`'s public
  operations, which is the algorithm this one replaced.

  `mul()` additionally has a hardware-accelerated path (x86-64 only, and
  only when `CERTPP_DISABLE_HWACCEL_SIMD` isn't set): `mulAccelerated()`
  reinterprets pairs of the native 32-bit limbs as 64-bit digits and uses
  MULX (BMI2)/ADCX (ADX) instead of the portable loop's 32-bit schoolbook
  multiply-accumulate, gated behind a runtime CPUID check (`hasAdxBmi2()`)
  since both extensions are optional even on x86-64. Given how much of this
  library depends on `mul()` being correct, this path is verified by a
  dedicated fuzz-style cross-check (`tests/utils/bignum.cpp`, against an
  independent reference multiply built only from `add()`/`shl()`/
  `testBit()`) across many random operand pairs, in addition to running
  this library's whole test suite under both `CERTPP_DISABLE_HWACCEL_SIMD`
  settings. That cross-check earned its keep immediately: an early version
  tried to fold a 64x64 multiply's high word and an addition's carry-out
  into one running "carry" value added straight into the next column,
  which is unsound whenever the three-way sum (the running carry, the
  existing accumulator digit, and the new digit's low word) needs a
  carry-out of 2 -- something a single `_addcarry_u64` chain can't
  represent (it can only ever produce 0 or 1). The fix restructures each
  row into the classic two-step "long multiplication" shape -- first
  compute the whole row `ai * b[]` on its own (safe: every step there only
  ever combines two 64-bit values plus an implicit carry-in), *then* add
  that row into the running total via an ordinary multi-precision add
  (equally safe, same reason) -- rather than trying to fuse both steps
  into a single pass.
- **`utils/montgomery.hpp` / `src/utils/montgomery.cpp`** define
  `CMontgomery`: one **odd** modulus together with the constants that let
  modular arithmetic against it run with no big-number division at all --
  Montgomery's `n' = -m^-1 mod 2^32` and `R^2 mod m`, where
  `R = 2^(32*limbs(m))`. It exists because `CBigNum::mulMod()` has nowhere to
  cache anything: it is necessarily `mul()` then `mod()`, and `mod()` is a full
  Knuth-D long division, so every single modular multiply inside a scalar
  multiplication paid for one. `CMontgomery` hoists that cost out of the loop
  — two divisions once, at construction, against the thousands the loop would
  otherwise perform.

  It is **additive, not a replacement**: `CBigNum::mod()`/`mulMod()` are
  unchanged and still the only option for an even modulus, which Montgomery
  reduction cannot handle (it needs `gcd(R, m) == 1` with `R` a power of two).
  A `CMontgomery` built from an even or zero modulus reports `isValid() ==
  false` and turns every operation into a no-op rather than computing
  something plausible-looking.

  Two domains are in play. *Ordinary* form is the plain residue `a`;
  *Montgomery* form is `a*R mod m`. `toMont()`/`fromMont()` convert,
  `one()` is the Montgomery form of 1 (what a projective `Z = 1` must be
  initialized to), and `mul()` multiplies two Montgomery-form values into a
  third. `add()`/`sub()`/`dbl()`/`neg()` are valid in *either* domain, since
  `a -> a*R` is linear — and they matter as much as `mul()` does, because the
  code they replaced spelled addition as `.add(x)` followed by `.mod(p)`, i.e.
  a long division to reduce a sum that was at most `2p`. `mulMod()` is the
  ordinary-form drop-in for `CBigNum::mulMod()` for a caller that does not want
  to think about domains, and `modExp()` is square-and-multiply in the domain.

  The multiply itself is CIOS (Coarsely Integrated Operand Scanning): the
  schoolbook multiply and the reduction are interleaved per limb of the second
  operand, so the accumulator never exceeds `limbs(m)+2` words and lives in an
  on-stack buffer (sized for 80 limbs, well past P-521's 17, so no curve
  operation allocates). It reaches `CBigNum`'s raw limb array through
  `friend class CMontgomery` rather than new public limb accessors — the
  representation stays `CBigNum`'s own business, and avoiding the per-operation
  copying is the entire point of the class.

  Its final step is the conditional subtraction that brings a result in
  `[m, 2m)` back below `m`. Skipping that is the classic Montgomery bug and it
  only shows on about half of all inputs, never on a hand-picked small case, so
  the class is tested the way `CBigNum::divMod()` is: differentially, against
  the `CBigNum` operation each method is the fast path for, over every modulus
  the library actually ships (the 29 `CEcCurve` parameter sets' `p` and `n`,
  plus edwards448's `p` and `L`), random odd moduli from 1 to 32 limbs,
  exhaustively over `[0, 2m+2]^2` for single-limb moduli, the hand-picked
  `0`/`1`/`m-1`/`m`/`m+1`/`m^2-1`/`m^2+m` operand classes per modulus, and
  200-step chained sequences that would expose an error that only accumulates
  (`tests/utils/montgomery.cpp`, ~915k assertions). Dropping the conditional
  subtraction, perturbing `n'`, or omitting one `fromMont()` each fail it.
- **`utils/gf2m.hpp` / `src/utils/gf2m.cpp`** define `CGf2m`, a binary
  field GF(2^m) element (polynomial basis) -- the field arithmetic
  `CEc2Curve`'s binary curves need, and which `CBigNum` cannot provide
  (`CBigNum` is arbitrary-precision integer arithmetic mod a prime; GF(2^m)
  addition is XOR with no carry, multiplication is carry-less and reduced
  by a fixed irreducible polynomial, not integer division). Fixed-capacity
  (`uint64_t[9]`, 576 bits, covering every field this library defines up to
  GF(2^571)) rather than arbitrary-precision like `CBigNum`, since a field
  element's width never grows past its field's fixed `m`. `add()` is XOR;
  `mul()` is schoolbook shift-and-XOR carry-less multiply followed by
  reduction against the field's trinomial/pentanomial reduction
  polynomial -- or, on x86/x86-64 with `CERTPP_DISABLE_HWACCEL_SIMD` unset and a
  runtime CPUID check confirming PCLMULQDQ support, a fixed 9x9 grid of
  hardware carry-less multiplies (`_mm_clmulepi64_si128`) building the same
  pre-reduction wide product instead, with the reduction step
  itself unchanged either way. That reduction (`reduceWide()`) is word-level,
  not bit-serial: `x^m == x^terms[0] + ... + 1` displaces *every* excess bit
  by the same amount, so the whole excess folds at once -- take
  `hi = wide >> m`, clear from bit `m` up, then XOR `hi` back in at offset 0
  and at each term offset, repeating until nothing remains at or above `m`
  (exactly twice for all five fields here). The earlier bit-serial version
  walked one bit at a time from `2m-2` down to `m`, toggling `1+termCount`
  bits per set bit, which measured at 95-98% of a multiplication's cost and
  so left the PCLMULQDQ product buying almost nothing; `square()` is implemented as `mul(self)` rather than a
  dedicated bit-spread fast path -- correct and much simpler, the same
  performance/simplicity trade-off `CBigNum`/`CEcCurve` already make;
  `inverse()` is the binary extended Euclidean algorithm over `GF(2)[x]`.
  `fromHex()` parses a hex string (via `CHex`, see below); `toInteger()`
  reinterprets this element's polynomial-basis bits as a `CBigNum` (FIPS
  186-4 Appendix C.2), bridging into `CBigNum` arithmetic where `CEcdsa2`
  needs it (e.g. reducing a binary-curve point's x-coordinate mod the
  subgroup order `n`, which is a `CBigNum` even on a binary curve).

  Like `CBigNum` above, `add`/`mul`/`square`/`inverse` mutate `*this` in
  place and return `CGf2m&` for chaining only -- the same "copy first if you
  still need the original" rule applies (see `CBigNum`'s note on this).
  `EGf2mKnownField` names the 5 field sizes (163/233/283/409/571) this
  library's binary curves use -- a "B" and "K" curve of the same size share
  the identical field, only their curve coefficients differ, so the field
  is a `CGf2m`-owned, non-owning `const SGf2mField*` pointing at one of 5
  program-lifetime singletons (via `knownField()`/`knownFieldPtr()`),
  mirroring `CEcCurve`'s known-curves lookup. Those singletons live behind
  a construct-on-first-use function-local `static` rather than a plain
  `CGf2m::_knownFields` class-static array: `CEc2Curve::_knownCurves`
  (`ec2curve.cpp`, a different translation unit) reads them while *it*
  is being statically constructed, and the standard doesn't guarantee
  which translation unit's static objects finish initializing first --
  this bit the initial implementation immediately (every `CEc2Curve`
  coefficient/point silently ended up as a zero-valued, null-field `CGf2m`,
  because the shared field singletons hadn't been populated yet when they
  were read, and `CGf2m::fromBigEndian()`'s bounds check against the
  not-yet-real `field.m` failed every single bit, leaving its `out`
  parameter untouched at its all-null default -- caught by a `SIGSEGV` the
  first time arithmetic dereferenced that null field pointer). The
  function-local `static` sidesteps the ordering question entirely: it's
  guaranteed initialized on first use, regardless of which translation
  unit's static initializer calls it first. The reduction polynomials
  themselves (FIPS 186-4 Appendix D / SEC 2's standard trinomials/
  pentanomials) were independently confirmed irreducible of the correct
  degree via a standalone check (Python's `sympy`) before hardcoding.
