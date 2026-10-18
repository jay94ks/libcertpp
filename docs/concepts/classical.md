# Classical asymmetric cryptography

[한국어](classical.ko.md)

## Classical asymmetric cryptography

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`crypto/asyms/rsa.hpp` / `src/crypto/asyms/rsa.cpp`** define `RSA`
  (RFC 8017), the first concrete `IAsymmetric`. Keys serialize as PKCS#1
  DER (`RSAPublicKey`/`RSAPrivateKey`, two-prime form only) via `CDer`.
  `sign()`/`verify()` implement EMSA-PKCS1-v1_5: since `IAsymmetricContext`
  isn't told which hash produced the digest it's given, the DigestInfo's
  hash `AlgorithmIdentifier` is inferred from the digest's byte length (16/
  20/28/32/48/64, covering MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512).
  Other same-width hashers cannot be identified from a digest alone. MD4 is
  the legacy 16-byte collision in that mapping, since it is also 16 bytes
  wide: a 16-byte digest is read as MD5, because `md5WithRSAEncryption` is a
  real (if obsolete) X.509 signature algorithm and `md4WithRSAEncryption` is
  effectively never seen. MD4 exists here for NTLM/EAP-MSCHAPv2's NT hash,
  not for signing, so that is the right way round -- but it is the reason
  digest-length sniffing cannot absorb another 16-byte hash, and a caller
  that genuinely needs MD4-with-RSA has to be given a named-algorithm path
  instead. `signPss()`/`verifyPss()`
  (declared on `IAsymmetricContext` itself, defaulting to `ERET_NOTSUP`
  there since only RSA overrides them) implement RSASSA-PSS (RFC 8017 9.1)
  instead: EMSA-PSS-ENCODE/-VERIFY plus an MGF1 mask built from a caller-
  named `EHashers`, rather than digest-length sniffing -- PSS's own
  `AlgorithmIdentifier` carries its hash/MGF/salt-length explicitly, so
  there's no ambiguity to resolve the way plain `sign()`/`verify()` have to.
  `createEncrypter()`/`createDecrypter()` implement RSAES-PKCS1-v1_5,
  using `CRng::fillNonZero()` for its padding. The private `RsaPublicKey`/
  `RsaPrivateKey`/`RsaContext`/`RsaTransformer` classes back the public
  `IPublicKey`/`IPrivateKey`/`IAsymmetricContext`/`IAsymmetricTransformer`
  interfaces respectively, same pattern as `MemStream` backing `IStream`.

  Every private-key operation (`sign()`, `signPss()`, `decryptBlock()`)
  goes through `RsaContext::privateExp()`, which uses CRT (Garner's
  formula) instead of a single full-modulus `modExp(x, d, n)`: it computes
  `m1 = x^dp mod p`, `m2 = x^dq mod q` (each a modular exponentiation over
  a modulus roughly half the bit length of `n`, so each is individually
  about 4x cheaper than the full-width version, and the two are
  independent of each other), then combines them via `h = qInv*(m1 - m2)
  mod p; m = m2 + h*q`. This only runs when all of `p`/`q`/`dp`/`dq`/`qInv`
  are present on the key (true for anything this library's own
  `generateKeyPair()` produces, but not guaranteed for a key imported via
  `createPrivateKey()` with only `n`/`d` populated) -- `privateExp()` falls
  back to plain `modExp(x, d, n)` whenever any CRT parameter is missing.
  Even when CRT parameters are present, the result is never returned
  directly: `privateExp()` always re-encrypts it (`modExp(m, e, n) ==
  x?`) before handing it back, falling back to plain `modExp` on any
  mismatch. This check is simultaneously the standard Lenstra/Bellcore
  fault-attack countermeasure (a single bit-flip during the CRT
  computation, whether from a hardware fault or a corrupted/inconsistent
  key, produces a faulty signature that -- for RSA specifically --
  leaks a factor of `n` via `gcd(x - m^e, n)`, so skipping the check isn't
  an option) and a safety net making CRT correct to use even on an
  imported key whose CRT parameters were never independently validated via
  `checkPrivateKey()`.

  RSA key objects cache Montgomery contexts for the public modulus `n` and the private CRT moduli
  `p` and `q`. Repeated public operations, private CRT exponentiations, and the private-operation
  fault check therefore reuse `R`, `R^2`, and packed moduli instead of rebuilding them with two
  long divisions per call. Exponents up to 64 bits remain in fixed-width
  64-bit Montgomery storage for the complete square-and-multiply chain. Longer exponents use a
  four-bit sliding window, widened to five bits above 512 bits, and keep the accumulator and odd
  powers packed for the whole chain. BMI2/ADX and an exact Tiger Lake tuning target are selected
  only after cached runtime feature checks. The generic BMI2/ADX gate decodes CPUID directly, so it
  does not depend on the compiler accepting a particular `__builtin_cpu_supports` feature string.
  The common 1024- and 2048-bit moduli select separate
  16- and 32-limb kernels once per exponentiation, so the compiler can unroll the integrated
  product/reduction loop without adding a limb-count branch to every inner iteration. Other sizes
  retain the runtime-count kernel. Squaring steps use matching fixed-count wrappers that pass one
  packed operand to both sides of the same CIOS body. This preserves the multiplication and
  reduction schedule while letting the compiler remove the independent right-operand address
  chain. These paths do not change `CBigNum`'s documented variable-time boundary.

  `decryptBlock()`'s EME-PKCS1-v1_5 unpadding (RFC 8017 7.2.2) scans the
  decrypted block for its `0x00`/`0x02` lead bytes and `0x00` separator in
  constant time: the separator search always runs the full `keyBytes - 2`
  iterations (never stopping at the first `0x00`), and every check -- lead
  bytes, separator found, minimum 8-byte padding length -- is folded into
  one bitmask via bitwise AND/OR rather than a chain of early-return
  branches, the same discipline `CbcTransformer`'s PKCS#7 check already
  applies (see its own doc comment below). The original version's
  data-dependent-length scan plus early-return branches on the lead
  bytes/separator position had the textbook Bleichenbacher-oracle shape:
  every failure path already returned the same `ERET_BADREQ`, but the
  *time taken* to reach it still leaked which check failed and where.
- **`crypto/asyms/dsa.hpp` / `src/crypto/asyms/dsa.cpp`** define `DSA`
  (FIPS 186-4), sign/verify only -- DSA has no encryption operation, so its
  `DsaContext::createEncrypter()`/`createDecrypter()` unconditionally
  return `ERET_NOTSUP`. `keySizes()` accepts exactly the three FIPS 186-4
  (L, N) pairs (1024/160, 2048/256, 3072/256), selected by L alone;
  `generateKeyPair()` generates fresh domain parameters (p, q, g) itself
  (FIPS 186-4 A.1.1.2's probable-primes construction, minus the seed/
  counter bookkeeping needed to later re-verify a parameter set's
  provenance) rather than requiring them supplied separately, since this
  library has no separate domain-parameter type to share them through.
  Private keys serialize as the traditional (OpenSSL-compatible)
  `DSAPrivateKey` DER layout; public keys as this library's own
  `SEQUENCE { p, q, g, y }` (there's no equally simple traditional
  single-blob public-key format -- OpenSSL's splits the domain parameters
  into a `SubjectPublicKeyInfo` `AlgorithmIdentifier`, which this library
  doesn't model yet). Signatures serialize as the standard
  `Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279).

  `sign()`'s `g^k mod p` term uses a Montgomery context cached with the private
  key and `CMontgomery::modExp()`'s four-bit sliding window. Verification calls
  `CMontgomery::modExpProduct()` to compute `g^u1*y^u2 mod p` with one shared
  squaring chain and a 16-entry two-bit product table; native Clang x86-64
  builds keep that table and every intermediate packed until the final
  conversion. The 2048-bit modulus uses the same fixed 32-limb kernel as RSA's public modulus.
  `CBigNum::modInverse()`
  uses binary extended GCD for the odd subgroup order, avoiding quotient-sized
  multiplication and division in signing and verification. The verification
  exponents are public; the exponent-bit branches are therefore acceptable
  there. The signing path is also variable-time because `CBigNum` has
  variable-length storage and is not a constant-time primitive, as documented
  in the public header and caller pitfalls.
- **`crypto/eccurve.hpp` / `src/crypto/eccurve.cpp`** define `CEcCurve`/
  `SEcPoint`, a short-Weierstrass elliptic curve (`y^2 = x^3 + a*x + b mod
  p`) in affine coordinates. Public rather than a `src/`-only implementation
  detail, for the same reason as `CBigNum`: the group arithmetic isn't tied
  to any one algorithm. `add()`/`doublePoint()` implement the group law
  directly in affine form (one modular inversion per call each) -- still
  the simplest path for a single one-off group operation, and what
  `isOnCurve()`/`encodePoint()`/`decodePoint()` and this library's known-
  curve self-checks build on. `scalarMul()` (an arbitrary point times an
  arbitrary scalar) and `scalarMulBase()` (`g` times a scalar, e.g. every
  sign()/verify() call's `k*g`/`u1*g` term) instead work internally in
  Jacobian coordinates (`X/Z^2, Y/Z^3`, `Z == 0` for infinity). On x86-64
  Clang/GCC builds with native 64-by-64-to-128 multiplication, coordinates
  stay in stack-resident, fixed-width 64-bit Montgomery limbs. The field selects a fixed-count
  multiplication kernel for each supported limb width, letting the compiler unroll product and
  reduction loops. Four-bit
  private-scalar windows scan all 16 candidates and select with masks; the
  exact standard P-256 parameters additionally use a process-wide 37-row, seven-bit comb
  table. Its batch-normalized affine coordinates retain only four field limbs per coordinate,
  and selection scans every entry with one-way masked assignments. This removes per-call point
  doublings and permits mixed additions. P-256 uses its sparse
  modulus during Montgomery reduction and the `a == -3` doubling formula.
  Reusable P-256 verification contexts use a separate position-dependent four-bit comb because
  both verification scalars are public. Its 60 KiB base table is shared process-wide and each
  bound public key retains one 60 KiB table; direct lookup replaces 256 point doublings with at
  most 128 mixed additions. Other prime curves retain width-eight wNAF verification tables.
  Other builds retain the masked R0/R1 `CBigNum` Montgomery ladder. Both paths
  pay for one final inversion rather than one per scalar bit.
  The per-modulus context is built at the top of `scalarMul()`/
  `scalarMulBase()` and passed down, rather than cached on the `CEcCurve`
  instance: `p`/`a`/`b` are public mutable fields, so a cached context would
  need invalidating whenever a caller wrote to one, and its two divisions are
  unmeasurable next to the scalar multiplication they precede.
  The fixed-width path converts at the scalar-multiplication boundary; the
  fallback uses `toJacobian()`/`toAffineFromJac()`. No Montgomery-form value
  escapes either path. The
  affine `add()`/`doublePoint()`/`isOnCurve()` deliberately stay on
  `CBigNum`'s general path, since a single group operation is dominated by its
  one modular inversion and there is nothing to amortize a context over.
  `scalarMulBase()` avoids secret-indexed fixed-base lookups: both its comb and
  per-call window paths scan every candidate. `doublePointJac()`/`addJac()`
  (Bernstein/Lange `dbl-2007-bl`/`add-2007-bl`, general `a`) and the
  Lopez-Dahab equivalents in `ec2curve.cpp` are written to mutate a
  `CBigNum`/`CGf2m` operand in place whenever that operand's current value
  is never read again afterward, rather than copying it into a fresh
  variable first (each such spot has a comment naming which read is that
  operand's last) -- same in-place-over-copy discipline `CBigNum`/`CGf2m`'s
  own methods follow (see their own doc comments above), just carried
  through to these free functions' local variables too. Neither implementation
  makes a complete side-channel-resistance claim: exceptional point cases have
  data-dependent control flow, and the fallback also allocates and trims
  variable-width `CBigNum` values. A verification context batch-normalizes width-eight affine
  odd-multiple tables for the generator and bound public key once when the key is bound, retaining
  their Montgomery limbs rather than round-tripping each coordinate through `CBigNum`. Repeated
  verification reuses those tables with mixed additions, one Jacobian accumulator, and one final
  inversion. Direct `linearCombination(k1, p1, k2, p2)` callers use width-five signed-window NAF.
  Both paths branch
  and index tables on those public values and are expressly limited to public
  verification scalars; private scalars continue through `scalarMul()` or
  `scalarMulBase()`.
  `EEcKnownCurves` (`ECURVE_P192`/`ECURVE_P224`/`ECURVE_P256`/`ECURVE_P384`/
  `ECURVE_P521`/`ECURVE_SECP256K1`, plus 14 `ECURVE_BPOOLxxxR1`/
  `ECURVE_BPOOLxxxT1` values for the Brainpool curves) names this library's
  built-in curves; `CEcCurve::knownCurves(which, out)` looks one up from the
  private `_knownCurves` array, defined in `eccurve.cpp` with each curve's
  standard domain parameters (FIPS 186-4 for the NIST curves, SEC 2 for
  secp256k1, RFC 5639 for Brainpool -- the R1 curves' `a`/`b` are random;
  each T1 curve is R1's isomorphic "twisted" counterpart with `a = -3 mod
  p`, sharing the same `p`/`n`) in `EEcKnownCurves` order (independently
  verified against a second source before hardcoding, given how silently a
  single wrong hex digit would produce an insecure, non-standard curve that
  still passes this library's own self-consistency tests -- this actually
  happened twice during development, both times caught immediately by
  `verify()` failing; every curve added since is instead checked
  programmatically -- curve-equation and bit-length self-consistency, plus
  a second-source cross-check -- before being hardcoded, precisely to catch
  that class of mistake before it ships).
- **`crypto/asyms/ecdsa.hpp` / `src/crypto/asyms/ecdsa.cpp`** define
  `CEcdsa`, ECDSA (FIPS 186-4) over any `EEcKnownCurves` value, selected via
  its constructor (`CEcdsa(ECURVE_P256)`, etc.) -- one class rather than a
  separate concrete class per curve, since the only difference between them
  is which domain parameters `keySizes()`/`generateKeyPair()`/sign/verify
  use. `CEcdsa` looks its `CEcCurve` up once (via `knownCurves()`) and keeps
  its own copy as a plain value member: the private `EcPublicKey`/
  `EcPrivateKey` classes likewise each keep their own `CEcCurve` copy rather
  than a pointer/reference back to `CEcdsa`'s, since a generated key can
  outlive the `IAsymmetric` instance it came from (e.g.
  `IAsymmetric::builtIn(EASYM_P256)->generateKeyPair(256)` as a one-liner)
  -- an early version stored a raw `const CEcCurve*` there instead, which
  dangled and crashed in exactly that pattern. Private keys serialize as
  this library's own
  `SEQUENCE { version INTEGER (0), d INTEGER, publicKey OCTET STRING }`;
  public keys as a bare SEC1 uncompressed point. The X.509 layer separately
  maps the supported named-curve OIDs to and from `SubjectPublicKeyInfo`.
  Signatures serialize as the standard
  `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279/SEC 1).
  `keySizes()` accepts exactly one size, the chosen curve's fixed field
  width (160/192/224/256/320/384/512/521 bits, depending on curve).
- **`crypto/ec2curve.hpp` / `src/crypto/ec2curve.cpp`** define `CEc2Curve`/
  `SEc2Point`, a binary curve (`y^2 + x*y = x^3 + a*x^2 + b` over GF(2^m))
  in affine coordinates -- `CEcCurve`'s binary-field counterpart, same
  reasoning for being public and affine/non-constant-time, but an entirely
  different group law (no formula is shared with `CEcCurve`) built on
  `CGf2m` instead of `CBigNum` for the field arithmetic. `add()`/
  `doublePoint()` stay affine (one field inversion each); `scalarMul()`/
  `scalarMulBase()` work internally in Lopez-Dahab coordinates
  (`EC2PointLD`: `X/Z, Y/Z^2`, `Z == 0` for infinity) via the same
  branch-free-ladder/cached-fixed-base-table/mutate-in-place-when-safe
  approach as `CEcCurve`'s Jacobian path (see its own doc comment above) --
  `doublePointLD()`/`addLD()`'s formulas were derived from this file's own
  affine ones and independently cross-checked against them (2000+ random
  trials plus edge cases, and an end-to-end ladder run) via a standalone
  Python GF(2^163) implementation before being hardcoded here, per this
  module's established constant-verification discipline (see `_knownCurves`
  below). Fixed-base multiplication and public linear combinations specialize
  the second operand as affine and use `addMixedLD()`; general private-scalar
  multiplication retains the complete projective formula. `CGf2m` dispatches
  the five supported widths to fixed-count PCLMUL product and square kernels,
  then reduces high words directly through the field polynomial; its portable
  path uses the same reducer after the shift-and-XOR product.
  `linearCombination()` provides the same public-verification
  optimization in Lopez-Dahab coordinates and has the same public-scalar-only
  restriction. `field` is a
  non-owning `const SGf2mField*` rather than an owned value, mirroring
  `CGf2m`'s own field pointer, since it's always one of `CGf2m`'s 5 shared
  static singletons (a "B" and "K" curve of the same size use the same
  field) -- see `CGf2m`'s doc comment for why this differs from `CEcCurve`
  owning its `CBigNum` values directly. `EEc2KnownCurves` (`ECURVE2_B163`/
  `ECURVE2_K163` .. `ECURVE2_B571`/`ECURVE2_K571`) names the 10 built-in
  curves; `CEc2Curve::knownCurves()` looks one up from the private
  `_knownCurves` array, defined in `ec2curve.cpp` with each curve's
  standard domain parameters (FIPS 186-4 Appendix D / SEC 2, cross-checked
  against a second source) in `EEc2KnownCurves` order. Every base
  point/order was independently verified two ways before being hardcoded --
  confirmed on-curve (`isOnCurve()`) *and* confirmed to have exactly the
  stated order (`scalarMul(g, n)` reduces to the point at infinity) -- the
  same two-property check this library used for Ed448's algebraically-
  derived base point, and much stronger than either property alone.
  Point encoding is SEC1 uncompressed (`0x04 || X || Y`) only; compressed-
  point decompression (which needs a GF(2^m) quadratic solve `CGf2m`
  doesn't implement) is deferred, since ECDSA sign/verify doesn't need it.
- **`crypto/asyms/ecdsa2.hpp` / `src/crypto/asyms/ecdsa2.cpp`** define
  `CEcdsa2`, ECDSA over any `EEc2KnownCurves` value -- `CEcdsa`'s binary-
  curve counterpart, same constructor-selects-curve shape and same
  by-value curve ownership in its private `Ec2PublicKey`/`Ec2PrivateKey`
  classes (for the identical dangling-pointer reason `CEcdsa`'s own doc
  comment explains). The ECDSA math itself (`r`/`s` reduced mod the
  subgroup order `n`) is unchanged from `CEcdsa`'s, since `n` stays a
  `CBigNum` regardless of curve family; only the signed point's
  x-coordinate needs converting from a GF(2^m) element to an integer
  first, via the field-element-to-integer rule FIPS 186-4 Appendix C.2
  defines for binary curves (a field element's `m`-bit polynomial-basis
  representation, reinterpreted directly as an unsigned integer -- the
  same bytes `CGf2m::toBigEndian()`/`CBigNum::fromBigEndian()` already
  agree on). `keySizes()` accepts exactly one size, the chosen curve's
  field degree `m` (163/233/283/409/571 bits). Serialization formats are
  identical in shape to `CEcdsa`'s.
