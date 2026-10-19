# Asymmetric interfaces and modern curves

[한국어](asymmetric.ko.md)

## Asymmetric interfaces

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`crypto/asym.hpp`** defines `IAsymmetric`, `IAsymmetricContext`, and
  `IAsymmetricTransformer`. `IAsymmetric` holds no key material: `keySizes()`
  describes what the algorithm accepts, `generateKeyPair(rng, keySize, out)`
  creates keys, `createPublicKey(out, bytes)`/`createPrivateKey(out, bytes)`
  deserialize keys, and `createContext(out, rng)` returns a key-less
  `IAsymmetricContext`. These `ERetCode` plus out-parameter forms are the
  primary APIs: they reset the output on failure and distinguish size,
  encoding, parameter, allocation, and RNG failures. The older pointer-returning
  key and context factories remain as compatibility wrappers and return null
  for any non-`ERET_OK` result. A key's `serialize(COctet& out)` already uses
  the same error-reporting form.

  Context construction accepts either a `shared_ptr<IRng>`, which the context
  owns, or a `const IRng&`, which is cloned first. The owned generator is fixed
  for the context's lifetime and is used by randomized signatures and RSA
  encryption padding. The no-RNG overload constructs a local `CRng` and
  delegates to this path. Key generation similarly prefers a `const IRng&`;
  its compatibility overload creates a local `CRng`.

  `generateKeyPair()` reports its result via `ERetCode` (an out-parameter
  `SKeyPair& out`, not a return value) rather than the empty-`SKeyPair`-on-
  failure convention an earlier version used, so a caller can distinguish
  *why* generation failed -- in particular, `ERET_AGAIN` specifically means
  the freshly generated key failed `checkPrivateKey()`'s validation (see
  below) and the caller should simply call `generateKeyPair()` again, as
  opposed to a structural failure (`ERET_KEY_SIZE` for an unsupported
  `keySize`, `ERET_UNKNOWN` for an RNG/arithmetic failure) that retrying
  won't fix. Every concrete implementation validates its own freshly built
  key via `checkPrivateKey()` before returning it, rather than looping
  internally on a validation failure -- looping is the caller's decision,
  not something hidden inside `generateKeyPair()`. Importantly,
  `checkPrivateKey()`'s own diagnostic code is never forwarded directly --
  `generateKeyPair()` always translates any non-`ERET_OK` result into
  `ERET_AGAIN`, since a fresh candidate's *specific* rejection reason isn't
  actionable for a caller who's just going to try again, and conflating the
  two would make `ERET_AGAIN` ambiguous for a caller validating a
  deserialized key directly (see `checkPrivateKey()` below) where retrying
  isn't a coherent response at all.

  `checkPrivateKey(key)` validates a private key's structure -- both a
  freshly generated one (called internally by `generateKeyPair()`, as
  above) and one parsed from untrusted storage via `createPrivateKey()`
  (called directly). Since retrying isn't coherent for the latter case, it
  reports *why* validation failed instead of `ERET_AGAIN`: `ERET_KEY_FORMAT`
  if `key` wasn't created by this algorithm instance (wrong concrete type),
  `ERET_KEY_ERROR` if `key` is internally inconsistent (e.g. its linked
  public key is missing or of the wrong type), or `ERET_KEY_PARAM` if a
  structural check on its own parameters/derived values fails. The same
  three-way distinction (missing vs. wrong type vs. bad value) is applied
  throughout `sign()`/`verify()`/`deriveSharedSecret()` too: each first
  checks whether the context's bound key is present at all (`ERET_KEY_EMPTY`
  if not), then whether it's this algorithm's own concrete key type
  (`ERET_KEY_FORMAT` if not) -- distinguishing "nothing bound" from "the
  wrong algorithm's key pair was bound to this context"
  (`IAsymmetricContext::keyPair()` itself doesn't type-check what it's
  given).

  For the elliptic-curve algorithms (`CEcdsa`/
  `CEcdsa2`/`Ed25519`/`Ed448`), this means the classic four checks on the
  key's derived public point Q (point-at-infinity, field range, curve
  equation, correct-order subgroup: `n*Q` must reduce to the identity) plus
  (for `CEcdsa`/`CEcdsa2` only -- see below) the private scalar's own range
  `d in [1, n-1]` -- and a fifth check every algorithm here applies
  regardless of curve family: that Q is *this key's own* point, not merely
  *some* well-formed one. `CEcdsa`/`CEcdsa2` recompute `d*G`
  (`scalarMulBase()`) and compare against Q directly; `Ed25519`/`Ed448`
  re-derive the scalar `s` from the stored seed (the same
  `deriveFromSeed()` signing itself uses) and compare `s*B` against Q;
  `RSA`/`DSA` (see below) and `X25519` apply the same idea to their own
  shape instead -- without this, a private scalar could be paired with an
  unrelated but independently well-formed public key/point and still pass
  every other check. `X25519` (a Montgomery curve, u-coordinate only, cofactor
  8, twist-secure by design) uses RFC 7748-appropriate analogues instead:
  field range, reject an all-zero derived public key (RFC 7748 6.1's own
  rule, applied to key generation rather than the ECDH output), and recompute
  the public value from the private scalar. The scalar clamp makes it a
  multiple of 8, so multiplication by the standard base point already lands
  in the prime-order subgroup; once the derived value is nonzero, a second
  `8*u` ladder cannot reject another case. Peer public keys deliberately have
  no curve-equation check, since X25519 accepts u-coordinates from either the
  curve or its quadratic twist by design; `deriveSharedSecret()` rejects the
  all-zero result from a low-order peer. `Ed25519`/`Ed448`
  skip the scalar-range check `CEcdsa`/`CEcdsa2` have: RFC 8032 5.1.5/5.2.5's
  clamped scalar is deliberately *not* meant to be less than the group
  order (clamping fixes it into a fixed high bit range instead), unlike
  ECDSA's `d`. `RSA`/`DSA` (not elliptic-curve algorithms) implement their
  own analogous structural checks instead of the four EC-point checks: RSA
  validates `p`/`q` are distinct probable primes, `n == p*q`, `e` is
  coprime to `phi(n)`, `d` is `e`'s modular inverse mod `phi(n)`, and the
  CRT parameters (`dp`/`dq`/`qInv`) are consistent with `d`/`p`/`q`; DSA
  validates `p`/`q` are probable primes, `q` divides `p-1`, `g` has order
  `q`, `x` is in `[1, q-1]`, and `y == g^x mod p` -- both also dynamic-cast
  their own `IPrivateKey::publicKey()` first (`ERET_KEY_ERROR` if that
  fails) and check its stored fields (`n`/`e` for RSA; `p`/`q`/`g`/`y` for
  DSA) match the private key's own, the same "Q is *this key's* point, not
  just *some* point" idea the EC/EdDSA algorithms apply via `d*G`/`s*B`
  above. `X25519`'s `checkPrivateKey()` does the analogous thing by
  re-deriving `u` from the stored raw scalar and comparing its little-endian
  encoding against the linked public key's stored bytes.

  `IAsymmetricContext`
  holds a bound key pair (`keyPair()`, cleared via `reset()`; both notify
  the `protected` `onReset()` hook so a derived class can invalidate
  anything it derives from the key) and acts on it directly: `sign()`/
  `verify()` return `ERetCode` (not `bool`, so "doesn't match" is
  distinguishable from `ERET_NOTSUP`/an error) and default to `ERET_NOTSUP`,
  `IStream`'s not-every-implementation-supports-this pattern.
  `deriveSharedSecret(peerPublicKey, out)` follows the same optional-
  capability idiom, for Diffie-Hellman-style key agreement (`X25519`, and
  `CEcdsa` for prime-curve ECDH): it combines the context's own bound
  private key with an explicitly passed peer public key, unlike every other
  method here, which acts only on the bound key(s) -- the minimal addition
  needed to fit a two-party operation into an interface otherwise built
  around a single bound key pair.

  Prime-curve ECDH lives on `CEcdsa`'s context rather than a separate
  `CEcdh` because an ECDH key pair over a prime curve *is* an ECDSA key pair
  -- RFC 5480's `id-ecPublicKey` `SubjectPublicKeyInfo`, with the same curve
  OID, serves both -- so a separate algorithm would have meant a second
  `EAsymmetrics` enumerator describing one encoded key, and `IKeyBase::
  algorithm()` exists precisely to pick that OID. It also matches `RSA`,
  whose one context already carries sign/verify alongside
  `createEncrypter()`/`createDecrypter()`. One generated key pair therefore
  binds to one context and does both. The shared secret is the
  x-coordinate of `d*Q` alone, left-padded to `CEcCurve::fieldByteLen()`
  (RFC 5903 section 7 -- not the full point, not a hash of it); callers run
  it through `CHkdf`. The peer point is re-validated against the *bound
  key's own* curve (not infinity; `0 <= x, y < p`; on the curve) rather than
  trusted from whatever curve the peer's key object carries, which is what
  stops an invalid-curve attack; there is deliberately no small-subgroup
  check, since every `CEcCurve` prime curve has cofactor 1, the opposite of
  `X25519`'s cofactor 8. **It is not constant-time** -- see
  `CEcCurve::scalarMul()`'s own note and the doc comment on
  `EcContext::deriveSharedSecret()`.

  `sign()`/`deriveSharedSecret()`'s `out` parameter is a fixed, caller-
  allocated `SByteSpan&` (not a growable `TArray<uint8_t>&`): the caller
  queries `sizeOfSign()` first, allocates a buffer at least that large, and
  passes it in; the implementation writes into `out.data` and narrows
  `out` to the actual bytes produced (`out = SByteSpan(out.data,
  actualLen)`) before returning, or returns `ERET_NOSPC` up front without
  writing anything if the caller's buffer was too small. `sizeOfSign()`/
  `sizeOfDigest()` (getters public, setters `protected` -- the same
  split-access pattern `IAsymmetric::keySizes()` already uses) are computed
  in each concrete context's `onReset()` from whichever key is bound
  (private key first, then public, so a verify-only context still reports
  a meaningful `sizeOfSign()`): `sizeOfSign()` is the maximum signature
  size (exact for RSA/Ed25519/Ed448's fixed-format signatures; a safe
  upper bound for DSA/ECDSA/ECDSA2's DER-encoded ones, which are
  frequently 1-2 bytes shorter in practice -- see those modules' own
  bullets for the exact DER-size formula), 0 where `sign()` isn't
  supported at all (`X25519`). `sizeOfDigest()` is the largest digest
  length an algorithm's math actually consumes (the field/subgroup byte
  length for DSA/ECDSA/ECDSA2, since a longer digest is truncated to
  exactly that many bits regardless) -- 0 for RSA (which accepts one of
  six discrete, unrelated lengths depending on hash algorithm, not a
  single "maximum") and for Ed25519/Ed448/X25519 (no digest concept at
  all: EdDSA's `sign()` "digest" parameter is the raw message).

  `createEncrypter()`/`createDecrypter()` are pure virtual instead, since
  asymmetric encryption only ever handles one block at a time -- they hand
  back an `IAsymmetricTransformer` (bound to the same key) for the caller to
  drive via `transform()` (repeatedly, one chunk at a time) then
  `transformFinal()`, rather than a single arbitrary-length call.
  `transform()`/`transformFinal()` take the same fixed `SReadOnlyByteSpan`/
  `SByteSpan&` shape as `sign()`; `IAsymmetricTransformer::blockSize()`
  (getter public, setter `protected`) reports the natural block size for
  the transformer's operation -- for `RsaTransformer`, the RSA modulus
  byte length (the ciphertext block size; PKCS#1v1.5's plaintext block is
  up to 11 bytes smaller, not tracked as a second field).

## EdDSA, X25519, and GOST

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`crypto/asyms/ed25519.hpp` / `src/crypto/asyms/ed25519.cpp`** define
  `Ed25519` (EdDSA over edwards25519, RFC 8032). Its field/point arithmetic
  is dedicated to this one curve rather than routed through `CEcCurve`
  (which only models short-Weierstrass curves; edwards25519 is a twisted
  Edwards curve, with a different, unconditionally-complete addition
  law -- one formula handles both point addition and doubling, unlike
  `CEcCurve::add()`/`doublePoint()`).

  **Two moduli, two types.** Ed25519 works modulo the field prime `p =
  2^255 - 19` for point coordinates and modulo the group order `L = 2^252 +
  0x14DEF9DEA2F79CD65812631A5CF5D3ED` for scalars, and the two are kept
  apart by the type system rather than by discipline. Coordinates are
  `Fe25519` (`src/crypto/asyms/fe25519.hpp`, shared with `X25519`), which
  implements `p` and nothing else; scalars -- the clamped private scalar,
  signing's nonce `r`, the reduced hash `k`, a signature's `S` -- are
  `CBigNum` reduced mod `groupOrder()`. `EdPoint`/`EdPointProj` hold nothing
  but `Fe25519`, and `Fe25519` has no conversion to or from `CBigNum`
  (its only external representation is 32 bytes), so a scalar cannot reach
  field arithmetic or a coordinate reach mod-`L` arithmetic without code
  that does not compile. The distinction matters because reducing a scalar
  mod `p` produces a signature that verifies against itself and against
  nothing else in the world -- a failure no self-consistency test can see,
  which is why all five of RFC 8032 section 7.1's byte-exact vectors are
  checked.

  Every curve constant (the equation parameter `d = -121665/121666 mod p`,
  the base point) is *derived* at first use from small integers rather
  than hardcoded as a 255-bit literal, except the group order's addend
  (`0x14DEF9DEA2F79CD65812631A5CF5D3ED`, independently confirmed against a
  second source), which has no simpler closed form -- deriving instead of
  transcribing sidesteps the exact class of mistake the NIST curve
  constants above hit twice. `sign()`/`verify()`'s "digest" parameter is
  unusually the *raw message*, not a hash: pure EdDSA hashes its input
  internally, so there is no caller-supplied digest to accept, unlike
  every other algorithm in this library. Keys and signatures serialize as
  RFC 8032's own raw byte encodings (32/32/64 bytes), with no DER
  structure, since that's what the format already is. Verified against
  all five of RFC 8032 section 7.1's known-answer vectors (the empty
  message, 1, 2, 64 and 1023 bytes) -- EdDSA signing is deterministic
  (no per-signature randomness), so an exact signature byte match
  validates the whole pipeline (arithmetic, derived constants, clamping,
  and the signing algorithm itself) far more strongly than a
  self-consistency round-trip alone could.

  Scalar multiplication works internally in extended projective coordinates
  (`EdPointProj`: Hisil/Wong/Carter/Dawson's `X/Z, Y/Z, T=XY/Z`, "Twisted
  Edwards Curves Revisited") and converts to affine only at an encoding or key
  boundary. Cached and affine-precomputed points reduce mixed additions; public
  double-scalar multiplication also keeps completed `P1P1` and `P2` forms to
  avoid a field multiplication per doubling. `Fe25519::addLoose()` and
  `subLoose()` skip a carry pass only when the result is consumed immediately
  by a multiply or square. The dedicated `square()` kernel is generated and
  mechanically checked by `tools/fe_square_gen.cpp` against `mul()`.

  Secret fixed-base multiplication (`scalarMulBase()`, used for `B*r` and
  `B*s`) recodes the scalar into 64 signed radix-16 digits. Its process-wide
  table has 32 rows containing `(1..8) * 256^i * B`; each selection scans all
  eight entries under arithmetic masks, and zero digits still perform an
  addition. Summing odd digits, doubling four times, then summing even digits
  reduces each operation from 256 point doublings to four without introducing
  a secret-indexed lookup. Arbitrary-point multiplication retains the
  branch-free 256-bit ladder for secret scalars. Verification uses public
  sliding-window digits to compute `S*B - k*A`, where `k = SHA-512(R || A ||
  M) mod L`, in one shared doubling chain. Each `EdPublicKey` prepares and
  retains the eight odd multiples of `A`, so repeated verifications do not
  rebuild the variable-base table. Imported public keys still pass the full
  `L*A` subgroup check. Signature `R` decoding retains canonical, on-curve,
  and identity checks but omits a separate `L*R`: with `A` already in the
  subgroup, the exact uncofactored equation can accept only an `R` in the same
  subgroup. An order-two `R` negative test covers that inference. On 64-bit
  GCC/Clang builds, the default radix-51 field layout uses five unsigned limbs
  and native 64-by-64-to-128 products. Targets without that product retain the
  signed ten-limb radix-2^25.5 fallback. Both layouts use the same fixed-base
  signed-radix-16 path.
- **`crypto/asyms/ed448.hpp` / `src/crypto/asyms/ed448.cpp`** define
  `Ed448` (EdDSA over edwards448/"Ed448-Goldilocks", RFC 8032) --
  structurally `Ed25519`'s twin, with its own field/point arithmetic (a
  different prime, and untwisted rather than twisted Edwards addition, so
  not shared code) and its own private `EdPublicKey`/`EdPrivateKey`/
  `EdContext` classes, but every hash SHAKE256 (114-byte output) rather
  than SHA-512, each prefixed with RFC 8032 5.2's `dom4(F, C)` string
  (fixed here at `F = 0`, empty `C`: `"SigEd448" || 0x00 || 0x00` --
  context strings aren't supported). Its base point is the one constant
  that resisted every attempt to transcribe it directly: repeated fetches
  of "authoritative" sources for its x/y coordinates each produced a
  *different*, self-inconsistent-with-the-real-curve value (one even had
  the wrong bit length outright). It was ultimately derived instead --
  `B = [s^-1 mod L] * A`, where `A` is RFC 8032 TEST 1's known-correct
  public key point and `s` its arithmetically-derived clamped scalar --
  and independently confirmed by regenerating that exact public key from
  it and by checking it has order exactly `L` (both extremely
  discriminating properties, especially the latter: edwards448's cofactor
  of 4 means most curve points don't have order `L` at all).
  Keys/signatures serialize as RFC 8032's raw byte encodings (57/57/114
  bytes). Verified against RFC 8032's own TEST 1 vector, for the same
  reason as `Ed25519`.

  Field operations live in `src/crypto/asyms/fe448.hpp/.cpp`. Native
  64-by-64-to-128 targets use eight radix-2^56 limbs; the portable fallback
  uses sixteen radix-2^28 limbs so its products fit in `uint64_t`. Fixed
  exponent chains implement inversion and point recovery without general
  big-number division. Edwards448 is *untwisted* (`a = 1`,
  vs. edwards25519's `a = -1`), so `pointAddProj()` here uses the general
  `a`-parametrized addition law rather than `Ed25519`'s `a = -1`-specialized
  one -- derived directly from the affine addition law (see this function's
  own comment in `ed448.cpp`) rather than transcribed from a reference,
  since the well-known named formula for this shape is specific to `a =
  -1`. Extended projective coordinates, a dedicated `a = 1` doubling formula,
  and mixed affine/projective addition keep inversions out of scalar loops.

  The private key caches its expanded RFC 8032 scalar and prefix. A
  process-wide 10-column comb table accelerates base-point multiplication,
  and each public key retains an equivalent table for repeated verification;
  table construction batch-normalizes all 1,024 entries with one inversion.
  Verification evaluates `S*B - k*A` with 45 shared doublings and at most 90
  mixed additions. Imported public keys still pass `L*A == 0`. Signature `R`
  decoding keeps canonical, on-curve, and identity checks but omits a separate
  `L*R`: the exact uncofactored equation with `A` already in the subgroup can
  accept only an `R` in the same subgroup, and an order-two `R` negative test
  covers that boundary. Comb indices depend on the scalar, and the group-order
  scalar arithmetic still uses `CBigNum`; Ed448 signing is therefore not
  claimed constant-time.
- **`crypto/asyms/x25519.hpp` / `src/crypto/asyms/x25519.cpp`** define
  `X25519` (Diffie-Hellman key agreement over Curve25519, RFC 7748) --
  same field prime as `Ed25519` (`2^255 - 19`), and in fact the same field
  *implementation* (`Fe25519`, `src/crypto/asyms/fe25519.hpp`), but
  Montgomery-form curve arithmetic rather than twisted-Edwards, since
  X25519 only ever needs the u-coordinate Montgomery ladder (RFC 7748 5),
  not full affine point addition. `sign()`/`verify()` are left at
  `IAsymmetricContext`'s
  `ERET_NOTSUP` defaults (no signing operation exists); only
  `deriveSharedSecret()` is overridden. A private key retains both the caller's
  raw 32 bytes and a clamped working copy, so `serialize()`/`createPrivateKey()`
  round-trip the exact original bytes while repeated scalar multiplications do
  not repeat the clamp and secure-copy work. A context also caches successful
  concrete-type checks for its bound private key and the current peer key.
  `deriveSharedSecret()` rejects an all-zero computed
  secret (RFC 7748 6.1 -- a low-order peer point, e.g. `u = 0`) rather than
  returning predictable output. Keys serialize as RFC 7748's raw 32-byte
  u-coordinate/scalar encodings, no DER. Verified against RFC 7748 5.2's
  Diffie-Hellman and iterated-scalar-multiplication known-answer vectors,
  independently re-derived via a standalone Python implementation of the
  same ladder before hardcoding -- not just transcribed from a single
  fetch, consistent with this module's established constant-verification
  discipline.
