# Post-quantum cryptography internals

[한국어](post-quantum.ko.md)

## Key types and ML-KEM

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`crypto/keys.hpp` / `src/crypto/keys.cpp`** define `SKeySize`/
  `SKeySizeSpec` (a `{minSize, maxSize, step}` range an `IAsymmetric`
  validates its `keySizes()` against); `IKeyBase` (`keySize()`,
  `serialize(COctet&)`, `compare()` -- common to any key, symmetric or
  asymmetric); `IPublicKey`/`IPrivateKey` (extend `IKeyBase` for the
  asymmetric case, `IStream`-style `Ptr` aliases, never constructed
  directly -- only produced by `IAsymmetric`; `IPrivateKey` adds
  `publicKey()` to derive its public half); and `SKeyPair`, a plain struct
  pairing the two (not an interface -- a key pair has no behavior beyond
  its halves). The same header also defines a third, parallel key family
  for KEMs (see `crypto/kem.hpp` below): `EKems`, `IKemKeyBase`,
  `IKemPublicKey`/`IKemPrivateKey`, and `SKemKeyPair` -- mirroring
  `EAsymmetrics`/`IAsymmetricKeyBase`/`IPublicKey`/`IPrivateKey`/`SKeyPair`
  exactly, kept as a separate family (the same reasoning `ESymmetrics`
  already uses) because a KEM key isn't a signature or DH key even though
  it's still asymmetric.
- **`crypto/kem.hpp` / `src/crypto/kem.cpp`** define `IKem`/`IKemContext`,
  the key-encapsulation counterpart of `asym.hpp`'s
  `IAsymmetric`/`IAsymmetricContext`. `IKem::builtIn()` dispatches `EKems`'
  three members -- `EKEM_MLKEM512`/`EKEM_MLKEM768`/`EKEM_MLKEM1024` -- to
  `MLKEM` (`crypto/kems/mlkem.hpp`, below). The interface was designed and
  committed ahead of any lattice-crypto implementation as the first step of
  the ML-KEM work in [`docs/PQC.md`](../PQC.md), which is why it
  mirrors `IAsymmetric` as closely as it does. It deliberately isn't just `IAsymmetric` reused:
  a KEM's core operation produces an algorithm-chosen shared secret
  *together with* the ciphertext that encapsulates it, unlike
  `createEncrypter()`'s "encrypt this caller-supplied plaintext" shape, so
  forcing it onto `IAsymmetric` would mean a `transform()` call whose
  input is ignored -- a worse fit than a small sibling interface. `IKem`
  mirrors `IAsymmetric`'s shape as closely as that one difference allows:
  `builtIn(EKems)`, `keySizes()`, `generateKeyPair()`, `checkPrivateKey()`,
  `createPublicKey()`/`createPrivateKey()` (span and `COctet` overloads),
  and `createContext()`. The primary key parsers and context factory report
  `ERetCode` through out-parameters; pointer-returning overloads remain as
  compatibility wrappers. Key generation accepts `const IRng&`, and a KEM
  context owns the `shared_ptr<IRng>` sealed into it at creation.
  `IKemContext` follows `IAsymmetricContext`'s
  "acts on whichever bound key, not a parameter passed in" convention:
  `encapsulate(SByteSpan& ciphertext, SByteSpan& sharedSecret)` operates on
  the bound *public* key (the peer's, bound via the two-key `keyPair(pub,
  nullptr)` overload -- the caller is encapsulating *to* that peer);
  `decapsulate(SReadOnlyByteSpan ciphertext, SByteSpan& sharedSecret)`
  operates on the bound *private* key. `sizeOfCiphertext()`/
  `sizeOfSharedSecret()` follow the existing getter-public/setter-protected
  split `sizeOfSign()`/`sizeOfDigest()` use.
- **`crypto/kems/mlkem.hpp` / `src/crypto/kems/mlkem.cpp`** implement ML-KEM
  (FIPS 203) and the K-PKE scheme underneath it, over raw byte spans. This is
  the algorithm itself, with no opinion about key objects or contexts, so it
  can be driven straight from a test vector; the `IKem`/`IKemContext` shape
  above is what most callers should prefer, and sits on
  top of this. The header publishes four types:
  - `SMlKemPoly`, one element of R_q = Z_q[X]/(X^256+1) as 256 `int16_t`
    coefficients, carrying `COEFFICIENTS`/`MODULUS`/`ROOT_OF_UNITY`. The same
    layout also holds NTT-domain values, which are 128 degree-1 blocks rather
    than a polynomial; FIPS 203 doesn't distinguish the two in its data types
    either, so which one an instance holds is the caller's to track.
  - `SMlKemParams`, one of FIPS 203 Table 2's three parameter sets as
    `{k, eta1, eta2, du, dv}` plus `mlKem512()`/`mlKem768()`/`mlKem1024()`.
    Only those five figures are stored; `ekBytes()`/`dkBytes()`/
    `dkPkeBytes()`/`ciphertextBytes()`/`sharedSecretBytes()`/`seedBytes()`
    all derive from them, and `tests/crypto/kems/kat_mlkem.cpp` pins the derived
    results against the published table with `static_assert`. A mistyped key
    length is exactly the error that stays internally consistent -- an
    implementation using the wrong `ek` length throughout still round-trips
    with itself -- so the sizes are made impossible to write down wrongly.
    `isValid()` reports whether the set is one of the three, and `equals()`
    compares two; every `CMlKem` entry point calls `isValid()` first and
    refuses otherwise. That is a memory-safety requirement rather than
    pedantry: `SMlKemParams` is public, so a caller can hand over a
    hand-built set, while the implementation sizes its fixed-capacity buffers
    from `MAX_K` and `maxCiphertextBytes()`.
  - `CMlKemSampler`, FIPS 203's two samplers: `sampleNtt()` (Algorithm 7,
    rejection-sampling a uniform NTT-domain polynomial from a SHAKE128
    stream) and `samplePolyCbd()` (Algorithm 8, turning PRF output into the
    small-coefficient noise Module-LWE needs). `sampleNtt()` appends its two
    index bytes in the order given, because FIPS 203's matrix expansion calls
    it as `SampleNTT(rho || j || i)` -- transposed relative to the natural
    loop order, which the standard's own margin note flags.
  - `CMlKem`, the scheme: `generateKeyPair()`/`encapsulate()`/
    `decapsulate()` (Algorithms 16-18), `checkEncapsulationKey()`/
    `checkDecapsulationKey()` (the FIPS 203 6.2 input checks), and
    `kpkeKeyGen()`/`kpkeEncrypt()`/`kpkeDecrypt()` (Algorithms 13-15).
    `encapsulate()` takes the 32-byte message explicitly rather than drawing
    it, so it is reproducible from a vector -- which means a caller outside
    the tests must pass fresh CSPRNG output, since reusing a message reuses
    the shared secret.

  The subtlety is all in `decapsulate()`. ML-KEM is the Fujisaki-Okamoto
  transform over K-PKE, which is what lifts an IND-CPA scheme to IND-CCA2:
  it re-encrypts what it decrypted and compares against the ciphertext it was
  given, and on a mismatch returns `J(z || ciphertext)` -- a secret derived
  from the private key's own rejection seed -- rather than an error. A
  malformed ciphertext therefore yields a well-formed but unrelated shared
  secret, and the caller cannot tell the two cases apart. Reporting failure
  there, or skipping the re-encryption, would hand back exactly the
  decryption oracle the transform exists to deny. That is why `decapsulate()`
  has no failure mode for a bad ciphertext at all, only for a
  structurally wrong-sized one.

  "Cannot tell the two cases apart" has to hold for timing too, so the
  comparison is `CSecure::equalsMask` and the choice between the two secrets
  is `CSecure::select` -- a `std::memcmp` would leak how long a prefix of
  the re-encryption matched, and a ternary on the verdict would leak the one
  bit that verdict is. The function has a single exit so that
  `CSecure::zero` cannot be skipped by an error path, which is FIPS 203's
  requirement that the reject flag be destroyed before returning.

  Validated against NIST's ACVP vectors for all three parameter sets,
  including the `modified ciphertext` cases that exercise that rejection path
  and the `encapsulationKeyCheck`/`decapsulationKeyCheck` negative cases --
  see `tests/crypto/kems/kat_mlkem.cpp`. FIPS 203 publishes no worked examples, so
  those vectors are the only external oracle available.

  The same header then declares **`MLKEM`**,
  `IKem`'s only implementation, serving all three ML-KEM parameter sets from
  one class with the set as constructor state -- the arrangement `CEcdsa` has
  across its curves. It implements nothing cryptographic itself: `CMlKem`
  above is the algorithm, and this is the key objects, the size bookkeeping
  `IKemContext` exposes, and the CSPRNG draws around it.

  `keySizes()` accepts exactly one size per instance, and that size is the
  parameter set's own number (512, 768 or 1024) rather than a modulus width
  or a claimed security strength. ML-KEM has no size that scales -- the sets
  differ in the module rank `k` and four other parameters, and those three
  numbers are names. Passing the name keeps `generateKeyPair()` usable the
  way every other algorithm in the library is, without inventing a figure
  that looks like it means something it doesn't.

  Keys serialize as FIPS 203's own encodings and nothing more: a public key
  is the encapsulation key, a private key the decapsulation key. Since a
  decapsulation key embeds its own encapsulation key at offset
  `dkPkeBytes()`, `IKemPrivateKey::publicKey()` reads it out rather than
  recomputing it, and `checkPrivateKey()` verifies the two agree (plus the
  embedded `H(ek)`, plus that the `ek` is canonical) rather than assuming
  so. `createPublicKey()`/`createPrivateKey()` apply the same checks, since
  a key reaching them came from outside. The SubjectPublicKeyInfo wrapping a
  certificate needs is tracked in [Remaining PQC work](../pqc/implementation.md),
  not here.

  This is also the only layer in the ML-KEM implementation that draws
  randomness. `CMlKem::generateKeyPair()`/`encapsulate()` take their seeds
  and message as parameters so they can be driven from a test vector;
  `IKemContext::encapsulate()` has no such parameter, so `MLKEM` fills them
  from the `IRng` owned by its context. The no-RNG context factory supplies a
  local `CRng`. There is no fixed known-answer test for that default-random
  wrapper path, and `tests/crypto/kems/mlkem.cpp` covers what the wrapper adds
  rather than the algorithm (asserting, among other things, that repeated
  `encapsulate()` calls against one key differ, since a shared secret that
  was a function of the key alone would be reused every session).

  Binding a key to `IKemContext` also prepares the key material used repeatedly: the public
  key's decoded t-hat and expanded A-hat matrix, and the private key's decoded s-hat vector.
  Encapsulation and decapsulation reuse those values until the context is reset. The raw
  `CMlKem` span API remains stateless and prepares its caller-supplied encoding on every call.
- **`src/crypto/kems/mlkemring.hpp`/`.cpp`, `src/crypto/kems/mlkemcodec.hpp`/
  `.cpp`** hold the arithmetic and wire encoding `CMlKem` is built from:
  `MlKemRing` (NTT, inverse NTT, base-case multiply over R_q, plus a
  schoolbook negacyclic multiply that exists only to check the others) and
  `MlKemCodec` (ByteEncode/ByteDecode, Compress/Decompress, `isCanonical12`).
  Both stay private to `src/` -- plain `PascalCase`, no `CERTPP_API` -- since
  nothing outside the ML-KEM implementation has a reason to reach them, and
  `SMlKemPoly` is the one type they share with the public header. Because
  they aren't exported, a test under `tests/crypto/kems/` compiles them into
  its own executable; see [`docs/BUILDING.md`](../BUILDING.md).

## ML-DSA internals

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`src/crypto/asyms/mldsaring.hpp`/`.cpp`** define `MlDsaRing`, arithmetic in
  ML-DSA's ring R_q = Z_q[X]/(X^256 + 1) with q = 8380417 (FIPS 204 4) --
  the first piece of ML-DSA, and also private to `src/`. It is deliberately
  a separate unit from `MlKemRing` rather than a parameterization of it,
  because three differences go deeper than the constants:
  - q = 2^23 - 2^13 + 1, so a coefficient needs 23 bits and `int32_t`
    storage, and a product of two coefficients reaches about 7.0e13 --
    which overflows `int32_t` by four orders of magnitude, so every
    intermediate runs in `int64_t`. In ML-KEM's ring the same product fits
    in `int32_t` with room to spare; carrying that habit across would be a
    silent-wraparound bug. It bites the twiddle-table builder too, where
    `ZETA * acc` reaches about 1.5e10.
  - `ZETA = 1753` has order exactly **512**, not 256, so X^256 + 1 splits
    all the way into 256 linear factors and the NTT is **complete**: eight
    layers, 256 independent evaluation points. ML-KEM's transform stops one
    layer short, leaving 128 degree-1 blocks that need a base-case multiply
    and a second twiddle table. So `multiplyNtt()` here is plain pointwise
    multiplication, and there is no `gammas()` at all.
  - The index permutation is `bitRev8`, over eight bits, against ML-KEM's
    `bitRev7`.

  Beyond the transform it provides `centered()` -- FIPS 204's `mod±`,
  the representative in (-q/2, q/2] -- and `infinityNorm()`, which ML-DSA's
  signing loop rejects on, so it belongs to the ring rather than to a
  caller. Coefficients remain in normal form at every ring boundary. The hot
  NTT loops derive a second twiddle table in Montgomery multiplication form
  and convert each product back immediately, avoiding per-coefficient division
  without changing the transform representation. FIPS 204 Appendix A warns
  that implementations usually store the zetas array in Montgomery form,
  which makes a representation mismatch there exactly the
  self-consistent-but-wrong failure mode this library has been bitten by before, so
  `tests/crypto/asyms/mldsaring.cpp` checks the table against Appendix B's
  printed values as well as against its defining property.
- **`src/crypto/asyms/mldsarounding.hpp`/`.cpp`** define `MlDsaRounding`,
  FIPS 204 7.4's rounding and hint machinery: `power2Round`, `decompose`,
  `highBits`/`lowBits`, `makeHint` and `useHint`, scalar and per-polynomial.
  Also private to `src/`.

  The hint mechanism is why this exists. A signature carries one bit per
  coefficient rather than w1 itself, and the verifier reconstructs
  `HighBits(w - c*s2 + c*t0)` from its own approximation plus those bits --
  which works only if `useHint()` inverts `makeHint()` exactly, and only
  while the perturbation stays within gamma2, a bound the signing loop is
  responsible for enforcing. The test checks that identity over random pairs
  and, separately, at the bucket boundaries and across the carve-out band,
  where random sampling would essentially never land.

  Two traps are documented in the header rather than left to be
  rediscovered:
  - **`decompose()`'s `(q-1)` carve-out is a band, not a point.** Algorithm
    36 branches on `r+ - r0 == q - 1`, which reads like "the single value
    r == q-1" and is not: the condition holds across the whole top band of
    width gamma2 -- 95232 values (1.14% of q) at gamma2 = (q-1)/88, 261888
    (3.1%) at (q-1)/32. The obvious simplification to a point comparison is
    wrong for 95231 inputs in the first case, and only an external vector
    would catch it.
  - **`mod±` here is not `MlDsaRing::centered()`.** That reduces modulo q,
    which is odd, so its split sits at (q-1)/2; these reduce modulo 2^d and
    2*gamma2, both even, where the range is (-m/2, m/2] and m/2 itself stays
    positive. Same definition, different modulus, different edge -- hence a
    separate `modPm()`.
- **`src/crypto/asyms/mldsacodec.hpp`/`.cpp`** define `MlDsaCodec`, FIPS 204
  7.1-7.2's bit packing and hint encoding -- the wire format ML-DSA's keys and
  signatures are built from. `simpleBitPack`/`simpleBitUnpack` handle
  coefficients in [0, b]; `bitPack`/`bitUnpack` handle [-a, b] by encoding
  `b - w_i`, so a signed range fits an unsigned field. Bits run little-endian
  within each byte, as in ML-KEM. The implementation moves those fields through
  a 64-bit reservoir; its widest field is 20 bits, so the next field always fits
  after complete bytes are flushed.

  **Decoding does not imply the range**, and FIPS 204 says so itself under
  Algorithm 17: for some (a, b) there are byte strings that decode outside the
  nominal range, which matters for untrusted input. It turns on whether the
  range exactly fills its bit width, and for ML-DSA's uses it splits cleanly --
  `t1`, `t0` and `z` are safe; `s1`/`s2` are not (at eta = 2 three bits decode
  down to -5, at eta = 4 four bits reach -11), so `skDecode` has to
  range-check; and `w1` is unsafe at b = 43 but is only ever encoded, never
  received. `inRange()` exists for the cases that need it. This is the same
  shape of hazard as ML-KEM's `ByteDecode_12`.

  `hintBitUnpack()` is the sharpest decode trap in the standard, and rejects
  on three *distinct* conditions: a cumulative index that moves backwards or
  past omega; positions not strictly increasing **within one polynomial**; and
  any non-zero leftover byte. Each one is what makes the encoding injective,
  and implementing fewer than all three accepts malleable signatures -- which
  is what ACVP's 36 "modified signature - hint" cases test. The
  within-one-polynomial scope matters in both directions: positions
  legitimately *decrease* across a polynomial boundary, so checking
  monotonicity over the whole array instead rejects valid signatures. A
  rejected decode leaves the caller's polynomials untouched rather than
  half-written.
- **`src/crypto/asyms/mldsasampler.hpp`/`.cpp`** define `MlDsaSampler`, FIPS
  204 7.3's pseudorandom sampling: `sampleInBall`, `rejNttPoly`,
  `rejBoundedPoly` and the `expandA`/`expandS`/`expandMask` procedures over
  them. All three samplers consume a seed-dependent amount of stream, so they
  read through `squeeze()` rather than `finish()` -- which is why incremental
  squeezing was a hard prerequisite rather than a convenience. The rejection
  loops squeeze complete SHAKE rate blocks and consume them in the standard's
  byte, three-byte, or low-nibble-first order; batching changes call overhead,
  not the sampled stream.

  Two things here are easy to get wrong and invisible without an external
  vector. The XOFs are not interchangeable: `rejNttPoly`/`expandA` use
  SHAKE128 (the standard's `G`), everything else SHAKE256 (`H`). And
  **`expandA`'s seed is transposed** -- `rho || s || r` for entry `A[r][s]`,
  the column byte before the row byte, exactly as ML-KEM's
  `SampleNTT(rho || j || i)` is. Both produce a scheme that is perfectly
  self-consistent and interoperates with nothing.
- **`src/crypto/asyms/mldsaparams.hpp`** defines `MlDsaParams`, FIPS 204
  Table 1's three parameter sets with every length derived from them rather
  than written out, and `static_assert`ed against Table 2 by
  `tests/crypto/asyms/mldsaparams.cpp`. Two of its values do not behave the way
  a reader expects: **eta is not monotone** across the sets (2, 4, 2 for
  ML-DSA-44/65/87), and **gamma1 is shared** by ML-DSA-65 and -87, so neither
  can be used to tell a set apart.
- **`src/crypto/asyms/mldsascheme.hpp`/`.cpp`** define `MlDsaScheme`, ML-DSA
  itself over raw byte spans: FIPS 204 7.2's key and signature encoders
  (`pkEncode`/`pkDecode`, `skEncode`/`skDecode`, `sigEncode`/`sigDecode`,
  `w1Encode`), and KeyGen/Sign/Verify in both the internal
  (Algorithms 6-8) and external (Algorithms 2-3) forms. It takes xi and rnd as
  parameters rather than drawing them, which is what lets it be driven straight
  from a test vector.

  It stays private to `src/`, unlike ML-KEM's `CMlKem`, because every entry
  point is parameterized by `MlDsaParams` -- exporting the signatures would
  mean either moving that already-tested private header into the public API or
  duplicating it, and the surface a caller actually needs is
  `IAsymmetric`-shaped anyway.

  **There are two message conventions and they are not interchangeable.** The
  internal interface signs `M'` verbatim. The external one prepends
  `IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx` first, and that is
  what RFC 9881's `id-ml-dsa-*` OIDs mean -- so an X.509 signature covers
  `0x00 || 0x00 || tbsCertificate`, not the TBS bytes alone. Signing the raw
  message instead round-trips perfectly against itself and rejects every
  genuine certificate; `tests/crypto/asyms/kat_mldsa.cpp` asserts the two
  interfaces disagree, each rejecting the other's signature, so the distinction
  cannot quietly collapse.

  `sign()`/`verify()` compute mu themselves and hand it to the internal form as
  its `externalMu`, rather than concatenating the prefix and the message into
  one buffer. The results are bit-identical, because mu is `H(tr || M')` and
  `H` absorbs its parts in order, but the message is never copied -- which
  matters when it is a document rather than a 3 KiB TBSCertificate. `tr` sits
  at a fixed offset in the private key, so reading it costs nothing. The same
  `externalMu` parameter covers ACVP's `externalMu: true` groups.

  `skDecode` **range-checks s1/s2**, which is not optional: `2*eta + 1` is 5 or
  9, neither a power of two, so the field encodes values the range does not
  contain (down to -5 at eta = 2, -11 at eta = 4). FIPS 204 Algorithm 25
  rejects such a key, and so does every entry point that decodes one -- a
  private key from storage or from a peer is untrusted input, and signing with
  an out-of-range s1 lands outside the scheme's security argument while still
  verifying against the matching public key.

  Signing is a **rejection loop with aborts**: each iteration draws a fresh
  masking vector and discards the whole attempt if any of four bounds fails, so
  the iteration count depends on the key and the message. There is no
  constant-time story to tell, and FIPS 204 offers none; see
  [Engineering, validation, and risk](../pqc/engineering.md). The working set is heap-allocated
  (`TArray<Poly>`) rather than on the stack because ML-DSA-87's is large --
  A-hat alone is 8x7 polynomials, 56 KiB, with a dozen more vectors alongside
  it.

  Only the pure variant is implemented. HashML-DSA has its own separate
  `id-hash-ml-dsa-*` OIDs, appears in no certificate this library is meant to
  read, and would drag in a hash-OID table for no present caller.
- **`crypto/asyms/mldsa.hpp` / `src/crypto/asyms/mldsa.cpp`** define `CMlDsa`,
  ML-DSA as an `IAsymmetric`, one instance per parameter set -- the same
  arrangement `CEcdsa` has across its curves, reached by passing
  `EASYM_MLDSA44`, `EASYM_MLDSA65`, or `EASYM_MLDSA87` to
  `IAsymmetric::builtIn()`.
  Sign/verify only; `createEncrypter()`/`createDecrypter()` and
  `deriveSharedSecret()` all report `ERET_NOTSUP`.

  **`sign()`/`verify()`'s `digest` parameter is the message, not a hash of
  it.** ML-DSA has no externally supplied digest -- it hashes the message
  internally, twice with different domain separation, and signs a lattice
  commitment rather than a fixed-width digest. Passing a pre-computed SHA-256
  value would produce a valid ML-DSA signature *over that 32-byte string*, one
  no other implementation would generate or check. Ed25519/Ed448 read the
  parameter the same way for the same reason, and `CDnssecKeys::hasherOf()`
  states the same fact from the other side. The signal to a caller is
  `sizeOfDigest()`, which stays 0 for a bound ML-DSA key: zero means "there is
  no digest to compute, pass the message". The parameter keeps its interface
  name, since renaming it per implementation would obscure the override
  relationship rather than clarify it.

  `keySizes()` accepts the parameter set's own number (44, 65 or 87) rather
  than a modulus width or a security strength, exactly as `MLKEM` does with
  512/768/1024 -- ML-DSA has no size that can be scaled, and those numbers are
  names. Keys serialize as FIPS 204's own encodings and nothing more, which is
  also exactly what a `SubjectPublicKeyInfo` BIT STRING carries for these OIDs
  (RFC 9881 puts the raw public key there, no inner `OCTET STRING`, with
  `parameters` absent), so `CCert` needs no reshaping step the way DSA's split
  `Dss-Parms` does. A private key does not embed its public key, so
  `IPrivateKey::publicKey()` re-derives it from the key's own rho/s1/s2 and
  checks the result against the stored `tr` (which is `H(pk)`) -- the one
  internal-consistency test an ML-DSA private key admits.

  This is also where randomness enters, and the only place it does. Signing is
  **hedged**: a fresh 32-byte rnd per signature, FIPS 204's recommended
  default, so two signatures over the same message differ and a known-answer
  test has to go through `MlDsaScheme` with rnd = 0 instead. That is not a test
  contrivance -- deterministic signing is the standard's own variant, and it is
  what ACVP's `deterministic: true` groups use.
  The public context obtains this rnd from the `IRng` sealed into it at
  construction; deterministic test-vector code continues to pass rnd directly
  to the internal scheme.

  Validated against NIST's ACVP vectors for all three parameter sets:
  `tests/crypto/asyms/kat_mldsa.cpp` (keyGen and sigGen, deterministic and
  hedged, internal and external), `tests/crypto/asyms/kat_mldsaver.cpp`
  (sigVer, including all four negative reasons -- modified message, commitment,
  hint and z), and `tests/crypto/asyms/mldsa.cpp` for the wrapper. The
  acceptance test is `tests/x509/realcerts.cpp`, where the real IdenTrust
  ML-DSA-87 pilot root verifies its own signature.
