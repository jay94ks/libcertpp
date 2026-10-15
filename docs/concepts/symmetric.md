# Hashing and symmetric cryptography

[한국어](symmetric.ko.md)

## Hashing

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`crypto/hasher.hpp`** defines `IHasher`, the interface every hash
  algorithm implements: `reset()` (back to the algorithm's initial state),
  `push(buf)` (feeds more input, streaming -- any chunking of the same total
  input produces the same digest), and `finish(out)` (writes the digest into
  a caller-supplied `SByteSpan`, failing if `out` is shorter than
  `byteWidth()`). `byteWidth()` (the digest length in bytes: 16/20/28/32/48/
  64 for MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 respectively) is set once
  via the constructor and exposed read-only, rather than being virtual, since
  it never varies per-instance for a concrete hasher. Unlike `IStream`, none
  of `IHasher`'s methods default to `ERET_NOTIMPL` -- every concrete hasher
  implements all three, so all three are pure virtual.
- **`crypto/hashers/md4.hpp`/`md5.hpp`/`sha1.hpp`/`sha224.hpp`/`sha256.hpp`/`sha384.hpp`/`sha512.hpp`**
  (and their matching `src/crypto/hashers/*.cpp`) implement `MD4`, `MD5`, `SHA1`,
  `SHA224`, `SHA256`, `SHA384`, and `SHA512` from scratch (no third-party
  dependency) -- each a concrete `IHasher`, living under the `hashers/` subdirectory
  (plural) as opposed to `crypto/hasher.hpp` (singular) which defines the
  interface itself; `crypto/asym.hpp`/`asyms/` follow the exact same
  singular-interface/plural-implementations split for asymmetric
  algorithms --
  cryptographic hash functions widely referenced by X.509 tooling (message
  digests, certificate fingerprints, `AuthorityKeyIdentifier`/
  `SubjectKeyIdentifier` computation, and legacy signature algorithms), so
  named plainly after the algorithm (`MD5`, not `CMD5`) rather than
  `C`-prefixed, matching how `asn1`'s enumerators use the standard's own
  abbreviations instead of inventing new names. MD4, MD5 and SHA-1 are
  cryptographically broken and only useful for interoperating with legacy
  certificates/fingerprints that still reference them, never for anything
  new -- MD4 most of all, which is here purely because NTLM and
  EAP-MSCHAPv2 define the NT hash as MD4 of the UTF-16LE password, with no
  alternative available to a client that must speak them. Each holds a
  private `Context` struct (running state words + an
  unprocessed-input buffer + a total-length counter) sized for its own block
  size (64 bytes for MD4/MD5/SHA-1/SHA-224/SHA-256, 128 for SHA-384/SHA-512);
  `push()` tops up a partial block from any previous call, runs the
  compression function over as many full blocks as it can consume directly
  from the caller's span, then buffers whatever's left over (less than one
  block). `finish()` runs the padding + compression on a *local copy* of the
  context (by constructing a scratch instance and overwriting its
  `Context`) rather than mutating `_ctx` in place, so it can be called more
  than once and always returns the same digest without disturbing the live
  object -- calling `push()` again afterward simply keeps extending the
  original (unfinalized) state, as if `finish()` had never been called.
  MD4 and MD5 pack message words and their 64-bit length field little-endian
  (the one place they differ from the SHA family, which is big-endian
  throughout). MD4 is MD5's direct ancestor and shares its padding and
  buffering exactly, but runs 3 rounds of 16 steps rather than 4, adds one
  constant per round (none, then `sqrt(2) * 2^30`, then `sqrt(3) * 2^30`)
  rather than one per step, uses a majority function where MD5's round 2
  uses a selection, and -- the part no formula produces -- takes its round-2
  and round-3 message-word order from fixed permutations spelled out in RFC
  1320 3.4 rather than from MD5's arithmetic `(5i + 1) % 16` family.
  SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 all pad the same way (a
  `0x80` byte, zero bytes up to the block-size-specific boundary, then the
  bit length) but with algorithm-specific block/word sizes and round counts.
  SHA-224/SHA-256 are identical except for their initial hash values and
  SHA-224's truncated (28-byte, first 7 of 8 state words) output, and
  SHA-384/SHA-512 are the same relationship one word size up (48-byte, first
  6 of 8 state words); each pair shares the one genuinely error-prone piece
  -- the round-by-round compression function -- via `Sha2_32Core::transform()`/
  `Sha2_64Core::transform()` in the private (not part of the public API)
  `src/crypto/hashers/sha2_32core.hpp`/`.cpp` and `sha2_64core.hpp`/`.cpp`
  respectively; everything else (`Context` layout, `reset()`/`push()`/
  `finish()`, padding) is duplicated between `sha224.cpp`/`sha256.cpp` (and
  separately `sha384.cpp`/`sha512.cpp`) rather than factored into a shared
  base class, since that boilerplate is short and mechanical -- only the
  part that's actually complex enough to risk skew between two copies (the
  compression function) is shared. The 128-bit SHA-384/SHA-512 length
  field's high 64 bits are always written as zero -- correct for any
  realistic input, since the low 64 bits alone can count up to 2^61 bytes
  before overflowing.

  `SHA1::transform()`/`Sha2_32Core::transform()` additionally have a
  hardware-accelerated path (x86-64 only, and only when
  `CERTPP_DISABLE_HWACCEL_SHA` isn't set): `transformAccelerated()` runs the
  same compression function via the x86 SHA Extensions (SHA1RNDS4/
  SHA1NEXTE/SHA1MSG1/SHA1MSG2 for SHA-1; SHA256RNDS2/SHA256MSG1/SHA256MSG2
  for SHA-224/SHA-256, since they share one compression function) instead of
  the portable round-by-round loop (`transformPortable()`), gated behind a
  runtime CPUID check (`hasSha()`, leaf 7 sub-leaf 0, EBX bit 29) since the
  extensions are optional even on x86-64 -- the same shape as
  `CBigNum::mul()`'s `hasAdxBmi2()`/`CGf2m::mul()`'s `hasPclmul()` gates
  above. Both are the well-known Intel-published intrinsics sequence (see
  "Intel SHA Extensions", also mirrored across OpenSSL/BoringSSL/the Linux
  kernel) rather than independently derived, given how easy a
  single-instruction transcription slip is to get subtly wrong in this kind
  of code; verified against this library's existing FIPS 180-4/RFC 3174 test
  vectors (including each algorithm's million-`'a'` multi-block stress
  vector, which exercises `transform()` across thousands of blocks), which
  on a SHA-NI-capable CPU exercise the accelerated path automatically rather
  than needing a dedicated forced-path test. The remaining families do not
  have equivalent dedicated hash extensions. MD5 stays portable-only;
  `Sha2_64Core::transform()` uses BMI2 RORX for SHA-384/SHA-512 rotations when
  available, and `KeccakCore` uses BMI1 ANDN for SHA-3/SHAKE's chi step. Both
  BMI paths are selected by runtime CPUID checks and are disabled by
  `CERTPP_DISABLE_HWACCEL_SIMD`.
- **`crypto/hashers/shake256.hpp` / `src/crypto/hashers/shake256.cpp`**
  implement `SHAKE256`, the 256-bit-security extendable-output function
  from the Keccak/SHA-3 family (FIPS 202) -- from scratch, like every other
  hasher. Structurally different from the MD5/SHA family: instead of a
  fixed-size compression function over a running hash state, it's a sponge
  construction (absorb input into a 1600-bit state via the Keccak-f[1600]
  permutation in 136-byte "rate" blocks, then squeeze output the same way)
  around a genuine XOF, whose output length isn't fixed by the algorithm at
  all -- so unlike every fixed-digest hasher here, `byteWidth()` is set by
  the *caller*, via the constructor argument (`SHAKE256(114)` for Ed448's
  usage, `SHAKE256()` defaulting to 32 otherwise), rather than being an
  intrinsic property of the algorithm. Verified against known-answer
  vectors generated locally via Python's `hashlib` (a mature, independent
  implementation) rather than hand-transcribed from a spec document,
  including inputs exactly at/one-below/one-above the 136-byte rate
  boundary specifically to catch off-by-one padding bugs -- which is
  exactly how an initial transposition bug in the rotation-offset table
  (rows and columns swapped from FIPS 202's own layout) was caught
  immediately, before it ever reached `Ed448`. Needed by `Ed448` (RFC
  8032), which uses `SHAKE256(x, 114)` everywhere `Ed25519` uses SHA-512.

  The Keccak-f[1600] permutation and sponge-absorption logic (`theta`/
  `rho`/`pi`/`chi`/`iota`, 24 rounds, plus the multi-rate `0x1F`/`0x80`
  domain-separated padding) are rate-independent -- i.e. identical for any
  SHAKE variant regardless of its 1600-bit-minus-2*security-level rate --
  so they live in a shared private `KeccakCore` class
  (`src/crypto/hashers/keccakcore.hpp`/`.cpp`, `STATE_BYTES=200`,
  `permute()`/`absorbBlock()`), not duplicated per algorithm. `SHAKE256`
  (RATE=136, 512-bit capacity) and `SHAKE128` (`crypto/hashers/
  shake128.hpp`/`src/crypto/hashers/shake128.cpp`, RATE=168, 256-bit
  capacity) both just drive `KeccakCore` at their own rate; `EHashers`
  gained `EHASH_SHAKE128` alongside the existing `EHASH_SHAKE256`.
  `SHAKE128` is verified the same way as `SHAKE256` -- Python `hashlib`-
  generated vectors (including rate-boundary cases at 167/168/169-byte
  inputs) plus one NIST-published vector (CSRC's `SHAKE128_Msg0.pdf`
  empty-message example, cross-checked against `hashlib.shake_128` to rule
  out a transcription error from the PDF). Not currently used by any
  signature/cipher algorithm in this library (unlike `SHAKE256`/Ed448) --
  added ahead of need, as the first step of the ML-KEM/ML-DSA groundwork
  described in [`docs/PQC.md`](../PQC.md), since both FIPS
  203/204 use SHAKE128 for matrix/vector expansion.

  Both XOFs additionally expose `squeeze(const SByteSpan&)` alongside
  `finish()`: successive calls return successive chunks of the output stream,
  advancing the sponge, so output length is independent of `byteWidth()`.
  `finish()` is the fixed-length, repeatable view (it squeezes from a copy and
  leaves the cursor alone); `squeeze()` is the streaming one. They are
  alternatives rather than something to interleave. This exists because FIPS
  203's `SampleNTT` and FIPS 204's challenge/mask expansion rejection-sample
  from a SHAKE stream until enough candidates are accepted -- with no length
  knowable in advance. `MlKemSampler::sampleNtt()` consumes 453-498 bytes
  depending on the seed, which is the concrete demonstration.
- **`crypto/hashers/sha3_256.hpp`/`sha3_512.hpp` /
  `src/crypto/hashers/sha3_256.cpp`/`sha3_512.cpp`** implement SHA3-256 and
  SHA3-512 (FIPS 202 6.1). Despite the name these are not SHA-2 variants:
  SHA-3 is the same sponge as the SHAKE XOFs above, so it reuses the same
  `KeccakCore` permutation, and the buffering/padding common to both digests
  lives in a shared private `Sha3Core`
  (`src/crypto/hashers/sha3core.hpp`/`.cpp`) -- the same arrangement
  `Sha2_32Core` has between SHA-224 and SHA-256, as free functions over raw
  arrays so each public header can declare its own context without depending
  on anything under `src/`.
  SHA-3 differs from SHAKE in exactly two respects: the rate is
  `200 - 2*digestWidth` (136 bytes for SHA3-256, 72 for SHA3-512, the capacity
  being twice the output length), and the domain-separation byte is `0x06`
  rather than SHAKE's `0x1F`. That single byte is the whole difference between
  a SHA-3 digest and a SHAKE output of the same length over an identical
  sponge, which is why `tests/crypto/hashers/sha3.cpp` asserts the two
  actually differ rather than only checking digests against vectors.
  `finish()` follows the SHA-2 convention rather than the XOFs': it is a query
  that leaves the sponge untouched, so it repeats and absorption can continue
  afterwards. These were added because ML-KEM needs them as FIPS 203's `H` and
  `G` -- a prerequisite `docs/PQC.md`'s plan had missed, since the
  library had SHAKE but no fixed-output SHA-3 at all -- but they are ordinary
  `EHashers` members (`EHASH_SHA3_256`/`EHASH_SHA3_512`) usable anywhere.

## Symmetric cryptography

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`crypto/transform.hpp`** defines `ITransformer`, the generic streaming
  transform interface (`blockSize()`, `transform()`, `transformFinal()`)
  both `IAsymmetricTransformer` (encrypt/decrypt with RSA, one block at a
  time) and `ISymmetricTransformer` (below) derive from.
- **`crypto/sym.hpp`** defines `ISymmetric`, `ISymmetricContext`, and
  `ISymmetricTransformer` -- the symmetric-cipher counterpart of
  `asym.hpp`'s `IAsymmetric`/`IAsymmetricContext`/`IAsymmetricTransformer`,
  with one structural difference: `ISymmetric::createContext(key)` binds
  the key immediately (there's no keyless context to fill in later, unlike
  `IAsymmetricContext::keyPair()`), and the IV is set separately via
  `ISymmetricContext::key(key, iv)` (the same method, called again) since
  `createContext()` itself takes no IV. `ISymmetric::builtIn(which)` is the
  `ESymmetrics` (`ESYM_AES`/`ESYM_ARIA`/`ESYM_DES`/`ESYM_3DES`/
  `ESYM_CHACHA20`) factory,
  mirroring `IAsymmetric::builtIn()`.
- **`crypto/syms/aes.hpp`/`aria.hpp`/`des.hpp`/`des3.hpp` and their matching
  sources** define `AES` (FIPS-197, 128/192/256-bit keys), `ARIA` (RFC 5794,
  128/192/256-bit keys), `DES` (FIPS 46-3, legacy/interop only), and `TripleDES` (two- or
  three-key EDE, built directly on the same DES block core). All three
  `ISymmetricContext`s operate in CBC mode -- the only mode this library's
  `ISymmetric` block ciphers implement -- via the
  shared `src/crypto/syms/cbctransformer.hpp`/`.cpp` (`CbcTransformer`, not
  part of the public API): buffering, CBC chaining, and padding add/strip
  factored out once rather than duplicated per algorithm, parameterized by
  a per-block encrypt/decrypt callback and the block size. Decrypting always
  holds back the most recently completed block instead of emitting it
  immediately, since it might turn out to be the final (padded) one.

  Padding is PKCS#7 (RFC 5652 6.3) by default and `ESYMPAD_NONE` on request,
  selected per context through `ISymmetricContext::padding()` and read when a
  transformer is created. Unpadded CBC exists for a protocol that pads for
  itself -- IKEv2 (RFC 7296 3.14) builds pad-length-terminated padding into the
  payload, so a PKCS#7 block underneath it would be a second, unexpected one.
  Unpadded, there is nothing to strip and nothing special about the last block,
  so every whole block is emitted as it completes and no block is held back;
  `transformFinal()` produces nothing and returns `ERET_BADREQ` if a partial
  block is left over, rather than quietly rounding the length up. `padding()`
  is deliberately *not* cleared by `reset()` or `key()`, unlike the key, IV and
  block size: it is a mode choice rather than key material, and clearing it
  would make `padding(ESYMPAD_NONE)` followed by `key(...)` silently revert to
  PKCS#7, which is a very quiet way to emit a ciphertext a peer rejects.
  Padding validation (`transformFinal()`'s decrypt path) is written to run
  every byte comparison unconditionally, with no early exit on the first
  mismatch and no branch on the pad value itself, specifically to avoid a
  Vaudenay-style CBC padding oracle (the exact class of bug behind
  POODLE/Lucky13) for any caller that lets an attacker observe many decrypt
  attempts against adaptively chosen ciphertexts -- the one place in this
  module where timing-side-channel hardening is treated as load-bearing
  rather than out of scope (contrast `CEcCurve`'s/`CBigNum`'s own
  correctness-over-constant-time stance elsewhere in `crypto/`). `AesCore`
  (shared private `aescore.hpp`/`.cpp`, used by both `aes.cpp` and
  `aeads/aesgcm.cpp`), `AriaCore` (private `ariacore.hpp`/`.cpp`, used by
  `aria.cpp`), `DesCore` (shared private `descore.hpp`/`.cpp`, used by both
  `des.cpp` and `des3.cpp`), and `TripleDesCore` (`des3.cpp`) hold each
  algorithm's own block-cipher math, kept private since nothing outside
  module needs them (`SymRawKey`, a trivial raw-byte `ISymmetricKey` with
  no validation beyond length, is shared the same way via
  `src/crypto/syms/symkey.hpp`).

  `AesCore` additionally has a hardware-accelerated path (x86-64 only, and
  only when `CERTPP_DISABLE_HWACCEL_AES` isn't set), the same shape as
  `SHA1`/`Sha2_32Core::transform`'s SHA-NI dispatch above: `encryptBlock()`/
  `decryptBlock()` are thin dispatchers that call
  `encryptBlockAccelerated()`/`decryptBlockAccelerated()` when a runtime
  CPUID check (`hasAesNi()`, leaf 1, ECX bit 25) passes, falling back to
  `encryptBlockPortable()`/`decryptBlockPortable()` (the original
  round-by-round implementation) otherwise. The accelerated path is the
  Intel-published `AESENC`/`AESENCLAST`/`AESDEC`/`AESDECLAST`/`AESIMC`
  intrinsics sequence (`<wmmintrin.h>`): encryption runs the standard
  cipher directly against `expandKey()`'s existing forward round keys
  (byte-identical to what AES-NI's own key schedule would produce, so no
  separate hardware key expansion is needed); decryption uses the
  "Equivalent Inverse Cipher" construction -- the forward round keys in
  reverse order, each put through `AESIMC` except the first and last --
  rather than re-deriving a true inverse key schedule. `DES`/`TripleDES`/
  have no equivalent: there is no mainstream x86 hardware extension for
  DES/3DES's Feistel network. ChaCha20's ARX rounds have no dedicated
  extension either, but they vectorize across blocks: groups of four use
  SSE2, groups of eight use AVX2, and groups of sixteen use AVX-512F after
  runtime CPU and OS vector-state checks. The paths are governed by
  `CERTPP_DISABLE_HWACCEL_SIMD`, with the AVX-512 tier separately suppressible
  through `CERTPP_DISABLE_HWACCEL_AVX512` -- see the
  `src/crypto/syms/chacha20core.hpp` bullet above.
  Verified by the same SP 800-38A/FIPS-46/RFC 8439 known-answer vectors
  this module already runs -- on an AES-NI-capable CPU they exercise the
  accelerated path automatically, with `CERTPP_DISABLE_HWACCEL_AES`
  available to force the portable path for an explicit comparison.
- **`crypto/syms/chacha20.hpp` / `src/crypto/syms/chacha20.cpp`** defines
  `ChaCha20` (RFC 8439): a 256-bit key, a 96-bit nonce (`iv()`), and an
  internal 32-bit block counter (always starting at 0) are expanded into a
  keystream XORed with the input -- encryption and decryption are the
  identical operation, so `createDecrypter()` just returns another
  `createEncrypter()`-shaped transformer. Being a stream cipher, it needs
  no padding and places no block-alignment requirement on input length;
  `sizeOfBlock()` (64, once a key is bound) only reports the cipher's
  internal keystream-generation granularity, not an alignment requirement.
  Verified against RFC 8439 Appendix A.1's block-function known-answer vector
  and an independent scalar implementation at every length through 600 bytes
  plus 1, 4, 16, and 64 KiB boundaries, which exercises every vector tier and
  scalar remainder.
