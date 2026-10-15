# MAC, KDF, AEAD, and randomness

[한국어](protocols.ko.md)

## MACs, KDFs, AEAD, and RNG

← [Modules](../CONCEPTS.md#detailed-concept-pages)

- **`crypto/hmac.hpp` / `src/crypto/hmac.cpp`** define `CHmac`, RFC 2104 over
  any fixed-output hasher here, with `IHasher`'s streaming shape plus a
  one-shot `compute()` and a constant-time `verify()`. Not an `IHasher`: HMAC
  is keyed, and `IHasher::create()` has nowhere to put a key. Re-keying an
  instance reuses the underlying hasher, so HKDF's expand loop does not
  allocate per block. The RFC 2104 block sizes live here rather than on
  `IHasher` (which exposes only `byteWidth()`), because putting them on the
  interface would mean changing its constructor and all of its implementations;
  the trade is that a hasher added later is unsupported until
  `blockBytesOf()` is extended, which fails loudly at `reset()` rather than
  computing a wrong tag. SHAKE is refused -- RFC 2104 is defined over a
  fixed-output hash. BLAKE2s's entry there is 64 bytes, the same block SHA-256
  uses; HMAC over BLAKE2s is well defined and distinct from BLAKE2's own keyed
  mode (`CBlake2sMac`).
- **`crypto/hashers/blake2s.hpp` / `src/crypto/hashers/blake2s.cpp`** define
  `BLAKE2s`, RFC 7693, as `EHASH_BLAKE2S`. Added for WireGuard's handshake
  (its `HASH()`, `MAC()` and HKDF all use it) but an ordinary member of the
  `EHashers` family. It is little-endian throughout where the SHA-2 family is
  big-endian, and a HAIFA rather than Merkle-Damgard construction: no
  length-padding block, the byte counter and a finalization flag go straight
  into the last compression, so a block is held back until a later byte proves
  it is not the last. The digest length (1-32) is bound into the parameter
  block, which makes `BLAKE2s(16)` a different function from the leading 16
  bytes of `BLAKE2s(32)` -- the constructor folds an out-of-range length onto
  32 rather than producing an instance the parameter block cannot describe.
  The state machine lives in `src/crypto/hashers/blake2score.hpp`
  (`Blake2sCore`) and is shared with `CBlake2sMac`, following `Sha3Core`'s
  pattern of free-standing operations over raw arrays so each public class
  declares its own context in its own header.
- **`crypto/blake2smac.hpp` / `src/crypto/blake2smac.cpp`** define
  `CBlake2sMac`, BLAKE2's *native* keyed mode (RFC 7693 2.9/3.3), which is
  what WireGuard's `MAC()` is. The key is one zero-padded first block and its
  length is in the parameter block; there is no ipad/opad and no second pass.
  This is **not** HMAC-BLAKE2s, which is `CHmac` with `EHASH_BLAKE2S` and is
  what WireGuard's HKDF uses -- the two produce different tags from the same
  inputs, so confusing them fails interoperability silently. It is a separate
  class rather than a keyed `reset()` on `BLAKE2s` because `IHasher::reset()`
  takes no arguments: a keyed hasher would either lose its key on a
  polymorphic reset or masquerade as a plain hash behind an `IHasherPtr`, the
  same reasoning that keeps `CPoly1305` out of the hasher hierarchy. Unlike
  `CPoly1305` the key is reusable across messages, and `finish()` is a
  repeatable query.
- **`crypto/hkdf.hpp` / `src/crypto/hkdf.cpp`** define `CHkdf`, RFC 5869's
  extract-then-expand KDF, as `extract()`/`expand()`/`derive()`. A concrete
  utility rather than one implementation of an `IKdf` family, following
  `CRng`'s precedent. `CHkdf` and `CPbkdf2` share only a static `derive()`
  taking spans; HKDF's extract/expand parameters and PBKDF2's iteration count
  do not form one useful common interface.
- **`crypto/pbkdf2.hpp` / `src/crypto/pbkdf2.cpp`** define `CPbkdf2`, RFC 8018
  section 5.2's iterated password-based KDF, as a single `derive()` plus
  `maxDeriveBytes()`. It sits beside `CHkdf` rather than inside the one caller
  that needed it (`CPfxFormat`) because a password KDF is a general-purpose
  primitive, and the two are emphatically **not** interchangeable: HKDF is
  built to be cheap because its input already has full entropy, and that is
  exactly what makes it useless over a password. The implementation notes worth
  carrying: `T(i)` is the XOR of *every* `U(j)`, not the last one (dropping the
  XOR costs the same to compute and matches nothing, which is why RFC 6070's
  vectors are the only cheap way to catch it); only `U(1)` sees the salt;
  `INT(i)` is four big-endian bytes from 1, which only shows up once the output
  runs past one digest; an iteration count of 0 is `ERET_BADREQ` rather than
  "no stretching", since a zeroed count parsed out of a container must not
  become a free derivation; and the output is bounded at `(2^32 - 1) * hLen`
  because past that the counter wraps and the keystream repeats.
  `tests/crypto/pbkdf2.cpp` checks it against RFC 6070's HMAC-SHA1 vectors and
  RFC 7914 section 11's HMAC-SHA256 ones, and explains why the 16777216-
  iteration case is left out.
- **`crypto/poly1305.hpp` / `src/crypto/poly1305.cpp`** define `CPoly1305`,
  RFC 8439 2.5's one-time authenticator. `finish()` *consumes* the state
  rather than being a repeatable query like `IHasher::finish()`, because
  Poly1305 is one-time by construction -- two messages under one key let an
  attacker solve for `r` and forge at will -- so leaving the instance usable
  would invite the misuse that breaks it. It deliberately shares no interface
  with `CHmac`: HMAC is keyed and reusable, this is neither, and letting them
  be swapped would make that difference invisible at the call site.
  `padToBlock()` is a named operation because RFC 8439 2.8's `pad16` closes a
  partial block rather than extending the message, which pushing zeros cannot
  express. On x86-64, whole groups of eight blocks use an AVX512-IFMA path
  after a runtime feature check; shorter input and the tail use the portable
  five-limb implementation. `CERTPP_DISABLE_HWACCEL_SIMD` forces the portable
  path.
- **`crypto/siphash.hpp` / `src/crypto/siphash.cpp`** define `CSipHash`,
  SipHash-2-4 (Aumasson and Bernstein), the keyed 128-bit-key/64-bit-output
  PRF RFC 9018 2.2 specifies for DNS server cookies. It takes `CPoly1305`'s
  shape -- `reset(key)`/`push()`/`finish(out)` plus a one-shot `compute()` --
  but deliberately *not* its lifecycle: SipHash is a reusable PRF, so
  `reset()` may be called any number of times, there is a no-argument
  `reset()` that restarts a message under the key already installed, and
  `finish()` is a repeatable query (finalizing a copy of the state, as
  `IHasher::finish()` does) rather than consuming the key. That difference is
  the security model of each primitive showing through, and the doc comment on
  each class says so, since the two classes otherwise look interchangeable.
  It is not an `IHasher` either: `IHasher` is unkeyed with 16-byte-and-up
  digests, this is keyed with an 8-byte output, and 64 bits is far too short
  to resist a collision search -- putting it behind `IHasher` would invite
  exactly the use it cannot support. The padding is the subtle part: there is
  always a final block, even for an empty or block-aligned message, and it
  carries the message length mod 256 in its top byte instead of any `0x80`
  marker or bit count, so an implementation that merely zero-pads the short
  block is self-consistent and gives any message and its zero-extension the
  same output -- the empty message and a single `0x00` byte being the
  smallest such pair, which is what the test for it uses.
- **`crypto/aeads/chacha20poly1305.hpp` /
  `src/crypto/aeads/chacha20poly1305.cpp`** define `CChaCha20Poly1305`, RFC
  8439 2.8. One instance is a keyed context -- construct per key, call
  `seal()`/`open()` per record with only the nonce changing -- and neither
  operation allocates. `out` may alias `in`, which is what lets a receiver
  decrypt a record where it already sits.

  `open()` verifies the tag *before* writing any plaintext. The tag covers the
  ciphertext, so it can be checked while the input is intact -- and because
  `out` may alias `in`, a decrypt-then-verify order would overwrite the
  caller's only copy of the ciphertext with unauthenticated plaintext before
  noticing the forgery. The comparison goes through `CSecure::equalsMask`, not
  `memcmp`.
- **`crypto/aeads/xchacha20poly1305.hpp` /
  `src/crypto/aeads/xchacha20poly1305.cpp`** define `CXChaCha20Poly1305`,
  draft-irtf-cfrg-xchacha's extended-nonce variant -- the one WireGuard and
  libsodium use. It is a thin wrapper rather than a second AEAD:
  `subkey = HChaCha20(key, nonce[0:16])`, then `CChaCha20Poly1305` under that
  subkey with the 96-bit nonce `00000000 || nonce[16:24]`. The API and every
  contract (in-place operation, no per-call allocation, constant-time
  verify-before-write) are `CChaCha20Poly1305`'s, inherited by delegation
  rather than restated.

  The 192-bit nonce is the whole point: 96 bits is too short to pick at
  random, since a birthday collision becomes likely after roughly 2^48 records
  under one key, so RFC 8439 effectively requires a counter -- and a counter
  requires state that survives restarts and is not shared between senders. At
  192 bits random nonces are safe for any realistic record count, so a key can
  be used by parties that cannot coordinate a counter at all. The cost is one
  extra ChaCha20 permutation per record.

  Nothing can be cached across calls, because the subkey depends on the nonce.
  The per-record subkey and inner nonce therefore live in a stack struct
  (`Inner` in the `.cpp`) that keys a stack `CChaCha20Poly1305` and zeroes the
  subkey in its destructor, which keeps the no-allocation contract without a
  `mutable` member or a non-const `seal()`.
- **`crypto/aeads/aesgcm.hpp` / `src/crypto/aeads/aesgcm.cpp`** define
  `CAesGcm`, NIST SP 800-38D, with AES-128/192/256 and a 96-bit IV. It matches
  `CChaCha20Poly1305`'s shape deliberately -- a keyed context, `seal()`/`open()`
  per record, no per-call allocation, `out` may alias `in`, and `open()` verifies
  before writing a plaintext byte -- because the same consumer (IKEv2) picks one
  or the other by negotiation and should not have to restructure around the
  choice. The differences are the ones the algorithms force: the tag may be
  truncated (SP 800-38D 5.2.1.2 permits 128/120/112/104 or 96 bits, which is
  every byte length from `MIN_TAG_BYTES` to `TAG_BYTES`, and nothing shorter),
  and the key may be any of three lengths rather than one.

  **Only a 96-bit IV is accepted.** SP 800-38D allows any length, but anything
  else derives the initial counter block by running the IV through GHASH instead
  of using it directly -- a second code path with its own ways to be subtly
  wrong, and no caller needs it: IKEv2 (RFC 4106/5282), TLS and SSH all use
  exactly 96 bits, which is also what SP 800-38D 8.2 recommends.

  `deriveSubkey()` exposes `H = E_K(0^128)` for the same reason
  `CChaCha20Poly1305::deriveOneTimeKey()` exists: the GCM specification
  publishes `H` per test case, and it is the one intermediate value that
  separates "the key schedule is wrong" from "the hash is wrong".
- **`src/crypto/aeads/ghash.hpp`/`.cpp`** define `Ghash`, GHASH (SP 800-38D 6.4)
  and GCM's `GF(2^128)` multiplication. It is **not** built on `CGf2m`, whose
  PCLMULQDQ-accelerated multiply would otherwise look like the obvious reuse,
  for three independent reasons:

  - GCM's field is **bit-reflected**: the most significant bit of a block's
    first byte is the `x^0` coefficient (SP 800-38D 6.3), the opposite of the
    polynomial-basis convention `CGf2m` and the rest of the library use. Handing
    `CGf2m` the bytes as they arrive yields a product that is self-consistent in
    every algebraic respect and is not GHASH -- the classic way to get this
    wrong, and one only a published vector catches.
  - `H` is **secret**, so the multiply must be constant-time; `CGf2m` documents
    that it has none, which is the right trade for ECDSA's public curve
    arithmetic and the wrong one for a MAC key.
  - `CGf2m` is sized for other fields: 9 limbs and a generic pentanomial
    reduction over an 18-limb product, where GHASH is two 64-bit words with one
    fixed modulus, once per 16 bytes of message.

  The portable multiply is SP 800-38D's own Algorithm 1 with every branch
  replaced by a mask, and no table -- the key-dependent indices of the usual
  windowed GHASH are what leak `H` through the cache. The accelerated path
  (PCLMULQDQ, behind `CERTPP_DISABLE_HWACCEL_SIMD` and a runtime CPUID check,
  exactly as `CGf2m`'s is) does **not** multiply in the reflected convention:
  it converts both operands into the ordinary one. GFNI reduces each operand's
  bit reflection to one instruction when available; otherwise an SSE2 sequence
  performs the same conversion. Reduction is then the textbook
  `x^128 = x^7 + x^2 + x + 1`,
  rather than carrying the shift-by-one-plus-mirrored-constants trick whose
  correctness cannot be eyeballed.

  Published vectors cannot tell the two paths apart -- whichever one this CPU
  takes is the only one they ever reach -- so `tests/crypto/aeads/ghash.cpp`
  compares them directly over thousands of random and structured operands, and
  checks the field identities that pin the bit order down (the multiplicative
  identity is the block `80 00 ... 00`, not `00 ... 00 01`). `Ghash` has no
  public header and no `CERTPP_API`, so that test compiles `ghash.cpp` into
  itself via `CERTPP_TEST_PRIVATE_SOURCES`.
- **`src/crypto/syms/aescore.hpp`/`.cpp`** define `AesCore`, AES's key schedule
  and single-block encrypt/decrypt (with the AES-NI path behind
  `CERTPP_DISABLE_HWACCEL_AES`), extracted from `aes.cpp` so GCM can share it --
  the arrangement `DesCore` and `ChaCha20Core` already have. GCM is not a mode
  `ISymmetricContext` can express: it needs the raw forward block function at
  arbitrary counter blocks *and* at the all-zero block (for `H`), and never uses
  the inverse cipher at all.
- **`src/crypto/syms/chacha20core.hpp`/`.cpp`** define `ChaCha20Core`, the
  block function, extracted from the stream cipher so the AEAD can share it --
  the arrangement `DesCore` and `KeccakCore` already have. The AEAD needs it at
  two counters `ISymmetric` cannot express: 0 for the Poly1305 key derivation,
  and 1 onward for the payload.
  `xorStream()` carries four-block SSE2 (`xorStream4()`) and eight-block AVX2
  (`xorStream8()`) keystream paths behind `CERTPP_DISABLE_HWACCEL_SIMD`.
  In the SSE2 path each of the sixteen state words
  becomes an `__m128i` holding that word for four consecutive counters, so one
  pass of the twenty rounds produces 256 bytes, followed by a 4x4 transpose per
  group of four words to get back to block-major byte order. Blocks are
  independent by construction, so nothing has to be serialized. The AVX2
  path applies the same layout at twice the width for inputs of at least eight
  blocks and is selected by a runtime feature check. SSE2 itself needs no
  runtime CPUID check because it is part of the x86-64 ABI. Whole eight-block
  groups use AVX2 where available, subsequent four-block groups use SSE2, and
  the remainder falls through to the scalar loop, which also serves every
  non-x86-64 target.
  RFC 8439's own vectors cannot check any of this -- the largest is 114 bytes,
  so every one of them is served entirely by the scalar loop -- which is why
  `tests/crypto/syms/chacha20.cpp` carries a second, independent
  implementation of RFC 8439 2.3 and sweeps every length from 0 to 600 plus
  1 KiB/4 KiB/16 KiB/64 KiB against it. Deliberately breaking the per-lane
  counter feed-forward leaves all seven RFC-vector cases passing and fails
  only those two.

  `hchacha20()` lives here for the same reason the block function does -- it is
  the same twenty rounds -- and differs from `block()` in two ways that are
  each self-consistent if got wrong: the 128-bit nonce fills words 12 through
  15 (there is no counter), and there is **no feed-forward**, so the rounds'
  output is emitted as-is, words 0-3 followed by words 12-15. Reusing
  `block()` for it would produce a subkey that round-trips against itself and
  matches no other implementation, which is why it is a separate function
  rather than a flag on the existing one.
- **`crypto/rng.hpp` / `src/crypto/rng.cpp`** define `CRng`, a CSPRNG utility.
  `fill(const SByteSpan&) -> ERetCode` is backed directly by the operating
  system's CSPRNG -- `BCryptGenRandom` (Windows CNG, linked via
  `bcrypt.lib`) on Windows, the `getrandom(2)` syscall (Linux 3.17+,
  looping past `EINTR`/short reads, with a `/dev/urandom` fallback for
  ENOSYS/an outright syscall failure) on Linux, or `/dev/urandom` directly
  on other POSIX platforms -- rather than any third-party library, falling
  back to `std::random_device` only if the OS API fails
  *and* the `CERTPP_RNG_FALLBACK` CMake option (`OFF` by default -- a
  stopgap for an environment that genuinely lacks an OS-level CSPRNG, not
  something to leave on by default, since `std::random_device` isn't
  guaranteed cryptographically secure on every standard library) is
  enabled; leaving it disabled compiles the fallback path out entirely and
  `fill()` returns `ERET_NOTSUP` instead. `fillNonZero(const SByteSpan&)`
  fills a buffer with random *nonzero* bytes via rejection sampling over
  `fill()`, for padding schemes that forbid zero bytes (RSAES-PKCS1-v1_5).
  Needed by key generation (`IAsymmetric::generateKeyPair()`) and
  encryption padding once any `asyms/` implementation exists.
