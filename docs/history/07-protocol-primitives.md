# Protocol cryptography primitives

[한국어](07-protocol-primitives.ko.md)

## Post-quantum: ML-DSA's parameter sets

← [History](../HISTORY.md)

`MlDsaParams` (`src/crypto/asyms/mldsaparams.hpp`) holds FIPS 204 Table 1 and
derives every length from it, the way `SMlKemParams` does — and for the same
reason, that a mistyped key or signature length stays internally consistent
and surfaces only against an external vector.

The derived figures are `static_assert`ed against FIPS 204 Table 2, so a
mismatch fails the build rather than a test run. All nine match: public keys
1312/1952/2592, private keys 2560/4032/4896, signatures 2420/3309/4627. The
test additionally re-derives each size a *second* way — by summing the parts a
key or signature is actually made of — rather than restating the formula it is
checking.

Two entries in the table do not behave the way a reader expects, and both are
asserted explicitly because an assumption either way would be silent:

- **η is not monotone in security level**: 2, 4, then back to **2** for
  ML-DSA-87. Reading it as rising gives ML-DSA-87 the wrong private-key range
  *and* the wrong `sk` length. There is a `static_assert(P87.eta < P65.eta)`
  purely to make that explicit to the next reader.
- **γ₁ is shared between two sets**: 2^17 for ML-DSA-44, 2^19 for *both*
  ML-DSA-65 and ML-DSA-87, so it cannot tell the latter two apart.

`maxSignatureBytes()` is 4627, derived from ML-DSA-87 rather than written
down — the final standard's figure, where 4595 was the initial public draft's
and still circulates.

The test also cross-checks the table against the units already built:
`highBitsRange()` must agree with `MlDsaRounding::highBitsRange(gamma2)`
computed from γ₂ alone (two independent routes to one number), every set's
`k`/`l`/`tau` must fit the samplers' own maxima, and `omega` must fit the
single byte `HintBitPack` writes it into.

## HMAC and HKDF, for a downstream link-encryption handshake

← [History](../HISTORY.md)

Requested downstream: cppskit's libcskcwk needs to encrypt node-to-node mesh
links. libcertpp already had the key agreement (X25519) and the ciphers; what
was missing was a KDF and an AEAD. This is the KDF half.

`CHmac` (`crypto/hmac.hpp`) implements RFC 2104 over any of this library's
fixed-output hashers, with the streaming shape `IHasher` uses — `reset()` to
key it, `push()`, `finish()` — and a one-shot `compute()`. Re-keying an
existing instance reuses the underlying hasher, so HKDF's expand loop does not
allocate per output block.

`CHkdf` (`crypto/hkdf.hpp`) implements RFC 5869 as three entry points:
`extract()`, `expand()` and `derive()` for the two together. A concrete
utility rather than one implementation of an `IKdf` family, following `CRng`'s
precedent — HKDF's two-step shape does not generalize to a password-based KDF
(salt plus iteration count, no `info`) without an interface that fits neither
well, so introducing one now would be speculative.

#### Two decisions worth recording

**`verify()` exists so callers don't reach for `memcmp`.** A MAC comparison
that stops at the first differing byte tells an attacker how long a prefix
they guessed, which is enough to forge a tag a byte at a time. `CHmac::verify`
goes through `CSecure::equalsMask` and also handles RFC 2104 4's truncated
tags, comparing only the bytes the caller presented.

**The block sizes live in `CHmac`, not on `IHasher`.** HMAC needs the hash's
block size (64, 128, or the SHA-3 rate) and `IHasher` exposes only
`byteWidth()`. Putting it on the interface would mean changing `IHasher`'s
constructor and all ten implementations — a second API change in a row for the
downstream consumer who had just absorbed `finish()`'s `const`. The cost of
keeping it local is that a hasher added later is unsupported by HMAC until
someone extends `blockBytesOf()`, which fails loudly at `reset()` rather than
silently computing a wrong tag. If a second consumer ever needs the block
size, it should move onto `IHasher` rather than be duplicated.

SHAKE128/SHAKE256 are refused: they are XOFs with a caller-chosen output
length, and RFC 2104 is defined over a fixed-output hash. SHA3-256/512 are
accepted using their sponge rate, though KMAC is what NIST actually recommends
for SHA-3.

#### The tests found my own transcription errors, twice

Both suites failed on the first run, and in both cases the implementation was
right and the test data was wrong. Worth recording because the way it was
diagnosed matters more than the typos:

- **HMAC**: one of fifteen transcribed vectors (RFC 4231 case 4, SHA-512) was
  wrong. Rather than guess, every vector was checked against Python's `hmac`
  module — 14 matched, which located the error immediately and proved the C++
  correct.
- **HKDF**: three of six Appendix A cases failed, and the pattern was the
  clue — A.2, A.4 and A.5 passed while A.1, A.3 and A.6 failed, and those
  three share one input. The IKM had been written as 21 octets of `0x0b` where
  RFC 5869 specifies **22**. The expected values were correct all along; the
  input was a byte short. Testing 21, 22 and 23 octets against the RFC's
  published PRK confirmed it in one step.

Had the expected values been generated from this implementation instead of
transcribed, both errors would have been invisible — which is the whole
argument for external vectors.

RFC 4231's seven cases across SHA-1/256/384/512 and all six of RFC 5869's
Appendix A cases now pass, each checked through the one-shot path, the
streaming path at four different chunk sizes, and a single-bit tamper at every
tag position.

## ChaCha20-Poly1305 AEAD, for downstream link encryption

← [History](../HISTORY.md)

The other half of libcskcwk's request. With HMAC/HKDF already in, this
completes what it needs to encrypt node-to-node mesh records: X25519 for the
agreement, HKDF to split the shared secret per direction, and an authenticated
cipher per record.

- `CPoly1305` (`crypto/poly1305.hpp`) — RFC 8439 2.5.
- `CChaCha20Poly1305` (`crypto/aeads/chacha20poly1305.hpp`) — RFC 8439 2.8.
- `ChaCha20Core` extracted from `crypto/syms/chacha20.cpp` into its own private
  unit, the way `DesCore` and `KeccakCore` already were.

#### Why the core had to be extracted

The AEAD needs the ChaCha20 block function at two *different* counters, and
`ISymmetric` cannot express either: counter 0, whose first 32 bytes are the
one-time Poly1305 key (RFC 8439 2.6), and counter 1 onward for the payload,
because block 0 is spent on that key. The stream cipher always starts at 0, so
reusing it through the public interface was not an option and duplicating the
block function would have been worse.

#### What the API guarantees, and why

The request asked for in-place operation, a reusable context, and a
constant-time `open`. All three are in, and one of them has a consequence
worth spelling out:

**`open()` verifies before it writes a single plaintext byte.** The tag covers
the ciphertext, so it can be checked while the input is still intact — and
because `out` may alias `in`, the obvious decrypt-then-verify order would
overwrite the caller's only copy of the ciphertext with unauthenticated
plaintext *before* noticing the forgery. A failed `open()` therefore leaves the
buffer exactly as it was, which the test asserts for every single-bit tag
change (128 of them) and every single-byte ciphertext change.

The tag comparison goes through `CSecure::equalsMask`, not `memcmp`: a
comparison that stops at the first difference reveals how much of a forged tag
was right, which is enough to construct one byte by byte.

`CPoly1305::finish()` deliberately *consumes* the state rather than being a
repeatable query like `IHasher::finish()`. Poly1305 is a one-time MAC — two
messages under one key let an attacker solve for `r` and forge at will — so
leaving the instance usable would invite exactly the misuse that breaks it. It
also does not implement any shared MAC interface alongside HMAC: HMAC is keyed
and reusable, this is neither, and letting the two be swapped behind one
interface would make that difference invisible at the call site.

`padToBlock()` exists as its own operation because RFC 8439 2.8's `pad16`
closes a partial block rather than extending the message. Pushing zeros
instead would be indistinguishable from the field itself ending in zeros, and
keeping the AEAD's four fields from running into one another is the entire
point of the padding.

#### Verified against the RFC at every published step

A round trip proves almost nothing here: each of the likely errors is
self-consistent. So the test checks RFC 8439 2.5.2 (Poly1305), 2.6.2 (the
one-time key derivation) and 2.8.2 (the full AEAD) — the intermediate vector
included, not just the end-to-end one.

Four negative controls, each confirming the vectors bite:

| change | result |
|---|---|
| keystream from counter 0 instead of 1 | 3 assertions fail |
| MAC length-footer fields swapped | 2 fail |
| `pad16` between aad and ciphertext omitted | 2 fail |
| Poly1305's `r` clamping weakened by one mask | 4 fail |

Every one of those produces output that seals and opens perfectly against
itself; only the RFC's bytes catch them.

The suite also includes an integration case shaped like cskcwk's actual
protocol — one context per direction over HKDF-derived keys, a 4-byte prefix
plus 64-bit counter nonce, eight records sealed in place — asserting that every
record's ciphertext and tag differ, that a record replayed under the wrong
counter is rejected, and that the opposite direction's key cannot open it.

All six new/changed units were additionally checked with Clang under
`-fno-ms-compatibility`, so they do not repeat the portability breakage fixed
in `d297767`.

## XChaCha20-Poly1305, so nonces can be random

← [History](../HISTORY.md)

The AEAD above needs a nonce that never repeats under one key, and 96 bits is
too short to get that by picking at random: a birthday collision becomes likely
after roughly 2^48 records, so the nonce has to be a counter, and a counter has
to survive restarts and not be shared between senders. XChaCha20-Poly1305
(draft-irtf-cfrg-xchacha, the variant WireGuard and libsodium use) takes a
192-bit nonce, which is long enough that random nonces are safe for any
realistic record count — so a key can be used by parties that cannot coordinate
a counter at all.

- `ChaCha20Core::hchacha20()` — the draft's nonce-extension function.
- `CXChaCha20Poly1305` (`crypto/aeads/xchacha20poly1305.hpp`) — the AEAD, as a
  wrapper: `subkey = HChaCha20(key, nonce[0:16])`, then `CChaCha20Poly1305`
  under that subkey with the 96-bit nonce `00000000 || nonce[16:24]`.

It delegates rather than reimplementing RFC 8439 2.8, so the in-place aliasing,
the counter-1 start, the MAC field order and the constant-time
verify-before-write are the existing AEAD's, inherited rather than restated.
The subkey depends on the nonce, so a reused context can cache nothing; it goes
in a stack struct that keys a stack `CChaCha20Poly1305` and zeroes itself in its
destructor, which keeps the no-per-call-allocation contract without a `mutable`
member or a non-const `seal()`.

#### HChaCha20 is not the block function

It shares the twenty rounds, which is why it lives in `ChaCha20Core`, and
differs in two ways that each produce something *self-consistent* if got wrong:
the 128-bit nonce fills words 12–15 (there is no counter), and there is **no
feed-forward** — the rounds' output is emitted as-is, words 0–3 then 12–15.
Reusing `block()` verbatim yields a subkey that round-trips perfectly against
itself and agrees with no other implementation.

The whole construction was written in Python first and checked against the
draft's vectors before any C++ existed — 2.2.1 (HChaCha20), A.3.1 (the AEAD),
and A.3.2.2 (the XChaCha20 stream at counter 1, which pins the inner nonce
independently of the MAC).

#### Negative controls

| change | result |
|---|---|
| feed-forward added back into HChaCha20 | 5 test cases fail |
| subkey taken as output words 0–7 instead of 0–3 ‖ 12–15 | 5 fail |
| inner nonce built as `nonce[16:24] ‖ 00000000` | 3 fail |
| `open()` forced to return true | 2 fail (incl. the tampered-AAD case) |

The third is the instructive one: the subkey is identical either way, so the
HChaCha20 vectors still pass and only the AEAD ciphertexts catch it. That is why
the test checks the subkey separately from the ciphertext rather than only end
to end — when the end-to-end vector fails, the subkey assertion says which half
is wrong.
