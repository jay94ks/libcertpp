# Pitfalls — how to use libcertpp wrongly and not notice

[한국어](pitfalls.ko.md)

Every item here is a way to call this library that compiles, runs, passes a
round-trip test against itself, and is wrong. They are collected because that
failure mode — *self-consistent and wrong* — is the one that has cost this
project the most time, and a caller inherits most of it.

The pattern to internalise: **if your only test is that your own code can read
back what your own code wrote, you have tested nothing about
interoperability.** Check against a published vector, a certificate someone
else issued, or a second implementation.

## Signing and verifying

**An output span's `size` is narrowed by the callee.** You pass capacity; you
read back length.

```cpp
uint8_t buf[512];
SByteSpan signature(buf, sizeof(buf));
cert.signData(message, signature);
// signature.size is now the signature's real length, not 512.
// Passing sizeof(buf) onward from here would hash trailing garbage.
```

**Some algorithms sign the message, not a digest.** Ed25519, Ed448 and ML-DSA
hash internally as part of the scheme. `CCert::signsMessageDirectly()` is the
predicate for this, and `sizeOfDigest() == 0` is the signal on a context. Feed
such an algorithm a pre-computed digest and you get a perfectly valid signature
over the digest's bytes — treated as the message — which no other
implementation will ever produce or check.
Do not write your own `algo == ED25519 || algo == ED448` test — that exact
predicate was copied into four verification paths in this library and a missed
site fails silently and in the worst direction, which is why it is now one
function.

**A signature covers the bytes as they arrived, not as you would re-encode
them.** `CCert::tbsCertificate()` hands back the original DER. Re-encoding the
parsed fields and verifying against that breaks on any input whose encoding
differs from what this library's encoder would emit — and in the worst case
produces different bytes that verify anyway.

**`verifyBy()` is one link.** It answers "was this certificate signed by the
key in that one?" and nothing else. It does not look at dates,
`basicConstraints`, `keyUsage`, name constraints or revocation, and it has no
idea which roots you trust. A chain of flawlessly-signed certificates rooted in
an attacker's own CA passes every `verifyBy()` call you can make.

**`buildChain()` + `verifyLinks()` is not path validation either, and its name
is the trap.** `ECHAINRES_OK` means the walk reached a self-issued certificate
*held in the collection* — a collection you assembled, possibly from a file an
attacker supplied — and `ERET_OK` from `verifyLinks()` means every link's
signature checks out. Neither looks at a single validity period,
`basicConstraints`, `keyUsage`, name constraint, policy or CRL, and neither
asks whether that self-issued certificate at the end is a root you trust.
Load an attacker's self-signed CA and a leaf it issued into one collection and
both calls succeed, reporting a complete, fully-verified chain. Treat the
ordered chain as the *input* to a validator you still have to write or
delegate.

**`ECHAINRES_OK` does not mean the root is self-signed.** `buildChain()` stops
at a self-*issued* certificate — subject equal to issuer — because that is a
name comparison it can make while walking. Whether that certificate's own
signature verifies under its own key is `verifyLinks()`'s business, so a
collection holding a certificate whose subject and issuer names match but
whose signature is someone else's still terminates the walk with
`ECHAINRES_OK`.

## RSASSA-PSS

**The parameters are in the `AlgorithmIdentifier`, and the DER defaults are a
trap.** All four fields of `RSASSA-PSS-params` are DEFAULTed, so under DER a
field equal to its default is *absent* — an empty-looking parameter set means
SHA-1/MGF1-SHA-1/salt 20, which is almost never what a modern certificate
actually uses. The QuoVadis certificate in `tests/x509/certs/implemented/` uses
SHA-256 with salt length **32**. Assume the defaults and you reject every valid
signature, which a caller cannot distinguish from a forgery.

Use `CCert::rsaPssParams()` to read what the certificate actually says.

## AEADs

All three (`CChaCha20Poly1305`, `CXChaCha20Poly1305`, `CAesGcm`) share these
contracts, which are guarantees you can rely on and obligations you must meet:

**You may encrypt in place** — `out` may alias `in` exactly. This is supported
deliberately so a receiver can decrypt a record where it already sits.
*Partial* overlap is not supported.

**`open()` writes no plaintext before the tag verifies**, and compares the tag
in constant time. So a failed `open()` leaves your buffer holding the
ciphertext it arrived as, not a half-decrypted mixture. Do not add your own
`memcmp` on the tag — that leaks the matching-prefix length through timing, and
it is already done correctly.

**Never reuse a nonce with one key.** For ChaCha20-Poly1305 the 96-bit nonce is
too short to pick at random (a birthday collision becomes likely after roughly
2^48 records), so use a counter. If you want random nonces, that is what
`CXChaCha20Poly1305`'s 192-bit nonce is for.

**A reused context allocates nothing per call.** Key it once with `reset()` and
vary the nonce per record; constructing a context per record is the slow path
and the contract exists so you do not have to.

## Hashes, MACs and KDFs

**`EHashers` values are not stable identifiers to persist.** They cross an ABI
boundary and new hashers are appended, but the numbers are a build-time detail.
Store the OID or the algorithm name, never the enumerator's integer value.

**BLAKE2s has two different MACs and they are not interchangeable.** The native
keyed mode (`CBlake2sMac`, RFC 7693 2.9, key absorbed as a padded first block)
and HMAC-BLAKE2s (the generic RFC 2104 construction over the hash) are
different functions. WireGuard uses both, in different places. Picking the
wrong one produces tags that are self-consistent and rejected by every peer.

**A BLAKE2s digest length is not a truncation.** The output length is bound
into the parameter block, so `BLAKE2s(16)` is not the first 16 bytes of
`BLAKE2s(32)`. Same for the key length.

**HKDF's argument order is `(hasher, salt, inputKey, info, out)`.** Salt comes
*before* the input key material, which is the opposite of what the name
"input key material" suggests reading left to right.

## Big numbers and curves

**`CBigNum`'s mutating methods change `*this` and return a reference for
chaining.** `a.mulMod(b, m)` modifies `a`. Copy first if you still need the
original — this is the single most common way to corrupt a computation here.

**`CBigNum` is not constant-time**, by its own documentation: it trims leading
zero limbs, so every operation's cost depends on its operands, and
`condSwap()` is a plain branch. Prime-curve ECDSA and ECDH inherit this. For an
online handshake with ephemeral keys that is a timing side channel — prefer
X25519, whose ladder is constant-time over `Fe25519`, where the protocol lets
you choose.

**Two moduli live on these curves and they are not interchangeable.** The field
prime (coordinates) and the group order (scalars) are different numbers.
`Fe25519` implements only the field prime 2^255−19; it has no conversion to or
from `CBigNum` in either direction precisely so that mixing them does not
compile. If you find yourself wanting to bridge them, you are about to produce
signatures that verify only against themselves.

**`CMontgomery` requires an odd modulus** and reports `isValid() == false`
otherwise, with every operation becoming a no-op. Check it, or use
`CBigNum::mod()`, which handles any modulus — adding `CMontgomery` left
`CBigNum::mod()`, `mulMod()` and `divMod()` byte-for-byte as they were, so the
general path is still there and still correct.

## Distinguished names

**DN equality is what matches an issuer to a subject**, so anything that makes
two different names compare equal is a correctness bug, not a cosmetic one.

That is why the parser **rejects** a name carrying an attribute type it does not
know, rather than skipping the unknown attribute and carrying on. Skipping would
mean dropping it, and `CDistinguishedName` is keyed by attribute type, so a
dropped attribute makes two genuinely different names compare equal — which
turns a parse failure into a wrong-certificate match. Rejecting is the
conservative direction; the fix when a real certificate trips it is to *add*
the attribute type, which is what happened for `organizationIdentifier`.

**Fourteen X.520 attribute types are recognized**, including
`organizationIdentifier` (which EU-regulated certificates carry) and
`domainComponent`. A name carrying something outside that set still fails.

## DNSSEC

**The flags field is 16 bits big-endian, and the common value hides byte-order
bugs.** Flags 257 is `0x0101`, which reads identically either way. Every
example in RFC 6605 (ECDSA) and RFC 8080 (EdDSA) uses 257, so none of them can
catch a byte-swapped flags field; RFC 5702's two RSA examples use 256
(`0x0100`) and can. Test with 256 if you touch this.

**Owner names are case-folded before the DS digest.** RFC 4034 6.2 folds ASCII
uppercase, and `CDnsName::toWire()` always does it with no option to skip,
because a name that reaches the digest unfolded produces a DS record that
disagrees with every published one.

**DNSSEC reuses none of X.509's encodings.** RSA puts the exponent *before* the
modulus (opposite to this library's DER), ECDSA writes bare `x | y` with no
SEC1 prefix, and an ECDSA signature is `r | s` with each half left-padded to a
fixed width — a DER INTEGER drops leading zeros, so converting without
re-padding shifts `s`. `CDnssecKeys` exists to do all of this; do not
hand-roll it.

## ML-DSA and post-quantum

**FIPS 204 has two message conventions and X.509 uses the external one.** The
internal interface signs the message verbatim; the external one prepends
`0x00 || |ctx| || ctx` first. RFC 9881's `id-ml-dsa-*` means external with an
empty context, so an X.509 signature covers
`0x00 || 0x00 || tbsCertificate`. Signing with the internal form round-trips
perfectly, matches half of NIST's own ACVP test groups, and is rejected by
every real certificate. `CMlDsa` exposes only the external form for this
reason.

**ML-DSA signing cannot be constant-time.** Fiat-Shamir with aborts has a
data-dependent iteration count; FIPS 204 Appendix C asks for unbounded loops
rather than a fixed bound. Do not build a timing assumption on it.

## Keys

**Pairing a private key with a certificate needs a signature, not a
comparison.** Comparing serialized keys works for some algorithms and not
others. `CCertCollection::checkKeyPairing()` signs a fixed value and verifies
it against the certificate's public key, which is the only test that holds for
every algorithm.

**`generateKeyPair()` takes a size in bits and is strict.** Ed448 wants 456,
not 448 — its keys are 57 bytes. A wrong size returns `ERET_KEY_SIZE` rather
than rounding to the nearest supported one.

## Build-time switches that change behaviour

**`CERTPP_DISABLE_HWACCEL_*` must produce byte-identical results.** The
accelerated and portable paths are expected to agree exactly, and the test
suite is run under both. If you ever observe a difference, that is a bug worth
reporting rather than a tuning knob.

**A static `certpp` must be consumed with a matching MSVC runtime.** Linking a
Release build into a Debug consumer produces `_ITERATOR_DEBUG_LEVEL` and
`RuntimeLibrary` mismatch errors. That is an MSVC rule, not something this
library can paper over.
