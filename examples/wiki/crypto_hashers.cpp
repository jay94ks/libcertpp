#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;

// Each example is one function, preceded by a `// === <TypeName> ===` marker. The function body
// is what gets published as that type's example, dedented, so write it as the code a caller
// would write -- not as a test. See the brief for the rules.

// === BLAKE2s ===
// Asks for a 16-byte BLAKE2s digest. The length is bound into BLAKE2s's parameter block, so a
// short digest is its own function and not a prefix of the 32-byte one.
void exampleBLAKE2s(const SReadOnlyByteSpan& message) {
    // 1..32 is the permitted range; anything outside it is silently folded onto 32, because
    // RFC 7693 has no encoding for a longer digest. Read byteWidth() back if it matters.
    BLAKE2s hasher(16);

    hasher.push(message);

    uint8_t digest[BLAKE2s::MAX_DIGEST_BYTES];
    SByteSpan out(digest, hasher.byteWidth());
    if (!hasher.finish(out)) {
        return;
    }

    // out holds BLAKE2s-128 of message -- not the leading half of BLAKE2s-256 of the same
    // bytes, which is a different value. A keyed tag is a third function again: that is
    // CBlake2sMac (native keyed mode) or CHmac over EHASH_BLAKE2S, never this class with the
    // key pushed in front of the message.
}

// === MD4 ===
// Derives the NTLM/EAP-MSCHAPv2 NT hash, which is MD4 of the UTF-16LE password. That protocol
// requirement is the only reason MD4 is in this library; nothing new should hash with it.
void exampleMD4(const SReadOnlyByteSpan& passwordUtf16le, SByteSpan ntHash) {
    if (ntHash.size < 16) {
        return;
    }

    MD4 hasher;
    hasher.push(passwordUtf16le);
    if (!hasher.finish(ntHash)) {
        return;
    }

    // The NT hash is a password equivalent -- anything that can replay it can authenticate --
    // so treat it as key material and clear it rather than letting it fall out of scope.
    CSecure::zero(SByteSpan(ntHash.data, 16));
}

// === MD5 ===
// Checks a legacy fingerprint whose algorithm the data named, so the hasher comes from
// IHasher::create() rather than from writing `MD5` into the caller's own code.
void exampleMD5(
    EHashers namedByTheData, const SReadOnlyByteSpan& content,
    const SReadOnlyByteSpan& recordedDigest
) {
    IHasherPtr hasher;
    if (IHasher::create(namedByTheData, hasher) != ERET_OK) {
        return;
    }

    hasher->push(content);

    uint8_t digest[64];
    if (hasher->byteWidth() > sizeof(digest)) {
        return;
    }

    SByteSpan out(digest, hasher->byteWidth());
    if (!hasher->finish(out)) {
        return;
    }

    if (CSecure::equals(out, recordedDigest)) {
        // The fingerprint matches, which is all it says. An MD5 match is evidence that two
        // files are the same file, never that either one is authentic: colliding pairs are
        // constructible to order, so EHASH_MD5 belongs on the reading side only.
    }
}

// === SHA1 ===
// Computes RFC 5280 4.2.1.2 method (1)'s keyIdentifier -- the SHA-1 of the subjectPublicKey
// BIT STRING's contents. Identifiers like this are the one place SHA-1 is still correct; a new
// signature is not.
void exampleSHA1(const SReadOnlyByteSpan& subjectPublicKeyBits, SByteSpan keyId) {
    if (keyId.size < 20) {
        return;
    }

    SHA1 hasher;
    hasher.push(subjectPublicKeyBits);
    if (!hasher.finish(keyId)) {
        return;
    }

    // keyId's first 20 bytes are the identifier that goes into subjectKeyIdentifier, and that
    // an authorityKeyIdentifier in an issued certificate has to repeat. Collision resistance
    // is not what is being relied on here -- matching a parent to a child is.
}

// === SHA224 ===
// Digests a message into an oversized buffer, then keeps byteWidth() bytes. SHA-224's 28 bytes
// are the odd size in the family and the easiest to accidentally read 32 of.
void exampleSHA224(const SReadOnlyByteSpan& message, COctet& digestOut) {
    SHA224 hasher;
    hasher.push(message);

    // A larger buffer is accepted -- finish() asks only for at least byteWidth() -- but it
    // writes 28 bytes and leaves whatever follows untouched.
    uint8_t buffer[32];
    if (!hasher.finish(SByteSpan(buffer, sizeof(buffer)))) {
        return;
    }

    // So the digest is byteWidth() bytes and never sizeof(buffer). The four bytes past it are
    // uninitialised stack, and SHA-224 is a differently seeded SHA-256 cut to 28 bytes, so
    // they are not the tail of anything either.
    if (!digestOut.store(SReadOnlyByteSpan(buffer, hasher.byteWidth()))) {
        return;
    }
}

// === SHA256 ===
// Digests two independent messages with one instance. finish() does not consume the state, so
// the reset() between them is what keeps the second digest from covering both messages.
void exampleSHA256(const SReadOnlyByteSpan& first, const SReadOnlyByteSpan& second) {
    SHA256 hasher;

    uint8_t digest[32];
    SByteSpan out(digest, sizeof(digest));

    hasher.push(first);
    if (!hasher.finish(out)) {
        return;
    }
    // out now holds SHA-256(first).

    hasher.reset();

    hasher.push(second);
    if (!hasher.finish(out)) {
        return;
    }
    // And now SHA-256(second). Drop the reset() and it would be SHA-256(first || second),
    // because finish() pads a copy and leaves the live context exactly where it was.
}

// === SHA384 ===
// Hashes a certificate's tbsCertificate for an ecdsa-with-SHA384 signature, over the bytes as
// they arrived rather than a re-encoding of the parsed fields.
void exampleSHA384(const SReadOnlyByteSpan& tbsCertificate, SByteSpan digest) {
    if (digest.size < 48) {
        return;
    }

    SHA384 hasher;
    if (hasher.push(tbsCertificate) != tbsCertificate.size) {
        return;
    }

    if (!hasher.finish(digest)) {
        return;
    }

    // Exactly byteWidth() == 48 bytes were written. SHA-384 is SHA-512's compression function
    // under a different initial state, so those 48 bytes are not the first 48 of a SHA-512
    // digest of the same message -- the two agree nowhere.
}

// === SHA3_256 ===
// Keeps a running commitment over an append-only sequence: push a record, read the digest so
// far, push the next. finish() leaves the sponge absorbing, so nothing has to be re-pushed.
void exampleSHA3_256(const SReadOnlyByteSpan& record, const SReadOnlyByteSpan& nextRecord) {
    SHA3_256 hasher;

    uint8_t digest[32];
    SByteSpan out(digest, sizeof(digest));

    hasher.push(record);
    if (!hasher.finish(out)) {
        return;
    }
    // out commits to record.

    hasher.push(nextRecord);
    if (!hasher.finish(out)) {
        return;
    }
    // out commits to record || nextRecord. SHA-3 is a Keccak sponge rather than a SHA-2
    // variant, but it wears the same IHasher contract, including finish() being a query --
    // so a reset() here would throw the first record away.
}

// === SHA3_512 ===
// Expands a 32-byte seed into a public half and a secret half, the way FIPS 203's G function
// splits one 64-byte SHA3-512 digest in two.
void exampleSHA3_512(const SReadOnlyByteSpan& seed, SByteSpan publicHalf, SByteSpan secretHalf) {
    if (publicHalf.size < 32 || secretHalf.size < 32) {
        return;
    }

    SHA3_512 hasher;
    hasher.push(seed);

    uint8_t wide[64];
    SByteSpan out(wide, sizeof(wide));
    if (!hasher.finish(out)) {
        return;
    }

    std::memcpy(publicHalf.data, wide, 32);
    std::memcpy(secretHalf.data, wide + 32, 32);

    // The second half is noise material, so the digest buffer it came from is secret too.
    // SHA3-512 is also fixed at 64 bytes: unlike SHAKE256 it takes no length argument, and
    // asking for a different split means a different construction, not a different call.
    CSecure::zero(out);
}

// === SHA512 ===
// Digests a stream of unknown length in fixed-size chunks. Chunk boundaries are not part of the
// input, so the result matches a single push() of the whole thing.
void exampleSHA512(const IStreamPtr& input) {
    SHA512 hasher;

    uint8_t chunk[4096];
    for (;;) {
        size_t got = input->read(chunk, sizeof(chunk));
        if (got == 0) {
            break;
        }

        // push() reports how much it absorbed; anything short of what was offered means the
        // rest never reached the hash, which a digest alone would never reveal.
        if (hasher.push(SReadOnlyByteSpan(chunk, got)) != got) {
            return;
        }
    }

    uint8_t digest[64];
    SByteSpan out(digest, sizeof(digest));
    if (!hasher.finish(out)) {
        return;
    }
}

// === SHAKE128 ===
// Runs a rejection sampler off SHAKE128's output stream with squeeze(), the call that makes
// this a genuine XOF: it continues where the last call stopped and byteWidth() does not cap it.
void exampleSHAKE128(const SReadOnlyByteSpan& seed, SByteSpan samples) {
    SHAKE128 xof;
    if (xof.push(seed) != seed.size) {
        return;
    }

    size_t filled = 0;
    while (filled < samples.size) {
        uint8_t candidate = 0;
        if (!xof.squeeze(SByteSpan(&candidate, 1))) {
            return;
        }

        // Draw a uniform 0..239 by discarding the 16 values that would bias it, rather than
        // reducing them -- which is the shape FIPS 203's and FIPS 204's samplers need, and
        // the reason squeeze() exists: how many bytes that takes is not known in advance.
        if (candidate < 240) {
            samples.data[filled++] = candidate;
        }
    }

    // Do not call finish() on this instance now. It reports the stream's first byteWidth()
    // bytes and deliberately ignores squeeze()'s cursor, so the two interleaved give output
    // that overlaps itself. Pick one of them per instance.
}

// === SHAKE256 ===
// Produces the 114-byte hash Ed448 (RFC 8032) uses everywhere Ed25519 uses SHA-512. The output
// length is this instance's constructor argument, not a constant of the algorithm.
void exampleSHAKE256(const SReadOnlyByteSpan& privateKey) {
    SHAKE256 xof(114);

    if (xof.push(privateKey) != privateKey.size) {
        return;
    }

    uint8_t wide[114];
    SByteSpan out(wide, sizeof(wide));
    if (!xof.finish(out)) {
        return;
    }

    // All 114 bytes are filled, because byteWidth() is 114 -- the default SHAKE256() would
    // have written 32 of them and left the rest alone. finish() squeezes from a copy of the
    // sponge, so it hands back these same bytes however often it is called; squeeze() is the
    // call for going further into the stream.
    CSecure::zero(out);
}

// === Streebog256 ===
// Hashes a message for a 256-bit GOST R 34.10-2012 signature. The 256-bit Streebog is its own
// function, not the 512-bit one cut short.
void exampleStreebog256(const SReadOnlyByteSpan& message, SByteSpan digestToSign) {
    if (digestToSign.size < 32) {
        return;
    }

    Streebog256 hasher;
    if (hasher.push(message) != message.size) {
        return;
    }

    if (!hasher.finish(digestToSign)) {
        return;
    }

    // RFC 6986 6.1 gives this function the initializing value (00000001)^64 where the 512-bit
    // one starts from 0^512, so the two states diverge at the first block. Feeding a GOST
    // 256-bit key the leading 32 bytes of a Streebog-512 digest instead produces a signature
    // that verifies against nothing.
}

// === Streebog512 ===
// Compares a Streebog-512 digest against a test vector copied out of RFC 6986, which prints its
// vectors in the reverse of the byte order every implementation emits.
void exampleStreebog512(
    const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& digestAsPrintedInRfc
) {
    if (digestAsPrintedInRfc.size != 64) {
        return;
    }

    Streebog512 hasher;
    hasher.push(message);

    uint8_t digest[64];
    SByteSpan out(digest, sizeof(digest));
    if (!hasher.finish(out)) {
        return;
    }

    // finish() writes RFC 6986's byte position 0 first, which is what every published
    // Streebog digest and every GOST signature expects -- and the reverse of the order the
    // RFC's own text prints. One side has to be turned around before comparing.
    uint8_t expected[64];
    for (size_t i = 0; i < sizeof(expected); ++i) {
        expected[i] = digestAsPrintedInRfc[sizeof(expected) - 1 - i];
    }

    if (CSecure::equals(out, SReadOnlyByteSpan(expected, sizeof(expected)))) {
        // matches the published vector
    }
}
