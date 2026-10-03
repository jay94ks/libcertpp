#include <certpp/crypto/aeads/aesgcm.hpp>
#include <certpp/utils/secure.hpp>
#include "../syms/aescore.hpp"
#include "ghash.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* Writes a 64-bit length big-endian, as GCM's length block does -- the opposite endianness
         * of ChaCha20-Poly1305's otherwise analogous footer (RFC 8439 2.8 uses le64), which is
         * precisely why it is written out here rather than assumed. */
        void storeBE64(uint8_t* out, uint64_t value) {
            for (size_t i = 0; i < 8; ++i) {
                out[i] = uint8_t(value >> (8 * (7 - i)));
            }
        }

        /* Increments the counter block's rightmost 32 bits, modulo 2^32, leaving the preceding 96
         * bits alone -- SP 800-38D 6.2's inc32. The wrap is deliberate: it is the reason
         * MAX_PAYLOAD_BYTES exists, since a message long enough to wrap would repeat keystream. */
        void inc32(uint8_t block[16]) {
            for (size_t i = 16; i-- > 12; ) {
                if (++block[i] != 0) {
                    break;
                }
            }
        }

        /* GCTR (SP 800-38D 6.5): XORs the keystream of successive counter blocks, starting at icb,
         * over `length` bytes. Written so `out` may alias `in` exactly, which is what lets a
         * receiver decrypt in place. */
        void applyCounterStream(
            const uint8_t* roundKeys, uint32_t rounds, const uint8_t icb[16],
            const uint8_t* in, uint8_t* out, size_t length
        ) {
            uint8_t counter[16];
            uint8_t keystream[16];

            std::memcpy(counter, icb, sizeof(counter));

            size_t offset = 0;
            while (offset < length) {
                AesCore::encryptBlock(counter, keystream, roundKeys, rounds);

                const size_t remaining = length - offset;
                const size_t take = (remaining < 16) ? remaining : 16;

                // A combine, not a copy: memcpy cannot express it, so this stays a byte loop (as
                // CbcTransformer's chaining XOR does), through raw pointers rather than spans.
                for (size_t i = 0; i < take; ++i) {
                    out[offset + i] = uint8_t(in[offset + i] ^ keystream[i]);
                }

                offset += take;
                inc32(counter);
            }

            CSecure::zero(SByteSpan(counter, sizeof(counter)));
            CSecure::zero(SByteSpan(keystream, sizeof(keystream)));
        }

        /* GHASH over `A || pad(A) || C || pad(C) || [len(A)]_64 || [len(C)]_64` (SP 800-38D 7.1
         * step 5), with both lengths in *bits* and big-endian.
         *
         * The padding closes a partial block rather than extending the message, which is why it
         * goes through padToBlock() rather than pushing zeros -- pushing them would be
         * indistinguishable from the field itself ending in zeros, and keeping the two fields from
         * running into one another is the whole point. */
        void computeHash(
            const uint8_t subkey[16], const SReadOnlyByteSpan& aad,
            const uint8_t* ciphertext, size_t ciphertextLength, uint8_t out[16]
        ) {
            Ghash hash;
            hash.reset(subkey);

            hash.push(aad.data, aad.size);
            hash.padToBlock();

            hash.push(ciphertext, ciphertextLength);
            hash.padToBlock();

            uint8_t lengths[16];
            storeBE64(lengths + 0, uint64_t(aad.size) * 8);
            storeBE64(lengths + 8, uint64_t(ciphertextLength) * 8);

            hash.push(lengths, sizeof(lengths));
            hash.finish(out);
        }

    } // namespace

    /* Constructs an unkeyed context. */
    CAesGcm::CAesGcm() : _rounds(0), _keyBytes(0) {
        std::memset(_roundKeys, 0, sizeof(_roundKeys));
        std::memset(_subkey, 0, sizeof(_subkey));
    }

    /* Clears the key schedule and the GHASH subkey. */
    CAesGcm::~CAesGcm() {
        CSecure::zero(SByteSpan(_roundKeys, sizeof(_roundKeys)));
        CSecure::zero(SByteSpan(_subkey, sizeof(_subkey)));
    }

    /* Keys this context. */
    bool CAesGcm::reset(const SReadOnlyByteSpan& key) {
        // --> Inside a member, since ROUND_KEY_BYTES is private: the header has to state the
        // buffer's size without naming AesCore (a src/-private type), so this is where the two
        // are held to each other.
        static_assert(
            ROUND_KEY_BYTES == AesCore::MAX_ROUND_KEY_BYTES,
            "CAesGcm's round-key buffer must hold AesCore's largest schedule"
        );

        _rounds = 0;
        _keyBytes = 0;
        CSecure::zero(SByteSpan(_roundKeys, sizeof(_roundKeys)));
        CSecure::zero(SByteSpan(_subkey, sizeof(_subkey)));

        if (!key.data) {
            return false;
        }
        if (key.size != KEY_BYTES_128 && key.size != KEY_BYTES_192 && key.size != KEY_BYTES_256) {
            return false;
        }

        uint32_t rounds = 0;
        if (!AesCore::expandKey(key.data, key.size, _roundKeys, rounds)) {
            return false;
        }

        // H = E_K(0^128). GHASH's key, derived from the block cipher rather than given -- which
        // is why it must be recomputed on every re-key and cleared with the schedule.
        uint8_t zeroBlock[BLOCK_BYTES];
        std::memset(zeroBlock, 0, sizeof(zeroBlock));
        AesCore::encryptBlock(zeroBlock, _subkey, _roundKeys, rounds);

        _rounds = rounds;
        _keyBytes = key.size;
        return true;
    }

    /* Whether a key is held. */
    bool CAesGcm::keyed() const {
        return _rounds != 0;
    }

    /* The held key's length. */
    size_t CAesGcm::keyBytes() const {
        return _keyBytes;
    }

    /* The GHASH subkey H = E_K(0^128). */
    bool CAesGcm::deriveSubkey(const SByteSpan& out) const {
        if (!keyed() || out.size != BLOCK_BYTES || !out.data) {
            return false;
        }

        std::memcpy(out.data, _subkey, BLOCK_BYTES);
        return true;
    }

    /* Encrypts and authenticates. */
    bool CAesGcm::seal(
        const SReadOnlyByteSpan& iv, const SReadOnlyByteSpan& aad,
        const SReadOnlyByteSpan& in, const SByteSpan& out, const SByteSpan& tag
    ) const {
        if (!keyed() || iv.size != IV_BYTES || !iv.data) {
            return false;
        }
        if (out.size != in.size) {
            return false;
        }
        if (in.size != 0 && (!in.data || !out.data)) {
            return false;
        }
        if (tag.size < MIN_TAG_BYTES || tag.size > TAG_BYTES || !tag.data) {
            return false;
        }
        if (aad.size != 0 && !aad.data) {
            return false;
        }
        if (uint64_t(in.size) > MAX_PAYLOAD_BYTES) {
            return false;
        }

        // J0 = IV || 0^31 || 1, the 96-bit-IV case of SP 800-38D 7.1 step 2. J0 itself is never a
        // payload counter: it produces the tag's mask, and the payload starts at J0 + 1.
        uint8_t j0[BLOCK_BYTES];
        std::memcpy(j0, iv.data, IV_BYTES);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;

        uint8_t counter[BLOCK_BYTES];
        std::memcpy(counter, j0, sizeof(counter));
        inc32(counter);

        // Encrypt first, then hash the ciphertext -- encrypt-then-MAC, which is what SP 800-38D
        // specifies and what makes open() able to reject before touching the plaintext.
        if (in.size != 0) {
            applyCounterStream(_roundKeys, _rounds, counter, in.data, out.data, in.size);
        }

        uint8_t hash[BLOCK_BYTES];
        computeHash(_subkey, aad, out.data, out.size, hash);

        uint8_t mask[BLOCK_BYTES];
        AesCore::encryptBlock(j0, mask, _roundKeys, _rounds);

        // A short tag is the full one with its tail dropped (SP 800-38D 5.2.1.2's MSB_t), not a
        // differently computed value.
        for (size_t i = 0; i < tag.size; ++i) {
            tag.data[i] = uint8_t(hash[i] ^ mask[i]);
        }

        CSecure::zero(SByteSpan(hash, sizeof(hash)));
        CSecure::zero(SByteSpan(mask, sizeof(mask)));
        CSecure::zero(SByteSpan(counter, sizeof(counter)));

        return true;
    }

    /* Verifies and decrypts. */
    bool CAesGcm::open(
        const SReadOnlyByteSpan& iv, const SReadOnlyByteSpan& aad,
        const SReadOnlyByteSpan& in, const SReadOnlyByteSpan& tag, const SByteSpan& out
    ) const {
        if (!keyed() || iv.size != IV_BYTES || !iv.data) {
            return false;
        }
        if (out.size != in.size) {
            return false;
        }
        if (in.size != 0 && (!in.data || !out.data)) {
            return false;
        }
        if (tag.size < MIN_TAG_BYTES || tag.size > TAG_BYTES || !tag.data) {
            return false;
        }
        if (aad.size != 0 && !aad.data) {
            return false;
        }
        if (uint64_t(in.size) > MAX_PAYLOAD_BYTES) {
            return false;
        }

        uint8_t j0[BLOCK_BYTES];
        std::memcpy(j0, iv.data, IV_BYTES);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;

        uint8_t hash[BLOCK_BYTES];
        computeHash(_subkey, aad, in.data, in.size, hash);

        uint8_t mask[BLOCK_BYTES];
        AesCore::encryptBlock(j0, mask, _roundKeys, _rounds);

        uint8_t expected[BLOCK_BYTES];
        for (size_t i = 0; i < BLOCK_BYTES; ++i) {
            expected[i] = uint8_t(hash[i] ^ mask[i]);
        }

        CSecure::zero(SByteSpan(hash, sizeof(hash)));
        CSecure::zero(SByteSpan(mask, sizeof(mask)));

        // --> Verify before writing anything. The tag covers the ciphertext, so it can be checked
        // while `in` is still intact -- and because `out` is allowed to alias `in`, a
        // decrypt-then-verify order would overwrite the caller's only copy of the ciphertext with
        // unauthenticated plaintext before discovering the forgery. Through CSecure, not memcmp: a
        // comparison that stops at the first difference reveals how much of a forged tag was
        // right, which is enough to build one byte by byte. Only tag.size bytes are compared, so a
        // truncated tag is checked against the same prefix the sender would have produced.
        const bool authentic = CSecure::equals(
            SReadOnlyByteSpan(expected, tag.size), tag);

        CSecure::zero(SByteSpan(expected, sizeof(expected)));

        if (!authentic) {
            return false;
        }

        if (in.size != 0) {
            uint8_t counter[BLOCK_BYTES];
            std::memcpy(counter, j0, sizeof(counter));
            inc32(counter);

            applyCounterStream(_roundKeys, _rounds, counter, in.data, out.data, in.size);

            CSecure::zero(SByteSpan(counter, sizeof(counter)));
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
