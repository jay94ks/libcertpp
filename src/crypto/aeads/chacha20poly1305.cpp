#include <certpp/crypto/aeads/chacha20poly1305.hpp>
#include <certpp/crypto/poly1305.hpp>
#include <certpp/utils/secure.hpp>
#include "../syms/chacha20core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* Writes a 64-bit length little-endian, as RFC 8439 2.8's MAC footer does. */
        void storeLE64(uint8_t* out, uint64_t value) {
            for (size_t i = 0; i < 8; ++i) {
                out[i] = uint8_t(value >> (8 * i));
            }
        }

        /* XORs the ChaCha20 keystream over `length` bytes, starting at block counter 1.
         *
         * --> Counter 1, not 0: block 0 is spent on the Poly1305 key (RFC 8439 2.6). Starting at
         * 0 yields a ciphertext that decrypts and authenticates perfectly against itself and is
         * rejected by every other implementation -- the single most likely way to get this AEAD
         * wrong. Written so `out` may alias `in` exactly, which is what lets a receiver decrypt
         * in place. */
        void applyKeystream(
            const uint8_t key[ChaCha20Core::KEY_BYTES],
            const uint8_t nonce[ChaCha20Core::NONCE_BYTES],
            const uint8_t* in, uint8_t* out, size_t length
        ) {
            // The state is built once for the whole payload rather than per block, and the XOR
            // runs 32 bits at a time -- see ChaCha20Core::xorStream. This used to re-parse the
            // key and nonce for every 64 bytes and combine byte by byte.
            ChaCha20Core::SState state;
            ChaCha20Core::initState(state, key, nonce);

            ChaCha20Core::xorStream(state, 1, in, out, length);

            CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(&state), sizeof(state)));
        }

        /* The AEAD's MAC input (RFC 8439 2.8): aad, padded to a block; the ciphertext, padded to
         * a block; then the two lengths as 64-bit little-endian values.
         *
         * The padding closes a partial block rather than extending the message, which is why it
         * goes through padToBlock() rather than pushing zeros -- pushing them would be
         * indistinguishable from the field itself ending in zeros, and the whole point of pad16
         * is to keep the fields from running into one another. */
        bool computeTag(
            const uint8_t oneTimeKey[CPoly1305::KEY_BYTES],
            const SReadOnlyByteSpan& aad, const uint8_t* ciphertext, size_t ciphertextLength,
            const SByteSpan& tag
        ) {
            CPoly1305 mac;
            if (!mac.reset(SReadOnlyByteSpan(oneTimeKey, CPoly1305::KEY_BYTES))) {
                return false;
            }

            if (aad.size != 0) {
                if (mac.push(aad) != aad.size) {
                    return false;
                }
            }
            if (!mac.padToBlock()) {
                return false;
            }

            if (ciphertextLength != 0) {
                if (mac.push(SReadOnlyByteSpan(ciphertext, ciphertextLength)) != ciphertextLength) {
                    return false;
                }
            }
            if (!mac.padToBlock()) {
                return false;
            }

            uint8_t lengths[16];
            storeLE64(lengths + 0, uint64_t(aad.size));
            storeLE64(lengths + 8, uint64_t(ciphertextLength));

            if (mac.push(SReadOnlyByteSpan(lengths, sizeof(lengths))) != sizeof(lengths)) {
                return false;
            }

            return mac.finish(tag);
        }

    } // namespace

    /* Constructs an unkeyed context. */
    CChaCha20Poly1305::CChaCha20Poly1305() : _keyed(false) {
        std::memset(_key, 0, sizeof(_key));
    }

    /* Clears the key. */
    CChaCha20Poly1305::~CChaCha20Poly1305() {
        CSecure::zero(SByteSpan(_key, sizeof(_key)));
    }

    /* Keys this context. */
    bool CChaCha20Poly1305::reset(const SReadOnlyByteSpan& key) {
        if (key.size != KEY_BYTES || !key.data) {
            return false;
        }

        std::memcpy(_key, key.data, KEY_BYTES);
        _keyed = true;
        return true;
    }

    /* Whether a key is held. */
    bool CChaCha20Poly1305::keyed() const {
        return _keyed;
    }

    /* The one-time Poly1305 key for a nonce (RFC 8439 2.6). */
    bool CChaCha20Poly1305::deriveOneTimeKey(
        const SReadOnlyByteSpan& nonce, const SByteSpan& out
    ) const {
        if (!_keyed || nonce.size != NONCE_BYTES || !nonce.data) {
            return false;
        }
        if (out.size != CPoly1305::KEY_BYTES || !out.data) {
            return false;
        }

        // The block's first 32 bytes are the key; the other 32 are discarded, which is why this
        // is a derivation rather than just "the keystream".
        uint8_t block[ChaCha20Core::BLOCK_BYTES];
        ChaCha20Core::block(_key, 0, nonce.data, block);

        std::memcpy(out.data, block, CPoly1305::KEY_BYTES);
        CSecure::zero(SByteSpan(block, sizeof(block)));

        return true;
    }

    /* Encrypts and authenticates. */
    bool CChaCha20Poly1305::seal(
        const SReadOnlyByteSpan& nonce, const SReadOnlyByteSpan& aad,
        const SReadOnlyByteSpan& in, const SByteSpan& out, const SByteSpan& tag
    ) const {
        if (!_keyed || nonce.size != NONCE_BYTES || !nonce.data) {
            return false;
        }
        if (out.size != in.size) {
            return false;
        }
        if (in.size != 0 && (!in.data || !out.data)) {
            return false;
        }
        if (tag.size != TAG_BYTES || !tag.data) {
            return false;
        }
        if (aad.size != 0 && !aad.data) {
            return false;
        }

        uint8_t oneTimeKey[CPoly1305::KEY_BYTES];
        if (!deriveOneTimeKey(nonce, SByteSpan(oneTimeKey, sizeof(oneTimeKey)))) {
            return false;
        }

        // Encrypt first, then MAC the ciphertext -- encrypt-then-MAC, which is what RFC 8439
        // specifies and what makes open() able to reject before touching the plaintext.
        if (in.size != 0) {
            applyKeystream(_key, nonce.data, in.data, out.data, in.size);
        }

        const bool ok = computeTag(oneTimeKey, aad, out.data, out.size, tag);

        CSecure::zero(SByteSpan(oneTimeKey, sizeof(oneTimeKey)));
        return ok;
    }

    /* Verifies and decrypts. */
    bool CChaCha20Poly1305::open(
        const SReadOnlyByteSpan& nonce, const SReadOnlyByteSpan& aad,
        const SReadOnlyByteSpan& in, const SReadOnlyByteSpan& tag, const SByteSpan& out
    ) const {
        if (!_keyed || nonce.size != NONCE_BYTES || !nonce.data) {
            return false;
        }
        if (out.size != in.size) {
            return false;
        }
        if (in.size != 0 && (!in.data || !out.data)) {
            return false;
        }
        if (tag.size != TAG_BYTES || !tag.data) {
            return false;
        }
        if (aad.size != 0 && !aad.data) {
            return false;
        }

        uint8_t oneTimeKey[CPoly1305::KEY_BYTES];
        if (!deriveOneTimeKey(nonce, SByteSpan(oneTimeKey, sizeof(oneTimeKey)))) {
            return false;
        }

        uint8_t expected[TAG_BYTES];
        const bool computed = computeTag(oneTimeKey, aad, in.data, in.size,
                                        SByteSpan(expected, sizeof(expected)));

        CSecure::zero(SByteSpan(oneTimeKey, sizeof(oneTimeKey)));

        if (!computed) {
            CSecure::zero(SByteSpan(expected, sizeof(expected)));
            return false;
        }

        // --> Verify before writing anything. The tag covers the ciphertext, so it can be
        // checked while `in` is still intact -- and because `out` is allowed to alias `in`, a
        // decrypt-then-verify order would overwrite the caller's only copy of the ciphertext
        // with unauthenticated plaintext before discovering the forgery. Through equalsMask, not
        // memcmp: a comparison that stops at the first difference reveals how much of a forged
        // tag was right, which is enough to build one byte by byte.
        const bool authentic = CSecure::equals(
            SReadOnlyByteSpan(expected, sizeof(expected)), tag);

        CSecure::zero(SByteSpan(expected, sizeof(expected)));

        if (!authentic) {
            return false;
        }

        if (in.size != 0) {
            applyKeystream(_key, nonce.data, in.data, out.data, in.size);
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
