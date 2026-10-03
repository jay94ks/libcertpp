#ifndef __INCLUDE_CERTPP_CRYPTO_SIPHASH_HPP__
#define __INCLUDE_CERTPP_CRYPTO_SIPHASH_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * SipHash-2-4 (Aumasson and Bernstein, "SipHash: a fast short-input PRF"), a keyed PRF taking
     * a 128-bit key and producing a 64-bit output. RFC 9018 2.2 specifies it as the algorithm for
     * DNS server cookies, which is what it is here for.
     *
     * Unlike `CPoly1305` this is a long-lived keyed primitive, not a one-time authenticator: the
     * key may authenticate any number of messages, `reset()` may be called repeatedly to start a
     * new message under the same or a different key, and `finish()` leaves the key in place so the
     * instance stays usable. That is SipHash's own security model, and the difference from
     * Poly1305 is not a convenience -- reusing a Poly1305 key hands an attacker forgeries, while
     * reusing a SipHash key is the intended mode of operation.
     *
     * It is also not an `IHasher`, and deliberately so: `IHasher` is unkeyed and its
     * implementations have digests of 16 bytes and up, while this is keyed and emits 8 bytes. A
     * 64-bit output is far too short to resist a collision search, so SipHash is a message
     * authenticator and a hash-table defence, never a digest to identify or sign data with --
     * letting it sit behind `IHasher` would invite exactly that mistake.
     *
     * The construction is an ARX sponge over four 64-bit words: each 8-byte message block is
     * XORed into v3, run through 2 SipRounds, then XORed into v0; after the final block (which
     * always carries the message length mod 256 in its top byte) v2 is XORed with 0xFF and 4 more
     * SipRounds finalize, the output being v0 ^ v1 ^ v2 ^ v3. The "2-4" in the name is those two
     * round counts.
     */
    class CERTPP_API CSipHash {
    private:
        uint64_t _k0;            // --> First half of the key, little-endian.
        uint64_t _k1;            // --> Second half of the key, little-endian.
        uint64_t _v[4];          // --> The four state words, v0..v3.
        uint8_t _buffer[8];      // --> Bytes of an incomplete block, held until it fills.
        size_t _buffered;        // --> Valid bytes in _buffer (0-7).
        uint64_t _totalLen;      // --> Total message bytes absorbed; only its low byte matters.
        bool _keyed;

    public:
        /** Key length in bytes. */
        static constexpr size_t KEY_BYTES = 16;

        /** Output length in bytes. */
        static constexpr size_t TAG_BYTES = 8;

        /** Message block length in bytes. */
        static constexpr size_t BLOCK_BYTES = 8;

    public:
        /**
         * Constructs an unkeyed instance; call reset() before pushing anything.
         */
        CSipHash();

        /**
         * Destructor; clears the key and state.
         */
        ~CSipHash();

        CSipHash(const CSipHash&) = delete;
        CSipHash& operator=(const CSipHash&) = delete;

    public:
        /**
         * Keys this instance and starts a fresh message. May be called as often as wanted, with a
         * key that has already been used -- SipHash is a reusable PRF, not a one-time MAC.
         * @param key Exactly KEY_BYTES.
         * @return true on success; false if the key is the wrong size.
         */
        bool reset(const SReadOnlyByteSpan& key);

        /**
         * Starts a fresh message under the key already in place, which `finish()` leaves intact.
         * @return true on success; false if this instance has never been keyed.
         */
        bool reset();

        /**
         * Absorbs message bytes. May be called with any lengths; blocks are buffered internally.
         * @param buf The data to authenticate.
         * @return The number of bytes absorbed; 0 if this instance is not keyed.
         */
        size_t push(const SReadOnlyByteSpan& buf);

        /**
         * Finalizes the current message and writes the 64-bit output little-endian, as the
         * reference implementation and RFC 9018 do.
         *
         * Unlike `CPoly1305::finish()` this does not consume the key: the state is left ready for
         * `reset()` to begin another message under the same key.
         * @param out Exactly TAG_BYTES.
         * @return true on success.
         */
        bool finish(const SByteSpan& out);

        /**
         * One-shot SipHash-2-4.
         * @param key Exactly KEY_BYTES; may be reused across calls.
         * @param message The message.
         * @param out Exactly TAG_BYTES.
         * @return true on success.
         */
        static bool compute(
            const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message,
            const SByteSpan& out
        );
    };

} // namespace crypto
} // namespace certpp

#endif
