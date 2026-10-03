#ifndef __INCLUDE_CERTPP_CRYPTO_POLY1305_HPP__
#define __INCLUDE_CERTPP_CRYPTO_POLY1305_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * Poly1305 (RFC 8439 2.5), the one-time authenticator ChaCha20-Poly1305 is built on.
     *
     * **The key must never be reused.** This is not advice, it is the security model: Poly1305
     * is a *one-time* MAC, and two messages authenticated under one key let an attacker solve
     * for `r` and then forge tags at will. ChaCha20-Poly1305 satisfies that by deriving a fresh
     * key per nonce from the cipher itself (RFC 8439 2.6), which is why this class is rarely the
     * right thing to call directly -- reach for `ChaCha20Poly1305` unless you are implementing
     * something that already guarantees key uniqueness.
     *
     * It is not a general-purpose MAC, and deliberately does not implement any shared MAC
     * interface alongside HMAC: HMAC is keyed and reusable, this is neither, and letting the two
     * be swapped behind one interface would make that catastrophic difference invisible at the
     * call site.
     *
     * The construction is a polynomial evaluated modulo 2^130 - 5. The key splits into `r` (the
     * evaluation point, with 22 bits cleared -- the "clamping" in RFC 8439 2.5) and `s` (added
     * at the end). Each 16-byte message block is read little-endian with a 1 bit appended above
     * it, so a block of zeros still advances the accumulator and trailing zeros are not
     * ignorable.
     */
    class CERTPP_API CPoly1305 {
    private:
        uint32_t _r[5];          // --> r in five 26-bit limbs, clamped.
        uint32_t _s[4];          // --> s, as four little-endian 32-bit words.
        uint32_t _accumulator[5];
        uint8_t _buffer[16];
        size_t _buffered;
        bool _keyed;

    public:
        /** Key length in bytes: 16 for r, 16 for s. */
        static constexpr size_t KEY_BYTES = 32;

        /** Tag length in bytes. */
        static constexpr size_t TAG_BYTES = 16;

        /** Message block length in bytes. */
        static constexpr size_t BLOCK_BYTES = 16;

    public:
        /**
         * Constructs an unkeyed instance; call reset() before pushing anything.
         */
        CPoly1305();

        /**
         * Destructor; clears the key and accumulator.
         */
        ~CPoly1305();

        CPoly1305(const CPoly1305&) = delete;
        CPoly1305& operator=(const CPoly1305&) = delete;

    public:
        /**
         * Keys this instance and starts a fresh message.
         * @param key Exactly KEY_BYTES; must not have been used for any other message.
         * @return true on success; false if the key is the wrong size.
         */
        bool reset(const SReadOnlyByteSpan& key);

        /**
         * Absorbs message bytes. May be called with any lengths; blocks are buffered internally.
         * @param buf The data to authenticate.
         * @return The number of bytes absorbed; 0 if this instance is not keyed.
         */
        size_t push(const SReadOnlyByteSpan& buf);

        /**
         * Pads the message to a 16-byte boundary with zeros, as RFC 8439 2.8's `pad16` does
         * between the AEAD's fields.
         *
         * This exists because the AEAD's MAC input is four concatenated fields, two of which are
         * zero-padded to a block boundary -- and the padding is *not* equivalent to pushing the
         * zeros as message bytes once a partial block is already buffered, since it closes the
         * current block rather than extending it.
         * @return true on success.
         */
        bool padToBlock();

        /**
         * Finalizes and writes the tag. Unlike `IHasher::finish()` this consumes the state: the
         * instance must be re-keyed before another message.
         * @param out Exactly TAG_BYTES.
         * @return true on success.
         */
        bool finish(const SByteSpan& out);

        /**
         * One-shot Poly1305.
         * @param key Exactly KEY_BYTES; single-use.
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
