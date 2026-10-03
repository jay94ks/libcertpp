#ifndef __INCLUDE_CERTPP_CRYPTO_BLAKE2SMAC_HPP__
#define __INCLUDE_CERTPP_CRYPTO_BLAKE2SMAC_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * BLAKE2s in keyed mode (RFC 7693 2.9 and 3.3) -- BLAKE2's *native* MAC, which is what
     * WireGuard's `MAC()` is.
     *
     * This is not HMAC-BLAKE2s. The key is absorbed as a single zero-padded first block and its
     * length is baked into the parameter block; there is no ipad/opad and no second pass, so one
     * pass over the message is the whole computation. For the generic RFC 2104 construction over
     * the same hash -- which is what WireGuard's HKDF uses, and what a protocol spelling out
     * "HMAC-BLAKE2s" means -- use `CHmac` with `EHASH_BLAKE2S` instead. The two produce completely
     * different tags from the same key and message, so picking the wrong one fails
     * interoperability rather than security, and fails it silently.
     *
     * It is a separate class rather than a keyed constructor on `BLAKE2s` because `IHasher` has
     * nowhere to put a key: `reset()` takes no arguments, so a keyed `BLAKE2s` would either lose
     * its key on a polymorphic `reset()` or masquerade as a plain hash at every call site that
     * holds an `IHasherPtr`. `CPoly1305` is kept out of the hasher hierarchy for the same reason.
     *
     * Unlike `CPoly1305`, the key may be reused across messages: this is a general-purpose keyed
     * hash, not a one-time authenticator.
     *
     * The streaming shape mirrors `IHasher` and `CHmac` -- `reset()` to key it, `push()` as often
     * as needed, `finish()` for the tag -- and `finish()` is a query, so it may be called more
     * than once and absorption may continue afterwards.
     *
     * **Compare tags with `verify()`, not `finish()` plus `memcmp`.** A comparison that stops at
     * the first differing byte leaks how long a prefix the attacker guessed, which is enough to
     * forge a tag a byte at a time. `verify()` goes through `CSecure::equalsMask`.
     */
    class CERTPP_API CBlake2sMac {
    private:
        uint32_t _state[8];
        uint8_t _buffer[64];
        size_t _buffered;
        uint64_t _counter;
        size_t _tagBytes;   // --> 0 until reset() has keyed this instance.

    public:
        /** The compression function's block size, which is also the key block's size. */
        static constexpr size_t BLOCK_BYTES = 64;

        /** The longest key RFC 7693 allows for BLAKE2s, the parameter block holding its length. */
        static constexpr size_t MAX_KEY_BYTES = 32;

        /** The longest tag BLAKE2s produces, and the default. */
        static constexpr size_t MAX_TAG_BYTES = 32;

    public:
        /**
         * Constructs an unkeyed instance; call reset() before pushing anything.
         */
        CBlake2sMac();

        /**
         * Destructor; clears the state and the buffered key block.
         */
        ~CBlake2sMac();

        CBlake2sMac(const CBlake2sMac&) = delete;
        CBlake2sMac& operator=(const CBlake2sMac&) = delete;

    public:
        /**
         * Keys this instance and starts a fresh message. May be called repeatedly.
         * @param key The key; 0..MAX_KEY_BYTES bytes. An empty key is accepted and gives the
         * unkeyed hash, which is `BLAKE2s` -- it is not a MAC, so pass one deliberately.
         * @param tagBytes The tag length, 1..MAX_TAG_BYTES; it is bound into the parameter block,
         * so a short tag is its own function and not a truncation of the long one.
         * @return true on success; false if the key or tag length is out of range.
         */
        bool reset(const SReadOnlyByteSpan& key, size_t tagBytes = MAX_TAG_BYTES);

        /**
         * @return The tag length in bytes; 0 before reset() has succeeded.
         */
        size_t byteWidth() const;

        /**
         * Absorbs message bytes.
         * @param buf The data to authenticate.
         * @return The number of bytes absorbed; 0 if this instance is not keyed.
         */
        size_t push(const SReadOnlyByteSpan& buf);

        /**
         * Finalizes and writes the tag. Like `IHasher::finish()` this is a query -- it works on a
         * copy of the state, so it may be called more than once and absorption may continue.
         * @param out At least byteWidth() bytes; exactly byteWidth() are written.
         * @return true on success.
         */
        bool finish(const SByteSpan& out);

        /**
         * One-shot keyed BLAKE2s.
         * @param key The key; 0..MAX_KEY_BYTES bytes.
         * @param message The message.
         * @param out The tag buffer; its size picks the tag length, so it must be
         * 1..MAX_TAG_BYTES bytes.
         * @return true on success.
         */
        static bool compute(
            const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message,
            const SByteSpan& out
        );

        /**
         * One-shot verification, comparing in time that depends only on the tag's length.
         *
         * This is the entry point to use when checking a received tag; see this class's doc
         * comment for why a `memcmp` there is a forgery oracle.
         * @param key The key; 0..MAX_KEY_BYTES bytes.
         * @param message The message.
         * @param tag The tag to check; its size is taken as the tag length the sender used, which
         * must be 1..MAX_TAG_BYTES.
         * @return true if the tag matches.
         */
        static bool verify(
            const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message,
            const SReadOnlyByteSpan& tag
        );
    };

} // namespace crypto
} // namespace certpp

#endif
