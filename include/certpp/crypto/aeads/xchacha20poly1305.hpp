#ifndef __INCLUDE_CERTPP_CRYPTO_AEADS_XCHACHA20POLY1305_HPP__
#define __INCLUDE_CERTPP_CRYPTO_AEADS_XCHACHA20POLY1305_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha), the extended-nonce construction
     * WireGuard and libsodium use.
     *
     * It is RFC 8439's ChaCha20-Poly1305 with a 192-bit nonce instead of a 96-bit one, reached in
     * two steps per record:
     *
     * - `subkey = HChaCha20(key, nonce[0:16])`, the nonce-extension function;
     * - then the RFC 8439 AEAD under that subkey with the 96-bit nonce `00 00 00 00 ||
     *   nonce[16:24]`.
     *
     * **Why bother.** A 96-bit nonce is too short to choose at random: by the birthday bound a
     * repeat becomes likely after about 2^48 records under one key, which is close enough to
     * matter that RFC 8439 effectively requires a counter, and a counter requires state that
     * survives restarts and is not shared between senders. 192 bits is long enough that random
     * nonces are safe for any realistic number of records, so the key can be used by parties that
     * cannot coordinate a counter at all. The cost is one extra block of ChaCha20 per record.
     *
     * The API mirrors CChaCha20Poly1305 exactly and keeps the same contracts: one instance is a
     * keyed context, constructed once per key -- in a transport, once per link direction -- and
     * called per record with only the nonce changing. Neither operation allocates. The subkey
     * cannot be cached across calls, since it depends on the nonce, so it is derived into a stack
     * buffer on each one and cleared before returning.
     *
     * **`out` may alias `in`**, which is what lets a receiver decrypt a record where it already
     * sits in its buffer. For `open()` that means the tag is verified before a single plaintext
     * byte is written, so a rejected record leaves the buffer holding the ciphertext it arrived
     * as rather than half-overwritten with unauthenticated plaintext.
     *
     * **A nonce must still never repeat under one key.** The longer nonce makes a collision
     * unlikely rather than impossible, and the consequence of one is unchanged: the XOR of two
     * plaintexts, and a recovered Poly1305 one-time key, after which tags can be forged.
     *
     * Two details beyond the inner AEAD's own three (see CChaCha20Poly1305) are easy to get wrong
     * and invisible to a round-trip test, because each is self-consistent:
     *
     * - HChaCha20 has **no feed-forward** -- it does not add the original state back the way the
     *   ChaCha20 block function does, so the block function cannot be reused for it;
     * - the inner nonce is four zero bytes **followed by** `nonce[16:24]`, not the other way
     *   round.
     */
    class CERTPP_API CXChaCha20Poly1305 {
    private:
        uint8_t _key[32];
        bool _keyed;

    public:
        /** Key length in bytes. */
        static constexpr size_t KEY_BYTES = 32;

        /** Nonce length in bytes (192 bits), which is what distinguishes this from RFC 8439. */
        static constexpr size_t NONCE_BYTES = 24;

        /** Authentication tag length in bytes. */
        static constexpr size_t TAG_BYTES = 16;

        /** Length in bytes of the subkey HChaCha20 derives. */
        static constexpr size_t SUBKEY_BYTES = 32;

    public:
        /**
         * Constructs an unkeyed context; call reset() before use.
         */
        CXChaCha20Poly1305();

        /**
         * Destructor; clears the key.
         */
        ~CXChaCha20Poly1305();

        CXChaCha20Poly1305(const CXChaCha20Poly1305&) = delete;
        CXChaCha20Poly1305& operator=(const CXChaCha20Poly1305&) = delete;

    public:
        /**
         * Keys this context. May be called again to re-key.
         * @param key Exactly KEY_BYTES.
         * @return true on success; false if the key is the wrong size.
         */
        bool reset(const SReadOnlyByteSpan& key);

        /**
         * @return true if this context holds a key.
         */
        bool keyed() const;

        /**
         * Encrypts and authenticates.
         * @param nonce Exactly NONCE_BYTES; must not repeat under this key.
         * @param aad Additional data to authenticate but not encrypt; may be empty.
         * @param in The plaintext.
         * @param out Receives the ciphertext; exactly in.size bytes, and may alias in.
         * @param tag Receives TAG_BYTES.
         * @return true on success; false on a size mismatch or if the context is unkeyed.
         */
        bool seal(
            const SReadOnlyByteSpan& nonce, const SReadOnlyByteSpan& aad,
            const SReadOnlyByteSpan& in, const SByteSpan& out, const SByteSpan& tag
        ) const;

        /**
         * Verifies and decrypts.
         *
         * The tag is checked first, in time that depends only on its length, and the plaintext is
         * written only if it matches -- so a false return leaves `out` untouched even when it
         * aliases `in`. Comparing the tag with `memcmp` instead would leak how much of a forged
         * tag was correct, which is enough to construct one byte by byte.
         * @param nonce Exactly NONCE_BYTES.
         * @param aad The additional data the sender authenticated; may be empty.
         * @param in The ciphertext.
         * @param tag The TAG_BYTES tag to verify.
         * @param out Receives the plaintext; exactly in.size bytes, and may alias in.
         * @return true if the tag verified and the plaintext was written; false otherwise, with
         * out left unmodified.
         */
        bool open(
            const SReadOnlyByteSpan& nonce, const SReadOnlyByteSpan& aad,
            const SReadOnlyByteSpan& in, const SReadOnlyByteSpan& tag, const SByteSpan& out
        ) const;

        /**
         * Derives the per-nonce subkey, `HChaCha20(key, nonce[0:16])`.
         *
         * Exposed for the same reason CChaCha20Poly1305::deriveOneTimeKey() is: the draft
         * publishes a test vector for HChaCha20 (2.2.1), and this is the step a reader most wants
         * to confirm independently. The last eight nonce bytes are not read -- they belong to the
         * inner AEAD's nonce -- so checking a published HChaCha20 vector means passing its 16-byte
         * nonce padded to NONCE_BYTES with any eight bytes at all.
         * @param nonce Exactly NONCE_BYTES; only the first 16 are used.
         * @param out Exactly SUBKEY_BYTES.
         * @return true on success.
         */
        bool deriveSubkey(const SReadOnlyByteSpan& nonce, const SByteSpan& out) const;
    };

} // namespace crypto
} // namespace certpp

#endif
