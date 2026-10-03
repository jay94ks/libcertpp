#ifndef __INCLUDE_CERTPP_CRYPTO_AEADS_CHACHA20POLY1305_HPP__
#define __INCLUDE_CERTPP_CRYPTO_AEADS_CHACHA20POLY1305_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * ChaCha20-Poly1305 AEAD (RFC 8439 2.8).
     *
     * One instance is a keyed context: construct it once per key -- in a transport, once per
     * link direction -- and call `seal()`/`open()` per record with only the nonce changing.
     * Neither operation allocates, so a per-record cost is the cipher and the MAC and nothing
     * else.
     *
     * **`out` may alias `in`.** Both operations are written to tolerate exact aliasing, which is
     * what lets a receiver decrypt a record where it already sits in its buffer. For `open()`
     * that needs care beyond the usual: the tag is computed over the *ciphertext*, so it is
     * verified before a single plaintext byte is written. A failed `open()` therefore leaves the
     * buffer untouched rather than half-overwritten with unauthenticated plaintext -- which
     * matters precisely because in-place use means the caller has nowhere else to keep it.
     *
     * **A nonce must never repeat under one key.** Reusing one reveals the XOR of two
     * plaintexts and, worse, exposes the Poly1305 one-time key, after which tags can be forged.
     * The 96-bit nonce is the caller's to manage; a counter is the usual answer, and RFC 8439
     * 4's guidance is worth reading before choosing anything else.
     *
     * Three details of RFC 8439 2.8 are easy to get wrong and invisible to a round-trip test,
     * since each is self-consistent:
     *
     * - the payload is encrypted from **block counter 1**, because counter 0 is spent deriving
     *   the Poly1305 key;
     * - the MAC covers `aad || pad16(aad) || ciphertext || pad16(ciphertext) || le64(|aad|) ||
     *   le64(|ciphertext|)`, where the padding closes a block rather than extending the message
     *   and the two lengths are 64-bit little-endian;
     * - the MAC is over the ciphertext, not the plaintext (encrypt-then-MAC).
     */
    class CERTPP_API CChaCha20Poly1305 {
    private:
        uint8_t _key[32];
        bool _keyed;

    public:
        /** Key length in bytes. */
        static constexpr size_t KEY_BYTES = 32;

        /** Nonce length in bytes (96 bits). */
        static constexpr size_t NONCE_BYTES = 12;

        /** Authentication tag length in bytes. */
        static constexpr size_t TAG_BYTES = 16;

    public:
        /**
         * Constructs an unkeyed context; call reset() before use.
         */
        CChaCha20Poly1305();

        /**
         * Destructor; clears the key.
         */
        ~CChaCha20Poly1305();

        CChaCha20Poly1305(const CChaCha20Poly1305&) = delete;
        CChaCha20Poly1305& operator=(const CChaCha20Poly1305&) = delete;

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
         * The tag is checked first, in time that depends only on its length, and the plaintext
         * is written only if it matches -- so a false return leaves `out` untouched even when it
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
         * Derives the one-time Poly1305 key for a nonce (RFC 8439 2.6): the first 32 bytes of
         * the ChaCha20 block at counter 0.
         *
         * Exposed because RFC 8439 2.6.2 publishes a test vector for it, and because the
         * derivation is the part a reader most wants to confirm independently. A caller
         * implementing the AEAD itself has no reason to need it.
         * @param nonce Exactly NONCE_BYTES.
         * @param out Exactly 32 bytes.
         * @return true on success.
         */
        bool deriveOneTimeKey(const SReadOnlyByteSpan& nonce, const SByteSpan& out) const;
    };

} // namespace crypto
} // namespace certpp

#endif
