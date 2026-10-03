#ifndef __INCLUDE_CERTPP_CRYPTO_AEADS_AESGCM_HPP__
#define __INCLUDE_CERTPP_CRYPTO_AEADS_AESGCM_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * AES-GCM (NIST SP 800-38D), with AES-128/192/256 and a 96-bit IV.
     *
     * One instance is a keyed context: construct it once per key -- in a transport, once per link
     * direction -- and call `seal()`/`open()` per record with only the IV changing. The key
     * schedule and the GHASH subkey are derived once, in `reset()`, and neither operation
     * allocates, so a per-record cost is the cipher and the hash and nothing else.
     *
     * **`out` may alias `in`.** Both operations tolerate exact aliasing, which is what lets a
     * receiver decrypt a record where it already sits in its buffer. For `open()` that needs care
     * beyond the usual: the tag is computed over the *ciphertext*, so it is verified before a
     * single plaintext byte is written. A failed `open()` therefore leaves the buffer untouched
     * rather than half-overwritten with unauthenticated plaintext.
     *
     * **An IV must never repeat under one key.** GCM is a counter mode, so a repeat reveals the
     * XOR of two plaintexts; far worse, it leaks enough to recover the GHASH subkey H, after
     * which tags can be forged at will for *every* message under that key. This is a sharper
     * cliff than most AEADs have, and SP 800-38D 8.3's limits (a deterministic construction, and
     * at most 2^32 invocations per key where the IV is random) exist because of it. The IV is the
     * caller's to manage; a counter is the usual answer.
     *
     * **Only a 96-bit IV is accepted.** SP 800-38D allows any length, but anything other than 96
     * bits derives the initial counter block by running the IV through GHASH instead of using it
     * directly -- a second code path, with its own way to be subtly wrong, that no caller of this
     * library needs: IKEv2 (RFC 4106/5282), TLS and SSH all use exactly 96 bits, and 96 bits is
     * the length SP 800-38D 8.2 itself recommends.
     *
     * Details of SP 800-38D 7.1 that are easy to get wrong and that a round-trip cannot see,
     * since each is self-consistent:
     *
     * - the payload is encrypted from **counter block J0 + 1**, because J0 itself is spent on the
     *   tag's mask -- with a 96-bit IV, J0 = IV || 0^31 || 1, so the first payload block uses
     *   IV || 0^31 || 2;
     * - GHASH covers `A || pad(A) || C || pad(C) || [len(A)]_64 || [len(C)]_64`, where the two
     *   lengths are in **bits**, not bytes, and **big-endian**, not little-endian (which is what
     *   ChaCha20-Poly1305 uses in the same position);
     * - GHASH's field is bit-reflected, so a GF(2^128) multiply written to the usual
     *   polynomial-basis convention is self-consistent and not GHASH;
     * - the hash is over the ciphertext, not the plaintext (encrypt-then-MAC).
     */
    class CERTPP_API CAesGcm {
    private:
        // --> Mirrors AesCore::MAX_ROUND_KEY_BYTES (16 bytes per round key, 15 of them for
        // AES-256); a static_assert in aesgcm.cpp keeps the two from drifting apart.
        static constexpr size_t ROUND_KEY_BYTES = 16 * 15;

        uint8_t _roundKeys[ROUND_KEY_BYTES];
        uint8_t _subkey[16];    // --> H = E_K(0^128), GHASH's key.
        uint32_t _rounds;
        size_t _keyBytes;

    public:
        /** AES-128's key length in bytes. */
        static constexpr size_t KEY_BYTES_128 = 16;

        /** AES-192's key length in bytes. */
        static constexpr size_t KEY_BYTES_192 = 24;

        /** AES-256's key length in bytes. */
        static constexpr size_t KEY_BYTES_256 = 32;

        /** IV length in bytes (96 bits); see this class's note on why it is the only one. */
        static constexpr size_t IV_BYTES = 12;

        /** The cipher's block length in bytes, which is also GHASH's. */
        static constexpr size_t BLOCK_BYTES = 16;

        /** The full authentication tag length in bytes, and the default. */
        static constexpr size_t TAG_BYTES = 16;

        /**
         * The shortest tag accepted, in bytes (96 bits). SP 800-38D 5.2.1.2 permits 128, 120,
         * 112, 104 and 96 bits -- which is every length from this to TAG_BYTES -- and nothing
         * shorter outside the narrow, application-specific exceptions of its Appendix C. A
         * truncated tag is the same tag with its tail dropped, so a shorter one is weaker by
         * exactly the bits it gives up: the forgery probability per attempt rises to 2^-t.
         */
        static constexpr size_t MIN_TAG_BYTES = 12;

        /**
         * The longest plaintext one invocation may cover, in bytes: SP 800-38D 5.2.1.1 caps the
         * ciphertext at 2^39 - 256 bits, because beyond it the counter would wrap around and
         * repeat keystream within a single message.
         */
        static constexpr uint64_t MAX_PAYLOAD_BYTES = (uint64_t(1) << 36) - 32;

    public:
        /**
         * Constructs an unkeyed context; call reset() before use.
         */
        CAesGcm();

        /**
         * Destructor; clears the key schedule and the GHASH subkey.
         */
        ~CAesGcm();

        CAesGcm(const CAesGcm&) = delete;
        CAesGcm& operator=(const CAesGcm&) = delete;

    public:
        /**
         * Keys this context, expanding the key schedule and deriving the GHASH subkey. May be
         * called again to re-key.
         * @param key Exactly KEY_BYTES_128, KEY_BYTES_192 or KEY_BYTES_256 bytes.
         * @return true on success; false if the key is not one of those three lengths, in which
         * case the context is left unkeyed.
         */
        bool reset(const SReadOnlyByteSpan& key);

        /**
         * @return true if this context holds a key.
         */
        bool keyed() const;

        /**
         * @return The length in bytes of the key this context holds, or 0 if it is unkeyed.
         */
        size_t keyBytes() const;

        /**
         * Encrypts and authenticates.
         * @param iv Exactly IV_BYTES; must not repeat under this key.
         * @param aad Additional data to authenticate but not encrypt; may be empty.
         * @param in The plaintext; may be empty, and at most MAX_PAYLOAD_BYTES long.
         * @param out Receives the ciphertext; exactly in.size bytes, and may alias in.
         * @param tag Receives the tag; between MIN_TAG_BYTES and TAG_BYTES bytes, and normally
         * TAG_BYTES.
         * @return true on success; false on a size mismatch or if the context is unkeyed.
         */
        bool seal(
            const SReadOnlyByteSpan& iv, const SReadOnlyByteSpan& aad,
            const SReadOnlyByteSpan& in, const SByteSpan& out, const SByteSpan& tag
        ) const;

        /**
         * Verifies and decrypts.
         *
         * The tag is checked first, in time that depends only on its length, and the plaintext is
         * written only if it matches -- so a false return leaves `out` untouched even when it
         * aliases `in`. Comparing the tag with `memcmp` instead would leak how much of a forged
         * tag was correct, which is enough to construct one byte by byte.
         *
         * The caller must decide the tag length rather than infer it from the record, and pass a
         * `tag` of exactly that length: letting an attacker choose it would let them pick the
         * shortest one accepted, which is a forgery probability they control.
         * @param iv Exactly IV_BYTES.
         * @param aad The additional data the sender authenticated; may be empty.
         * @param in The ciphertext.
         * @param tag The tag to verify, between MIN_TAG_BYTES and TAG_BYTES bytes.
         * @param out Receives the plaintext; exactly in.size bytes, and may alias in.
         * @return true if the tag verified and the plaintext was written; false otherwise, with
         * out left unmodified.
         */
        bool open(
            const SReadOnlyByteSpan& iv, const SReadOnlyByteSpan& aad,
            const SReadOnlyByteSpan& in, const SReadOnlyByteSpan& tag, const SByteSpan& out
        ) const;

        /**
         * Copies out the GHASH subkey H = E_K(0^128) (SP 800-38D 7.1 step 1).
         *
         * Exposed because the GCM specification publishes H for each of its test cases, and it is
         * the one intermediate value that tells a reader whether a mismatch is in the block
         * cipher or in the hash. A caller using the AEAD has no reason to need it -- and should
         * treat it as key material if it takes it, since H is what an IV repeat leaks and what
         * forging a tag requires.
         * @param out Exactly BLOCK_BYTES.
         * @return true on success; false if out is the wrong size or the context is unkeyed.
         */
        bool deriveSubkey(const SByteSpan& out) const;
    };

} // namespace crypto
} // namespace certpp

#endif
