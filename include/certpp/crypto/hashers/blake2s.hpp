#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_BLAKE2S_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_BLAKE2S_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * BLAKE2s (RFC 7693), the 32-bit-word member of the BLAKE2 family, as an unkeyed hash --
     * from scratch, like every other hasher here.
     *
     * Structurally it is a ChaCha-style permutation in a HAIFA construction, not a Merkle-Damgard
     * one: there is no length-padding block, the byte counter and a finalization flag are fed
     * directly into the last compression, and the whole thing is little-endian where the SHA-2
     * family is big-endian. The digest length is bound into the parameter block, so BLAKE2s-16 is
     * a different function from the leading 16 bytes of BLAKE2s-32 -- truncating a 32-byte digest
     * yourself is not the same thing as asking for a shorter one.
     *
     * Added because WireGuard's handshake is built on it (its `HASH()`, its `MAC()` and its HKDF),
     * but it is an ordinary member of the EHashers family (EHASH_BLAKE2S) and usable anywhere a
     * hasher is, including under `CHmac` (whose block size for it is 64 bytes).
     *
     * This class is the **unkeyed** hash only. BLAKE2's native keyed mode absorbs the key as a
     * padded first block rather than wrapping the hash the way HMAC does, and `IHasher` has
     * nowhere to put a key -- see `CBlake2sMac` (crypto/blake2smac.hpp) for that, and `CHmac`
     * with EHASH_BLAKE2S for the generic RFC 2104 construction over this hash. The three are
     * genuinely three different functions over the same key and message; they are not
     * interchangeable.
     *
     * `finish()` is a query, as in the SHA-2 family: it pads and compresses a copy, so it may be
     * called repeatedly and `push()` still works afterwards.
     */
    class CERTPP_API BLAKE2s : public IHasher {
    private:
        /**
         * Internal state for BLAKE2s computation.
         */
        struct Context {
            uint32_t state[8];   // --> h0..h7, seeded from the IV XORed with the parameter block.
            uint8_t buffer[64];  // --> Buffered input; a full block is held back in case it's last.
            size_t bufferLen;    // --> Valid bytes currently in buffer (0-64, not 0-63).
            uint64_t counter;    // --> Total bytes already compressed (RFC 7693's t).
        };

    private:
        Context _ctx;

    public:
        /** The compression function's block size, and HMAC's block size for this hash. */
        static constexpr size_t BLOCK_BYTES = 64;

        /** The longest digest RFC 7693 defines for BLAKE2s, and the default. */
        static constexpr size_t MAX_DIGEST_BYTES = 32;

    private:
        /**
         * Folds an out-of-range requested digest length onto the default, so the constructor
         * cannot leave an instance whose byteWidth() the parameter block has no encoding for.
         * @param outputBytes The requested digest length.
         * @return outputBytes when it is 1..MAX_DIGEST_BYTES, otherwise MAX_DIGEST_BYTES.
         */
        static constexpr size_t clampDigestBytes(size_t outputBytes) {
            return (outputBytes >= 1 && outputBytes <= MAX_DIGEST_BYTES)
                ? outputBytes : MAX_DIGEST_BYTES;
        }

    public:
        /**
         * Constructs a BLAKE2s hasher, ready to accept input.
         * @param outputBytes The digest length, 1..MAX_DIGEST_BYTES; anything outside that range
         * is taken as MAX_DIGEST_BYTES, since RFC 7693 binds the length into the parameter block
         * and has no encoding for a longer one.
         */
        explicit BLAKE2s(size_t outputBytes = MAX_DIGEST_BYTES)
            : IHasher(clampDigestBytes(outputBytes))
        {
            reset();
        }

        /**
         * Resets the BLAKE2s context to its initial state, for the same digest length.
         */
        void reset() override;

        /**
         * Pushes data into the BLAKE2s context for hashing.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes the BLAKE2s hash computation and writes the result to the output buffer.
         * Works on a copy of the state, so it may be called more than once and hashing may
         * continue afterwards.
         * @param out The output buffer to store the hash result (at least byteWidth() bytes).
         * @return True if the hash was successfully finalized, false otherwise.
         */
        bool finish(const SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
