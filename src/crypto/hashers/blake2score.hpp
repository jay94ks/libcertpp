#ifndef __SRC_CRYPTO_HASHERS_BLAKE2SCORE_HPP__
#define __SRC_CRYPTO_HASHERS_BLAKE2SCORE_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * The whole BLAKE2s state machine (RFC 7693 3.1-3.3) -- parameter-block initialization, the
     * compression function, the buffering, and the finalization -- private, so no type prefix.
     * Exposed as free-standing operations over raw arrays exactly as `Sha3Core` is, so each
     * public class can declare its own context in its own header without depending on anything
     * under `src/`.
     *
     * Shared by `BLAKE2s` (the unkeyed `IHasher`) and `CBlake2sMac` (the keyed MAC of RFC 7693
     * 2.9/3.3), which differ in nothing but how they are initialized: both the digest length and
     * the key length are baked into the first state word by `init()`, so a 16-byte digest is a
     * different function from the first 16 bytes of a 32-byte one, and a keyed instance is a
     * different function from an unkeyed one over the key-prefixed message.
     *
     * Two traps worth naming, since both produce a self-consistent wrong answer:
     * - BLAKE2s is **little-endian** throughout (message words in, digest words out), where the
     *   SHA-2 family is big-endian.
     * - A block is compressed only once the next byte is known to exist. The final block gets the
     *   `f[0]` flag (`v[14] ^= 0xFFFFFFFF`), so an exactly-block-sized message must leave its last
     *   block buffered rather than compressing it eagerly -- which is why `absorb()` breaks on a
     *   strict `>` and not `>=`.
     *
     * `f[1]`, the last-node flag, is not implemented: it only applies to BLAKE2's tree-hashing
     * mode, which this does not support (fanout and depth are fixed at 1, the sequential mode).
     */
    class Blake2sCore {
    public:
        static constexpr size_t BLOCK_BYTES = 64;      // --> One compression-function block.
        static constexpr size_t MAX_DIGEST_BYTES = 32; // --> RFC 7693 3.2's nn upper bound.
        static constexpr size_t MAX_KEY_BYTES = 32;    // --> RFC 7693 3.2's kk upper bound.

    private:
        /**
         * Runs the compression function F over one block, updating the 8-word state in place.
         * @param state The running hash state h[0..7], updated in place.
         * @param block The BLOCK_BYTES-sized input block.
         * @param counter The total number of input bytes consumed including this block (t).
         * @param last Whether this is the final block (sets the f[0] finalization flag).
         */
        static void compress(
            uint32_t state[8], const uint8_t block[BLOCK_BYTES], uint64_t counter, bool last
        );

    public:
        /**
         * Initializes a context: sets the state to the IV XORed with the parameter block, and
         * seeds the buffer with the zero-padded key block when a key is given (RFC 7693 2.9 --
         * the key is the first message block, not an HMAC-style wrapper).
         * @param state The 8-word state to initialize.
         * @param buffer The BLOCK_BYTES-sized partial-block buffer.
         * @param bufferLen Set to 0, or to BLOCK_BYTES when a key is given.
         * @param counter Set to 0.
         * @param digestBytes The digest length in bytes; must be 1..MAX_DIGEST_BYTES.
         * @param key The key; empty for the unkeyed hash, otherwise at most MAX_KEY_BYTES.
         */
        static void init(
            uint32_t state[8], uint8_t buffer[BLOCK_BYTES], size_t& bufferLen, uint64_t& counter,
            size_t digestBytes, const SReadOnlyByteSpan& key
        );

        /**
         * Absorbs input, holding back whatever might turn out to be the final block.
         * @param state The 8-word state, updated in place.
         * @param buffer The BLOCK_BYTES-sized partial-block buffer.
         * @param bufferLen Valid bytes in buffer (1..BLOCK_BYTES after any input); updated.
         * @param counter The byte counter t; updated.
         * @param buf The input to absorb.
         * @return The number of input bytes consumed, which is always buf.size.
         */
        static size_t absorb(
            uint32_t state[8], uint8_t buffer[BLOCK_BYTES], size_t& bufferLen, uint64_t& counter,
            const SReadOnlyByteSpan& buf
        );

        /**
         * Pads the buffered bytes with zeros, compresses that final block with the f[0] flag set
         * and writes the little-endian digest -- all on copies, leaving state, buffer and counter
         * untouched so this is a query the caller may repeat and absorb past.
         * @param state The current 8-word state.
         * @param buffer The partial-block buffer.
         * @param bufferLen Valid bytes in buffer.
         * @param counter The byte counter t, excluding the buffered bytes.
         * @param out Destination for digestBytes bytes.
         * @param digestBytes Bytes to write; must be 1..MAX_DIGEST_BYTES.
         */
        static void digest(
            const uint32_t state[8], const uint8_t buffer[BLOCK_BYTES], size_t bufferLen,
            uint64_t counter, uint8_t* out, size_t digestBytes
        );
    };

} // namespace crypto
} // namespace certpp

#endif
