#ifndef __SRC_CRYPTO_SYMS_CHACHA20CORE_HPP__
#define __SRC_CRYPTO_SYMS_CHACHA20CORE_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * ChaCha20's block function (RFC 8439 2.3). Private to `src/`, shared between the
     * `ISymmetric` stream cipher (`crypto/syms/chacha20.cpp`) and the AEAD
     * (`crypto/aeads/chacha20poly1305.cpp`) -- the same arrangement `DesCore` has between DES
     * and TripleDES, and `KeccakCore` between the SHAKEs and SHA-3.
     *
     * It was extracted here rather than duplicated because the AEAD needs the block function at
     * two *different* counters that the stream-cipher interface cannot express:
     *
     * - counter 0, whose first 32 bytes are the one-time Poly1305 key (RFC 8439 2.6), and whose
     *   remaining 32 bytes are discarded;
     * - counter 1 onwards for the payload, because block 0 is spent on that key.
     *
     * That off-by-one is the detail most easily got wrong in this AEAD. Encrypting from counter
     * 0 produces a ciphertext that decrypts correctly against itself, authenticates correctly
     * against itself, and is rejected by every other implementation.
     *
     * **The state is prepared once and reused across blocks.** The constants, key and nonce
     * occupy fifteen of the sixteen state words and do not change between blocks; only the
     * counter does. An interface that took the key and nonce per block -- which this had
     * originally -- re-parsed eleven little-endian words for every 64 bytes of output, which at
     * 64 KiB is eleven thousand redundant loads. `SState` exists so that cost is paid once per
     * message instead.
     */
    class ChaCha20Core {
    public:
        /** Key length in bytes (256 bits). */
        static constexpr size_t KEY_BYTES = 32;

        /** Nonce length in bytes (96 bits, RFC 8439's IETF variant). */
        static constexpr size_t NONCE_BYTES = 12;

        /** Keystream block length in bytes. */
        static constexpr size_t BLOCK_BYTES = 64;

        /**
         * The prepared state: the four constants, the eight key words and the three nonce words,
         * with word 12 (the counter) left for each block to fill in.
         */
        struct SState {
            uint32_t words[16];
        };

    public:
        /**
         * Prepares a state from a key and nonce.
         * @param out Receives the prepared state.
         * @param key The 32-byte key.
         * @param nonce The 12-byte nonce.
         */
        static void initState(
            SState& out, const uint8_t key[KEY_BYTES], const uint8_t nonce[NONCE_BYTES]
        );

        /**
         * Produces one keystream block from a prepared state.
         * @param state The prepared state.
         * @param counter The 32-bit block counter.
         * @param out Receives 64 bytes of keystream.
         */
        static void block(const SState& state, uint32_t counter, uint8_t out[BLOCK_BYTES]);

        /**
         * XORs `length` bytes of keystream, starting at `initialCounter`, over the input.
         *
         * Whole blocks are combined 32 bits at a time rather than byte by byte, which is the
         * difference between four and sixteen operations per sixteen bytes; only the trailing
         * partial block falls back to bytes. `out` may alias `in` exactly, which is what lets a
         * receiver decrypt a record where it already sits.
         * @param state The prepared state.
         * @param initialCounter The block counter for the first block.
         * @param in The input bytes.
         * @param out Receives the result; may alias in.
         * @param length Number of bytes to process.
         */
        static void xorStream(
            const SState& state, uint32_t initialCounter,
            const uint8_t* in, uint8_t* out, size_t length
        );

        /**
         * Produces one keystream block, preparing the state for this call alone.
         *
         * Convenient for a one-off block, and wasteful for a sequence of them -- prefer
         * `initState()` plus `xorStream()` or `block()` when producing more than one.
         * @param key The 32-byte key.
         * @param counter The 32-bit block counter.
         * @param nonce The 12-byte nonce.
         * @param out Receives 64 bytes of keystream.
         */
        static void block(
            const uint8_t key[KEY_BYTES], uint32_t counter,
            const uint8_t nonce[NONCE_BYTES], uint8_t out[BLOCK_BYTES]
        );
    };

} // namespace crypto
} // namespace certpp

#endif
