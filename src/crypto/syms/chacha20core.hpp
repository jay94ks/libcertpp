#ifndef __SRC_CRYPTO_SYMS_CHACHA20CORE_HPP__
#define __SRC_CRYPTO_SYMS_CHACHA20CORE_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * ChaCha20's block function (RFC 8439 2.3): expands a 256-bit key, a 96-bit nonce and a
     * 32-bit block counter into one 64-byte keystream block. Private to `src/`, shared between
     * the `ISymmetric` stream cipher (`crypto/syms/chacha20.cpp`) and the AEAD
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
     */
    class ChaCha20Core {
    public:
        /** Key length in bytes (256 bits). */
        static constexpr size_t KEY_BYTES = 32;

        /** Nonce length in bytes (96 bits, RFC 8439's IETF variant). */
        static constexpr size_t NONCE_BYTES = 12;

        /** Keystream block length in bytes. */
        static constexpr size_t BLOCK_BYTES = 64;

    public:
        /**
         * Produces one keystream block.
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
