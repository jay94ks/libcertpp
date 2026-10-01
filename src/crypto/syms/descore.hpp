#ifndef __SRC_CRYPTO_SYMS_DESCORE_HPP__
#define __SRC_CRYPTO_SYMS_DESCORE_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /* Single-DES block cipher core (FIPS 46-3), shared by DES and TripleDES -- 3DES simply runs
     * this same 8-byte-block core three times in Encrypt-Decrypt-Encrypt order with up to three
     * keys, so the Feistel network/key schedule/S-boxes only need to exist once. */
    class DesCore {
    private:
        static const uint8_t IP[64];
        static const uint8_t FP[64];
        static const uint8_t EXPANSION[48];
        static const uint8_t PBOX[32];
        static const uint8_t PC1[56];
        static const uint8_t PC2[48];
        static const uint8_t SHIFTS[16];
        static const uint8_t SBOX[8][64]; // --> 8 S-boxes, 4 rows x 16 cols each, flattened.

        /* Selects tableLen bits out of input (an inputBits-wide value) per table, where table[i]
         * is the 1-indexed source bit position counting from input's most significant bit --
         * the convention FIPS 46-3 itself numbers every one of its permutation tables with. */
        static uint64_t permute(uint64_t input, const uint8_t* table, size_t tableLen, size_t inputBits);

        /* The Feistel round function f(R, K): expansion, key mixing, S-box substitution, P
         * permutation. */
        static uint32_t feistel(uint32_t r, uint64_t roundKey);

    public:
        /**
         * Expands an 8-byte key into its 16 round keys, in encryption order (K1..K16).
         * @param key The 8-byte (64-bit, including the 8 parity bits PC-1 discards) DES key.
         * @param roundKeys Receives the 16 round keys, each a 48-bit value in the low 48 bits.
         */
        static void keySchedule(const uint8_t key[8], uint64_t roundKeys[16]);

        /**
         * Encrypts or decrypts one 8-byte block with the given round keys, applied in the order
         * given -- K1..K16 (keySchedule()'s own output order) to encrypt, or that same array
         * reversed (K16..K1) to decrypt, since DES's Feistel structure is self-inverse under a
         * reversed key schedule.
         * @param in The 8-byte input block.
         * @param out The 8-byte output block; may alias in.
         * @param roundKeys The 16 round keys, in the order to apply them.
         */
        static void processBlock(const uint8_t in[8], uint8_t out[8], const uint64_t roundKeys[16]);
    };

} // namespace crypto
} // namespace certpp

#endif
