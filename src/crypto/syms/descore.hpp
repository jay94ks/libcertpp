#ifndef __SRC_CRYPTO_SYMS_DESCORE_HPP__
#define __SRC_CRYPTO_SYMS_DESCORE_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /* Single-DES block cipher core (FIPS 46-3), shared by DES and TripleDES. The TripleDES path
     * applies three Feistel schedules in Encrypt-Decrypt-Encrypt order while retaining the
     * permuted block between stages, so each block needs only one initial/final permutation. */
    class DesCore {
    public:
        struct RoundKey {
            uint32_t even;
            uint32_t odd;
        };

    private:
        struct SpBoxes {
            uint32_t values[8][64];
        };

        struct BlockPermutations {
            uint64_t initial[8][256];
            uint64_t final[8][256];
        };

        static const uint8_t IP[64];
        static const uint8_t FP[64];
        static const uint8_t PBOX[32];
        static const uint8_t PC1[56];
        static const uint8_t PC2[48];
        static const uint8_t SHIFTS[16];
        static const uint8_t SBOX[8][64]; // --> 8 S-boxes, 4 rows x 16 cols each, flattened.

        /* Selects tableLen bits out of input (an inputBits-wide value) per table, where table[i]
         * is the 1-indexed source bit position counting from input's most significant bit --
         * the convention FIPS 46-3 itself numbers every one of its permutation tables with. */
        static uint64_t permute(uint64_t input, const uint8_t* table, size_t tableLen, size_t inputBits);

        /* Builds the eight S-box/P-permutation tables once from the FIPS tables above. */
        static const SpBoxes& spBoxes();

        /* Builds byte-sliced initial/final permutation tables once from the FIPS tables. */
        static const BlockPermutations& blockPermutations();

        /* Applies one of the byte-sliced 64-bit block permutations. */
        static uint64_t permuteBlock(uint64_t input, const uint64_t table[8][256]);

        /* The Feistel round function f(R, K), using combined S-box/P-permutation lookups. */
        static uint32_t feistel(uint32_t r, const RoundKey& roundKey, const SpBoxes& boxes);

        static uint64_t loadBlock(const uint8_t in[8]);
        static void storeBlock(uint64_t value, uint8_t out[8]);
        static uint64_t processPermuted(
            uint64_t input, const RoundKey roundKeys[16], const SpBoxes& boxes
        );

    public:
        /**
         * Expands an 8-byte key into its 16 round keys, in encryption order (K1..K16).
         * @param key The 8-byte (64-bit, including the 8 parity bits PC-1 discards) DES key.
         * @param roundKeys Receives 16 pairs of words arranged for the rotated S-box lookups.
         */
        static void keySchedule(const uint8_t key[8], RoundKey roundKeys[16]);

        /**
         * Encrypts or decrypts one 8-byte block with the given round keys, applied in the order
         * given -- K1..K16 (keySchedule()'s own output order) to encrypt, or that same array
         * reversed (K16..K1) to decrypt, since DES's Feistel structure is self-inverse under a
         * reversed key schedule.
         * @param in The 8-byte input block.
         * @param out The 8-byte output block; may alias in.
         * @param roundKeys The 16 round keys, in the order to apply them.
         */
        static void processBlock(const uint8_t in[8], uint8_t out[8], const RoundKey roundKeys[16]);

        /**
         * Processes one Triple-DES EDE block while applying the initial and final permutations
         * only once; the final permutation of one DES stage and the next stage's initial
         * permutation are inverses and cancel.
         * @param in The 8-byte input block.
         * @param out The 8-byte output block; may alias in.
         * @param roundKeys Three schedules already oriented for their encrypt/decrypt stages.
         */
        static void processTripleBlock(
            const uint8_t in[8], uint8_t out[8], const RoundKey roundKeys[3][16]
        );

        /** Encrypts complete DES-CBC blocks while keeping the chaining value local. */
        static void encryptCbcBulk(
            const uint8_t* in, uint8_t* out, size_t blocks, uint8_t chain[8],
            const RoundKey roundKeys[16]
        );

        /** Encrypts complete Triple-DES-CBC blocks with one IP/FP pair per EDE block. */
        static void encryptTripleCbcBulk(
            const uint8_t* in, uint8_t* out, size_t blocks, uint8_t chain[8],
            const RoundKey roundKeys[3][16]
        );

    };

} // namespace crypto
} // namespace certpp

#endif
