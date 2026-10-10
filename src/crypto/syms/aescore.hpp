#ifndef __SRC_CRYPTO_SYMS_AESCORE_HPP__
#define __SRC_CRYPTO_SYMS_AESCORE_HPP__

#include <certpp/common.hpp>
#include <certpp/io/array.hpp>

namespace certpp {
namespace crypto {

    /**
     * AES's block cipher core (FIPS-197): key expansion plus single-block encrypt/decrypt.
     * Private to `src/`, shared between the `ISymmetric` block cipher
     * (`crypto/syms/aes.cpp`) and the AES-GCM AEAD (`crypto/aeads/aesgcm.cpp`) -- the same
     * arrangement `DesCore` has between DES and TripleDES, and `ChaCha20Core` between the
     * ChaCha20 stream cipher and its AEAD.
     *
     * It was extracted here rather than duplicated because GCM is not a mode the
     * `ISymmetricContext` surface can express: GCM needs the raw forward block function at
     * arbitrary counter blocks *and* at the all-zero block (to derive the GHASH subkey
     * H = E_K(0^128)), and it never uses the inverse cipher at all, not even to decrypt.
     *
     * **This is the raw block function, with no mode, no chaining and no padding.** Encrypting
     * more than one block with it directly is ECB, which leaks plaintext equality block by
     * block; every caller is expected to build a mode around it (`CbcTransformer` does, and
     * `CAesGcm` does).
     *
     * Hardware acceleration (AES-NI) is chosen inside encryptBlock()/decryptBlock() per call,
     * behind a runtime CPUID check and the `CERTPP_DISABLE_HWACCEL_AES` build option, so a
     * caller never has to know which path ran. The portable round functions are exposed
     * separately only so a test can compare the two.
     */
    class AesCore {
    private:
        static const uint8_t SBOX[256];
        static const uint8_t INV_SBOX[256];
        static const uint8_t RCON[11]; // --> index 0 unused; 1..10 covers every Nk this supports.

        static uint8_t xtime(uint8_t a);
        static uint8_t gmul(uint8_t a, uint8_t b);

        static void subBytes(uint8_t s[16]);
        static void invSubBytes(uint8_t s[16]);
        static void shiftRows(uint8_t s[16]);
        static void invShiftRows(uint8_t s[16]);
        static void mixColumns(uint8_t s[16]);
        static void invMixColumns(uint8_t s[16]);
        static void addRoundKey(uint8_t s[16], const uint8_t* roundKey);

    public:
        /** Block size in bytes. */
        static constexpr size_t BLOCK_BYTES = 16;

        /** The largest round-key schedule any supported key size produces: 15 rounds x 16 bytes (AES-256). */
        static constexpr size_t MAX_ROUND_KEY_BYTES = 16 * 15;

    public:
        /**
         * Expands a key into its full round-key schedule (FIPS-197 5.2).
         * @param key The key bytes.
         * @param keyBytes The key length; must be 16, 24 or 32.
         * @param roundKeys Receives the schedule; must have room for at least
         * MAX_ROUND_KEY_BYTES, of which 16 * (nr + 1) are written.
         * @param nr Receives the round count (10, 12 or 14).
         * @return true on success; false if keyBytes isn't a legal AES key length, in which case
         * nothing is written and nr is set to 0.
         */
        static bool expandKey(const uint8_t* key, size_t keyBytes, uint8_t* roundKeys, uint32_t& nr);

        /**
         * Expands a key into a growable array, resized to exactly the schedule's length. See the
         * raw-pointer overload.
         * @param key The key bytes.
         * @param keyBytes The key length; must be 16, 24 or 32.
         * @param roundKeys Receives the schedule, resized to 16 * (nr + 1) bytes.
         * @param nr Receives the round count.
         * @return true on success; false if keyBytes isn't a legal AES key length.
         */
        static bool expandKey(const uint8_t* key, size_t keyBytes, TArray<uint8_t>& roundKeys, uint32_t& nr);

        /**
         * Encrypts one block with the portable round functions, whatever this CPU supports --
         * exposed so a test can hold the two paths against one another.
         * @param in The 16 input bytes.
         * @param out Receives the 16 output bytes; may alias in.
         * @param roundKeys The schedule expandKey() produced.
         * @param nr The round count expandKey() reported.
         */
        static void encryptBlockPortable(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr);

        /**
         * Decrypts one block with the portable round functions. See encryptBlockPortable().
         * @param in The 16 input bytes.
         * @param out Receives the 16 output bytes; may alias in.
         * @param roundKeys The schedule expandKey() produced.
         * @param nr The round count expandKey() reported.
         */
        static void decryptBlockPortable(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr);

        /**
         * Encrypts one block, on AES-NI where the build and the CPU both offer it and the
         * portable round functions otherwise.
         * @param in The 16 input bytes.
         * @param out Receives the 16 output bytes; may alias in.
         * @param roundKeys The schedule expandKey() produced.
         * @param nr The round count expandKey() reported.
         */
        static void encryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr);

        /**
         * Encrypts a run of CBC blocks with the chaining value held in a register.
         *
         * `chain` is read on entry and written back on exit, so the caller's chain state
         * survives exactly as the per-block path leaves it. `blocks` must be a whole number
         * of blocks; partial-block and padding work stays with the caller.
         *
         * --> Exists because the per-block path costs ~84 cycles a block on AES-256 where
         * this costs ~45, which is OpenSSL's own figure. The difference is not arithmetic:
         * `encryptBlock()` loads the block, rounds it and stores it, and CbcTransformer then
         * memcpys the ciphertext back into the chain -- two loads and two stores per block,
         * where the chaining value never needs to leave a register. Measured at 64 KiB.
         *
         * Falls back to a per-block loop when this CPU lacks AES-NI, so the caller need not
         * check for it. Held against an independent implementation by
         * tests/crypto/syms/aes.cpp's "the bulk path matches CBC computed one block at a
         * time", which drives this for all three round counts and compares the ciphertext
         * against AesCore::encryptBlockPortable(). Round-trips alone are not enough for
         * that job: they prove the two directions agree with each other, not that the
         * ciphertext is correct, and two matching errors still round-trip.
         */
        static void encryptCbcBulk(
            const uint8_t* in, uint8_t* out, size_t blocks, uint8_t* chain,
            const uint8_t* roundKeys, uint32_t nr
        );

        /** Whether this CPU has AES-NI; false in a portable build or on a CPU without it. */
        static bool hasAesNi();

        /**
         * Decrypts one block. See encryptBlock().
         * @param in The 16 input bytes.
         * @param out Receives the 16 output bytes; may alias in.
         * @param roundKeys The schedule expandKey() produced.
         * @param nr The round count expandKey() reported.
         */
        static void decryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr);
    };

} // namespace crypto
} // namespace certpp

#endif
