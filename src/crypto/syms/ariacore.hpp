#ifndef __SRC_CRYPTO_SYMS_ARIACORE_HPP__
#define __SRC_CRYPTO_SYMS_ARIACORE_HPP__

#include <certpp/common.hpp>
#include <certpp/io/array.hpp>

namespace certpp {
namespace crypto {

    /**
     * ARIA's block cipher core (RFC 5794 / KS X 1213:2004): key expansion plus single-block
     * encrypt/decrypt. Private to `src/`, shared between the `ISymmetric` block cipher
     * (`crypto/syms/aria.cpp`) and any AEAD or mode that needs the raw block function -- the
     * same arrangement `AesCore` has between AES and AES-GCM, and `DesCore` between DES and
     * TripleDES.
     *
     * It was extracted rather than duplicated because a mode is not something the
     * `ISymmetricContext` surface can express on its own: CBC needs the raw block function with
     * chaining and padding applied around it, which is what `CbcTransformer` does.
     *
     * **This is the raw block function, with no mode, no chaining and no padding.** Encrypting
     * more than one block with it directly is ECB, which leaks plaintext equality block by
     * block; every caller is expected to build a mode around it (`CbcTransformer` does).
     *
     * ARIA is a 16-byte block cipher with 128/192/256-bit keys and 12/14/16 rounds
     * respectively. Unlike AES's byte-oriented matrix it works on the block as sixteen
     * independent bytes through two substitution layers (SL1 for odd rounds, SL2 for even
     * rounds) and a diffusion layer, and its key schedule is a three-round Feistel network
     * over the key rather than a linear words-to-round-keys expansion.
     *
     * There is no hardware acceleration path. Unlike AES-NI, which Intel and AMD both
     * implement, ARIA has no equivalent instruction set on any mainstream x86, so the
     * portable round functions *are* the implementation and `CERTPP_DISABLE_HWACCEL_SIMD`
     * does not apply to it. `CERTPP_DISABLE_HWACCEL_ARIA` is accepted and deliberately does
     * nothing, so a build script that disables every cipher uniformly still configures.
     */
    class AriaCore {
    private:
        static const uint8_t SB1[256];
        static const uint8_t SB2[256];
        static const uint8_t SB3[256];
        static const uint8_t SB4[256];

        // 128-bit constants from the first 384 bits of the fractional part of 1/PI.
        static const uint32_t C1[4];
        static const uint32_t C2[4];
        static const uint32_t C3[4];

        /** Checks SB3 == SB1^-1 and SB4 == SB2^-1, and the RFC's own worked examples. */
        static bool selfCheckTables();

        static void substitutionLayer1(uint8_t s[16]);
        static void substitutionLayer2(uint8_t s[16]);
        static void diffusionLayer(uint8_t s[16]);

        /** FO(D, RK) = A(SL1(D ^ RK)) -- the odd round function. */
        static void roundOdd(uint8_t d[16], const uint8_t rk[16]);

        /** FE(D, RK) = A(SL2(D ^ RK)) -- the even round function. */
        static void roundEven(uint8_t d[16], const uint8_t rk[16]);

        /** block = block ^ roundKey, all sixteen bytes. */
        static void xorRoundKey(uint8_t s[16], const uint8_t rk[16]);

        /** W0 = KL, then the three-round key-schedule Feistel producing W1..W3.
         *
         * The whole schedule runs on 16-byte values in the RFC's own byte order -- which is
         * what the round functions consume -- so `w` is an array of byte strings rather than
         * words, and no endianness conversion happens anywhere in the key schedule. The
         * words only exist for the 128-bit rotations that build the round keys, and are
         * formed from these bytes at that point. */
        static void scheduleWords(uint8_t w[4][16], const uint8_t ck[3][16]);

    public:
        /** Block size in bytes. */
        static constexpr size_t BLOCK_BYTES = 16;

        /** The largest round-key schedule any supported key size produces: 17 rounds x 16 bytes (ARIA-256). */
        static constexpr size_t MAX_ROUND_KEY_BYTES = 16 * 17;

        /**
         * Expands a master key into its full encryption round-key schedule (RFC 5794 2.2).
         *
         * The third key-dependent choice -- which of C1/C2/C3 becomes CK1/CK2/CK3 -- is
         * selected by key size: 128-bit uses C1,C2,C3; 192-bit uses C2,C3,C1; 256-bit uses
         * C3,C1,C2. Getting that permutation right is the difference between correct round
         * keys and keys that agree with themselves only.
         *
         * @param key The master key bytes.
         * @param keyBytes The key length; must be 16, 24 or 32.
         * @param roundKeys Receives the schedule; must have room for MAX_ROUND_KEY_BYTES,
         * of which 16 * (nr + 1) are written.
         * @param nr Receives the round count (12, 14 or 16).
         * @return true on success; false if keyBytes isn't a legal ARIA key length or the
         * table self-check failed, in which case nothing is written and nr is set to 0.
         */
        static bool expandKey(const uint8_t* key, size_t keyBytes, uint8_t* roundKeys, uint32_t& nr);

        /**
         * Expands a key into a growable array, resized to exactly the schedule's length. See
         * the raw-pointer overload. Leaves the array untouched and returns false if the key
         * length is not one ARIA supports.
         * @param key The master key bytes.
         * @param keyBytes The key length; must be 16, 24 or 32.
         * @param roundKeys Receives the schedule, resized to 16 * (nr + 1) bytes.
         * @param nr Receives the round count.
         * @return true on success.
         */
        static bool expandKey(const uint8_t* key, size_t keyBytes, TArray<uint8_t>& roundKeys, uint32_t& nr);

        /**
         * Encrypts one block (RFC 5794 2.3.1).
         * @param in The 16 input bytes.
         * @param out Receives the 16 output bytes; may alias in.
         * @param roundKeys The schedule expandKey() produced.
         * @param nr The round count expandKey() reported.
         */
        static void encryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr);

        /**
         * Decrypts one block (RFC 5794 2.3.2). The decryption round keys are derived from the
         * encryption schedule the RFC specifies: dk1 = ek{n+1}, dk{n+1} = ek1, and every key
         * in between passed through the diffusion layer, A being an involution.
         *
         * Deriving decryption keys on every call would be wasteful for bulk work, so a caller
         * processing many blocks should expand once and cache the decryption schedule; this
         * single-block entry point derives what it needs per call.
         *
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