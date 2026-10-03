#include "chacha20core.hpp"
#include <cstring>

/* Four-block SSE2 path. Unlike CBigNum's ADX/BMI2 and CGf2m's PCLMULQDQ, this needs no runtime
 * CPU check: SSE2 is part of the x86-64 ABI, so every 64-bit x86 processor has it. The gate is
 * therefore the architecture and the build option alone, and there is no feature-detection
 * branch to get wrong. Still honours CERTPP_DISABLE_HWACCEL_SIMD, so the portable path stays
 * reachable for comparison -- which is what the differential test below relies on. */
#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && (defined(_M_X64) || defined(__x86_64__))
#define CERTPP_CHACHA20_SSE2 1
#include <emmintrin.h>
#endif

namespace certpp {
namespace crypto {

    namespace {

        inline uint32_t rotl32(uint32_t x, int n) {
            return (x << n) | (x >> (32 - n));
        }

        /* Unaligned 32-bit access through memcpy: the caller's buffer carries no alignment
         * guarantee, and every compiler folds this to a single load or store. */
        inline uint32_t loadWord(const uint8_t* p) {
            uint32_t v;
            std::memcpy(&v, p, sizeof(v));
            return v;
        }

        inline void storeWord(uint8_t* p, uint32_t v) {
            std::memcpy(p, &v, sizeof(v));
        }

        /* Explicitly little-endian, for the state words and the keystream block, where the byte
         * order is part of the algorithm rather than host-defined. */
        inline uint32_t loadLE32(const uint8_t* p) {
            return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
                 | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
        }

        inline void storeLE32(uint8_t* p, uint32_t v) {
            p[0] = uint8_t(v);
            p[1] = uint8_t(v >> 8);
            p[2] = uint8_t(v >> 16);
            p[3] = uint8_t(v >> 24);
        }

        inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
            a += b; d ^= a; d = rotl32(d, 16);
            c += d; b ^= c; b = rotl32(b, 12);
            a += b; d ^= a; d = rotl32(d, 8);
            c += d; b ^= c; b = rotl32(b, 7);
        }

        /* The twenty rounds, from a prepared state plus a counter, leaving the result in
         * `working` *without* the final feed-forward addition -- one caller wants the sum XORed
         * straight into a buffer and the other wants it stored, so they add it themselves. */
        inline void rounds(
            const ChaCha20Core::SState& state, uint32_t counter, uint32_t working[16]
        ) {
            std::memcpy(working, state.words, sizeof(uint32_t) * 16);
            working[12] = counter;

            for (int i = 0; i < 10; ++i) {
                // Columns, then diagonals -- RFC 8439 2.3's double round.
                quarterRound(working[0], working[4], working[8], working[12]);
                quarterRound(working[1], working[5], working[9], working[13]);
                quarterRound(working[2], working[6], working[10], working[14]);
                quarterRound(working[3], working[7], working[11], working[15]);

                quarterRound(working[0], working[5], working[10], working[15]);
                quarterRound(working[1], working[6], working[11], working[12]);
                quarterRound(working[2], working[7], working[8], working[13]);
                quarterRound(working[3], working[4], working[9], working[14]);
            }
        }


#if defined(CERTPP_CHACHA20_SSE2)

        /* SSE2 has no vector rotate, so it is a shift pair. The 16- and 8-bit cases have faster
         * shuffle forms under SSSE3, which is deliberately not required here. */
        template <int N>
        inline __m128i rotl32x4(__m128i x) {
            return _mm_or_si128(_mm_slli_epi32(x, N), _mm_srli_epi32(x, 32 - N));
        }

        inline void quarterRoundX4(__m128i& a, __m128i& b, __m128i& c, __m128i& d) {
            a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = rotl32x4<16>(d);
            c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = rotl32x4<12>(b);
            a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = rotl32x4<8>(d);
            c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = rotl32x4<7>(b);
        }

        /* Turns four vectors each holding one state word across four blocks into four vectors
         * each holding four consecutive words of one block -- which is the layout the output
         * needs. The whole 4-way scheme is one 4x4 transpose per group of four words. */
        inline void transpose4(__m128i& a, __m128i& b, __m128i& c, __m128i& d) {
            const __m128i t0 = _mm_unpacklo_epi32(a, b);
            const __m128i t1 = _mm_unpackhi_epi32(a, b);
            const __m128i t2 = _mm_unpacklo_epi32(c, d);
            const __m128i t3 = _mm_unpackhi_epi32(c, d);

            a = _mm_unpacklo_epi64(t0, t2);
            b = _mm_unpackhi_epi64(t0, t2);
            c = _mm_unpacklo_epi64(t1, t3);
            d = _mm_unpackhi_epi64(t1, t3);
        }

        /* Four blocks at a time: each of the sixteen state words becomes a vector holding that
         * word for four consecutive counters, so one pass of the rounds produces 256 bytes of
         * keystream. The rounds are the same twenty; what changes is that four independent
         * blocks fill the four lanes, which is where the speedup comes from -- ChaCha20 blocks
         * are independent by construction, so there is nothing to serialize.
         *
         * x86 is little-endian, so a state word stored straight out of a vector is already in
         * the byte order the algorithm specifies; no byte-swapping is needed anywhere here. */
        void xorStream4(
            const ChaCha20Core::SState& state, uint32_t counter,
            const uint8_t* in, uint8_t* out, size_t blocks
        ) {
            __m128i original[16];
            for (size_t i = 0; i < 16; ++i) {
                original[i] = _mm_set1_epi32(int(state.words[i]));
            }

            for (size_t blockIndex = 0; blockIndex < blocks; blockIndex += 4) {
                const uint32_t base = counter + uint32_t(blockIndex);

                __m128i v[16];
                for (size_t i = 0; i < 16; ++i) {
                    v[i] = original[i];
                }
                v[12] = _mm_setr_epi32(int(base), int(base + 1), int(base + 2), int(base + 3));

                const __m128i counters = v[12];

                for (int round = 0; round < 10; ++round) {
                    quarterRoundX4(v[0], v[4], v[8], v[12]);
                    quarterRoundX4(v[1], v[5], v[9], v[13]);
                    quarterRoundX4(v[2], v[6], v[10], v[14]);
                    quarterRoundX4(v[3], v[7], v[11], v[15]);

                    quarterRoundX4(v[0], v[5], v[10], v[15]);
                    quarterRoundX4(v[1], v[6], v[11], v[12]);
                    quarterRoundX4(v[2], v[7], v[8], v[13]);
                    quarterRoundX4(v[3], v[4], v[9], v[14]);
                }

                // Feed-forward: add the original state back, with word 12 taking the per-lane
                // counters rather than the broadcast zero.
                for (size_t i = 0; i < 16; ++i) {
                    v[i] = _mm_add_epi32(v[i], (i == 12) ? counters : original[i]);
                }

                // Transpose each group of four words, then XOR each block into place.
                for (size_t group = 0; group < 4; ++group) {
                    transpose4(v[4 * group], v[4 * group + 1],
                               v[4 * group + 2], v[4 * group + 3]);
                }

                for (size_t block = 0; block < 4; ++block) {
                    for (size_t group = 0; group < 4; ++group) {
                        const size_t offset =
                            (blockIndex + block) * 64 + group * 16;

                        const __m128i keystream = v[4 * group + block];
                        const __m128i input = _mm_loadu_si128(
                            reinterpret_cast<const __m128i*>(in + offset));

                        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset),
                                         _mm_xor_si128(input, keystream));
                    }
                }
            }
        }

#endif
    } // namespace

    /* Prepares a state from a key and nonce. */
    void ChaCha20Core::initState(
        SState& out, const uint8_t key[KEY_BYTES], const uint8_t nonce[NONCE_BYTES]
    ) {
        out.words[0] = 0x61707865u;
        out.words[1] = 0x3320646eu;
        out.words[2] = 0x79622d32u;
        out.words[3] = 0x6b206574u;

        for (size_t i = 0; i < 8; ++i) {
            out.words[4 + i] = loadLE32(key + 4 * i);
        }

        out.words[12] = 0;   // the counter, filled in per block

        for (size_t i = 0; i < 3; ++i) {
            out.words[13 + i] = loadLE32(nonce + 4 * i);
        }
    }

    /* One keystream block from a prepared state. */
    void ChaCha20Core::block(const SState& state, uint32_t counter, uint8_t out[BLOCK_BYTES]) {
        uint32_t working[16];
        rounds(state, counter, working);

        for (size_t i = 0; i < 16; ++i) {
            const uint32_t original = (i == 12) ? counter : state.words[i];
            storeLE32(out + 4 * i, working[i] + original);
        }
    }

    /* XORs the keystream over the input, 32 bits at a time for whole blocks. */
    void ChaCha20Core::xorStream(
        const SState& state, uint32_t initialCounter,
        const uint8_t* in, uint8_t* out, size_t length
    ) {
        uint32_t counter = initialCounter;
        size_t offset = 0;

#if defined(CERTPP_CHACHA20_SSE2)
        // Four-block groups go through SSE2; the remainder falls through to the scalar loop
        // below, which also serves every non-x86-64 target and a build with the option off.
        const size_t wholeBlocks = (length - offset) / BLOCK_BYTES;
        const size_t vectorBlocks = wholeBlocks & ~size_t(3);

        if (vectorBlocks != 0) {
            xorStream4(state, counter, in + offset, out + offset, vectorBlocks);

            offset += vectorBlocks * BLOCK_BYTES;
            counter += uint32_t(vectorBlocks);
        }
#endif

        while (length - offset >= BLOCK_BYTES) {
            uint32_t working[16];
            rounds(state, counter, working);

            // --> Word-wise, which is the whole point of this function. The previous version
            // XORed a byte at a time, so one 64-byte block cost 64 loads, 64 XORs and 64 stores
            // instead of 16 of each -- at 64 KiB, roughly 48 thousand redundant operations.
            for (size_t i = 0; i < 16; ++i) {
                const uint32_t original = (i == 12) ? counter : state.words[i];
                const uint32_t keyWord = working[i] + original;
                storeWord(out + offset + 4 * i, loadWord(in + offset + 4 * i) ^ keyWord);
            }

            offset += BLOCK_BYTES;
            ++counter;
        }

        if (offset < length) {
            // The trailing partial block, byte by byte: there is no whole word left, and reading
            // past the caller's buffer to get one is not an option.
            uint8_t keystream[BLOCK_BYTES];
            block(state, counter, keystream);

            const size_t rest = length - offset;
            for (size_t i = 0; i < rest; ++i) {
                out[offset + i] = uint8_t(in[offset + i] ^ keystream[i]);
            }

            // Keystream bytes are as sensitive as the plaintext they cover.
            std::memset(keystream, 0, sizeof(keystream));
        }
    }

    /* One keystream block, preparing the state for this call alone. */
    void ChaCha20Core::block(
        const uint8_t key[KEY_BYTES], uint32_t counter,
        const uint8_t nonce[NONCE_BYTES], uint8_t out[BLOCK_BYTES]
    ) {
        SState state;
        initState(state, key, nonce);
        block(state, counter, out);
    }

    /* HChaCha20's subkey derivation (draft-irtf-cfrg-xchacha 2.2). */
    void ChaCha20Core::hchacha20(
        const uint8_t key[KEY_BYTES], const uint8_t nonce[HNONCE_BYTES],
        uint8_t out[SUBKEY_BYTES]
    ) {
        // Not initState(): that reserves word 12 for the counter and takes only three nonce
        // words. Here the 128-bit nonce fills words 12 through 15 outright -- there is no
        // counter, because HChaCha20 is called once per nonce rather than once per block.
        SState state;
        state.words[0] = 0x61707865u;
        state.words[1] = 0x3320646eu;
        state.words[2] = 0x79622d32u;
        state.words[3] = 0x6b206574u;

        for (size_t i = 0; i < 8; ++i) {
            state.words[4 + i] = loadLE32(key + 4 * i);
        }
        for (size_t i = 0; i < 4; ++i) {
            state.words[12 + i] = loadLE32(nonce + 4 * i);
        }

        // rounds() writes its third argument's word 12 from the counter it is handed, so the
        // nonce's first word is passed there to keep the state it just built intact.
        uint32_t working[16];
        rounds(state, state.words[12], working);

        // --> No feed-forward. block() adds the original state back here; HChaCha20 does not, and
        // the difference is invisible to any test that only checks a round trip against itself.
        // Then words 0-3 and 12-15 -- the constants' and nonce's positions, not the key's.
        for (size_t i = 0; i < 4; ++i) {
            storeLE32(out + 4 * i, working[i]);
            storeLE32(out + 16 + 4 * i, working[12 + i]);
        }

        std::memset(working, 0, sizeof(working));
        std::memset(&state, 0, sizeof(state));
    }

} // namespace crypto
} // namespace certpp
