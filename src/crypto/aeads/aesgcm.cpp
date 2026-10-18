#include <certpp/crypto/aeads/aesgcm.hpp>
#include <certpp/utils/secure.hpp>
#include "../syms/aescore.hpp"
#include "ghash.hpp"
#include <cstring>

#if !defined(CERTPP_DISABLE_HWACCEL_AES) && !defined(CERTPP_DISABLE_HWACCEL_SIMD) && \
    (defined(_M_X64) || defined(__x86_64__))
#define CERTPP_GCM_WIDE_AVAILABLE 1
#include <immintrin.h>
#endif

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
#define CERTPP_TARGET_GCM_WIDE \
    __attribute__((target("avx512f,avx512bw,gfni,vpclmulqdq,vaes,sse4.1")))
#define CERTPP_TARGET_GCM_SHORT __attribute__((target("aes,sse4.1")))
#else
#define CERTPP_TARGET_GCM_WIDE
#define CERTPP_TARGET_GCM_SHORT
#endif

namespace certpp {
namespace crypto {

    namespace {

        /* Writes a 64-bit length big-endian, as GCM's length block does -- the opposite endianness
         * of ChaCha20-Poly1305's otherwise analogous footer (RFC 8439 2.8 uses le64), which is
         * precisely why it is written out here rather than assumed. */
        void storeBE64(uint8_t* out, uint64_t value) {
            for (size_t i = 0; i < 8; ++i) {
                out[i] = uint8_t(value >> (8 * (7 - i)));
            }
        }

        /* Increments the counter block's rightmost 32 bits, modulo 2^32, leaving the preceding 96
         * bits alone -- SP 800-38D 6.2's inc32. The wrap is deliberate: it is the reason
         * MAX_PAYLOAD_BYTES exists, since a message long enough to wrap would repeat keystream. */
        void inc32(uint8_t block[16]) {
            for (size_t i = 16; i-- > 12; ) {
                if (++block[i] != 0) {
                    break;
                }
            }
        }

#if defined(CERTPP_GCM_WIDE_AVAILABLE)
        CERTPP_TARGET_GCM_SHORT
        inline __m128i shortCounterBlock(__m128i prefix, uint32_t value) {
            const uint32_t be = ((value & 0x000000ffu) << 24)
                | ((value & 0x0000ff00u) << 8)
                | ((value & 0x00ff0000u) >> 8)
                | ((value & 0xff000000u) >> 24);
            return _mm_insert_epi32(prefix, static_cast<int>(be), 3);
        }

        /* Encrypts J0 and the first four payload counters together. A 64-byte GCM record needs
         * exactly these five independent AES results; running the tag mask as a later
         * single-block dependency chain leaves the AES execution units idle for most rounds. */
        CERTPP_TARGET_GCM_SHORT
        void seal4AndMask(
            const uint8_t* roundKeys, uint32_t rounds, const uint8_t j0[16],
            const uint8_t* in, uint8_t* out, uint8_t mask[16]
        ) {
            const __m128i prefix =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0));
            const uint32_t initial = (uint32_t(j0[12]) << 24)
                | (uint32_t(j0[13]) << 16) | (uint32_t(j0[14]) << 8)
                | uint32_t(j0[15]);

            __m128i states[5] = {
                prefix,
                shortCounterBlock(prefix, initial + 1),
                shortCounterBlock(prefix, initial + 2),
                shortCounterBlock(prefix, initial + 3),
                shortCounterBlock(prefix, initial + 4)
            };
            const __m128i first =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys));
            for (auto& state : states) {
                state = _mm_xor_si128(state, first);
            }
            for (uint32_t round = 1; round < rounds; ++round) {
                const __m128i key = _mm_loadu_si128(
                    reinterpret_cast<const __m128i*>(roundKeys + round * 16));
                for (auto& state : states) {
                    state = _mm_aesenc_si128(state, key);
                }
            }
            const __m128i last = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(roundKeys + rounds * 16));
            for (auto& state : states) {
                state = _mm_aesenclast_si128(state, last);
            }

            _mm_storeu_si128(reinterpret_cast<__m128i*>(mask), states[0]);
            for (size_t lane = 0; lane < 4; ++lane) {
                const __m128i ciphertext = _mm_xor_si128(
                    states[lane + 1],
                    _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + lane * 16)));
                _mm_storeu_si128(
                    reinterpret_cast<__m128i*>(out + lane * 16), ciphertext);
            }
        }

        template<uint32_t Begin, uint32_t End>
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((always_inline))
#endif
        CERTPP_TARGET_GCM_WIDE
        inline void aesRounds4(
            __m512i& c0, __m512i& c1, __m512i& c2, __m512i& c3,
            const uint8_t* roundKeys
        ) {
            for (uint32_t round = Begin; round < End; ++round) {
                const __m512i key = _mm512_broadcast_i32x4(_mm_loadu_si128(
                    reinterpret_cast<const __m128i*>(roundKeys + round * 16)));
                c0 = _mm512_aesenc_epi128(c0, key);
                c1 = _mm512_aesenc_epi128(c1, key);
                c2 = _mm512_aesenc_epi128(c2, key);
                c3 = _mm512_aesenc_epi128(c3, key);
            }
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((always_inline))
#endif
        CERTPP_TARGET_GCM_WIDE
        inline void hashWide16Products(
            const uint8_t ciphertext[256], const uint8_t powers[16][16], __m128i y,
            __m512i& productLo, __m512i& productHi, __m512i& productMid
        ) {
            const __m512i matrix = _mm512_set1_epi64(
                static_cast<long long>(0x8040201008040201ULL));
            const __m512i y0 = _mm512_maskz_mov_epi64(
                0x03, _mm512_castsi128_si512(y));
            productLo = _mm512_setzero_si512();
            productHi = _mm512_setzero_si512();
            productMid = _mm512_setzero_si512();
            for (size_t i = 0; i < 4; ++i) {
                __m512i value = _mm512_loadu_si512(ciphertext + i * 64);
                if (i == 0) {
                    value = _mm512_xor_si512(value, y0);
                }
                value = _mm512_gf2p8affine_epi64_epi8(value, matrix, 0);
                const __m512i power = _mm512_loadu_si512(powers + i * 4);
                const __m512i partLo =
                    _mm512_clmulepi64_epi128(value, power, 0x00);
                const __m512i partHi =
                    _mm512_clmulepi64_epi128(value, power, 0x11);
                const __m512i valueMixed = _mm512_xor_si512(
                    value, _mm512_shuffle_epi32(value, 0x4e));
                const __m512i powerMixed = _mm512_xor_si512(
                    power, _mm512_shuffle_epi32(power, 0x4e));
                __m512i partMid =
                    _mm512_clmulepi64_epi128(valueMixed, powerMixed, 0x00);
                partMid = _mm512_xor_si512(
                    partMid, _mm512_xor_si512(partLo, partHi));
                productLo = _mm512_xor_si512(productLo, partLo);
                productHi = _mm512_xor_si512(productHi, partHi);
                productMid = _mm512_xor_si512(productMid, partMid);
            }
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((always_inline))
#endif
        CERTPP_TARGET_GCM_WIDE
        inline __m128i finishWideHash(
            __m512i productLo, __m512i productHi, __m512i productMid
        ) {
            __m256i lo256 = _mm256_xor_si256(
                _mm512_castsi512_si256(productLo),
                _mm512_extracti64x4_epi64(productLo, 1));
            __m256i hi256 = _mm256_xor_si256(
                _mm512_castsi512_si256(productHi),
                _mm512_extracti64x4_epi64(productHi, 1));
            __m256i mid256 = _mm256_xor_si256(
                _mm512_castsi512_si256(productMid),
                _mm512_extracti64x4_epi64(productMid, 1));
            __m128i lo128 = _mm_xor_si128(
                _mm256_castsi256_si128(lo256), _mm256_extracti128_si256(lo256, 1));
            __m128i hi128 = _mm_xor_si128(
                _mm256_castsi256_si128(hi256), _mm256_extracti128_si256(hi256, 1));
            const __m128i mid128 = _mm_xor_si128(
                _mm256_castsi256_si128(mid256), _mm256_extracti128_si256(mid256, 1));
            lo128 = _mm_xor_si128(lo128, _mm_slli_si128(mid128, 8));
            hi128 = _mm_xor_si128(hi128, _mm_srli_si128(mid128, 8));
            const __m128i poly = _mm_cvtsi64_si128(0x87);
            const __m128i f0 = _mm_clmulepi64_si128(hi128, poly, 0x00);
            const __m128i f1 = _mm_clmulepi64_si128(hi128, poly, 0x01);
            lo128 = _mm_xor_si128(lo128, f0);
            lo128 = _mm_xor_si128(lo128, _mm_slli_si128(f1, 8));
            lo128 = _mm_xor_si128(lo128, _mm_clmulepi64_si128(
                _mm_srli_si128(f1, 8), poly, 0x00));
            const __m128i matrix128 = _mm_set1_epi64x(
                static_cast<long long>(0x8040201008040201ULL));
            return _mm_gf2p8affine_epi64_epi8(lo128, matrix128, 0);
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((always_inline))
#endif
        CERTPP_TARGET_GCM_WIDE
        inline __m128i hashWide16(
            const uint8_t ciphertext[256], const uint8_t powers[16][16], __m128i y
        ) {
            __m512i productLo, productHi, productMid;
            hashWide16Products(
                ciphertext, powers, y, productLo, productHi, productMid);
            return finishWideHash(productLo, productHi, productMid);
        }

        /* Encrypts and authenticates complete groups of thirty-two blocks in one instruction
         * stream. VAES and VPCLMULQDQ use different execution resources, so keeping the next
         * counters, the ciphertext and the GHASH recurrence in one loop lets the processor
         * overlap work that two whole-message passes serialize. */
        CERTPP_TARGET_GCM_WIDE
        size_t sealWideGroups(
            const uint8_t* roundKeys, uint32_t rounds, uint8_t counter[16],
            const uint8_t powers[16][16], uint8_t accumulator[16],
            const uint8_t* in, uint8_t* out, size_t length
        ) {
            const size_t groups = length / 256;
            if (groups == 0) {
                return 0;
            }

            uint32_t counterValue = (uint32_t(counter[12]) << 24)
                | (uint32_t(counter[13]) << 16) | (uint32_t(counter[14]) << 8)
                | uint32_t(counter[15]);
            const __m128i prefix =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(counter));
            const __m512i prefix4 = _mm512_broadcast_i32x4(prefix);
            const __m512i counterOffsets = _mm512_setr_epi32(
                0, 0, 0, 0, 0, 0, 0, 1,
                0, 0, 0, 2, 0, 0, 0, 3);
            const __m512i counterStep = _mm512_maskz_set1_epi32(0x8888, 4);
            const __m512i reverse32 = _mm512_setr_epi32(
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
            const __m512i first = _mm512_broadcast_i32x4(
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys)));
            const __m512i last = _mm512_broadcast_i32x4(_mm_loadu_si128(
                reinterpret_cast<const __m128i*>(roundKeys + rounds * 16)));
            __m128i y = _mm_loadu_si128(reinterpret_cast<const __m128i*>(accumulator));

            for (size_t groupIndex = 0; groupIndex < groups; ++groupIndex) {
                __m512i nativeCounters = _mm512_maskz_add_epi32(
                    0x8888, _mm512_set1_epi32(static_cast<int>(counterValue)),
                    counterOffsets);
                __m512i c0 = _mm512_xor_si512(
                    _mm512_mask_mov_epi32(prefix4, 0x8888,
                        _mm512_shuffle_epi8(nativeCounters, reverse32)), first);
                nativeCounters = _mm512_add_epi32(nativeCounters, counterStep);
                __m512i c1 = _mm512_xor_si512(
                    _mm512_mask_mov_epi32(prefix4, 0x8888,
                        _mm512_shuffle_epi8(nativeCounters, reverse32)), first);
                nativeCounters = _mm512_add_epi32(nativeCounters, counterStep);
                __m512i c2 = _mm512_xor_si512(
                    _mm512_mask_mov_epi32(prefix4, 0x8888,
                        _mm512_shuffle_epi8(nativeCounters, reverse32)), first);
                nativeCounters = _mm512_add_epi32(nativeCounters, counterStep);
                __m512i c3 = _mm512_xor_si512(
                    _mm512_mask_mov_epi32(prefix4, 0x8888,
                        _mm512_shuffle_epi8(nativeCounters, reverse32)), first);

                const uint32_t productRound = rounds / 3;
                const uint32_t finishRound = (rounds * 2) / 3;
                if (rounds == 14) {
                    aesRounds4<1, 4>(c0, c1, c2, c3, roundKeys);
                } else {
                    for (uint32_t round = 1; round < productRound; ++round) {
                        const __m512i key = _mm512_broadcast_i32x4(_mm_loadu_si128(
                            reinterpret_cast<const __m128i*>(roundKeys + round * 16)));
                        c0 = _mm512_aesenc_epi128(c0, key);
                        c1 = _mm512_aesenc_epi128(c1, key);
                        c2 = _mm512_aesenc_epi128(c2, key);
                        c3 = _mm512_aesenc_epi128(c3, key);
                    }
                }

                __m512i productLo, productHi, productMid;
                if (groupIndex != 0) {
                    hashWide16Products(out + (groupIndex - 1) * 256, powers, y,
                        productLo, productHi, productMid);
                }

                if (rounds == 14) {
                    aesRounds4<4, 9>(c0, c1, c2, c3, roundKeys);
                } else {
                    for (uint32_t round = productRound; round < finishRound; ++round) {
                        const __m512i key = _mm512_broadcast_i32x4(_mm_loadu_si128(
                            reinterpret_cast<const __m128i*>(roundKeys + round * 16)));
                        c0 = _mm512_aesenc_epi128(c0, key);
                        c1 = _mm512_aesenc_epi128(c1, key);
                        c2 = _mm512_aesenc_epi128(c2, key);
                        c3 = _mm512_aesenc_epi128(c3, key);
                    }
                }

                // Split the preceding group's GHASH around independent AES rounds. This gives
                // both its carry-less multiplies and its horizontal reduction useful work to
                // overlap with the current group's four VAES dependency chains.
                if (groupIndex != 0) {
                    y = finishWideHash(productLo, productHi, productMid);
                }

                if (rounds == 14) {
                    aesRounds4<9, 14>(c0, c1, c2, c3, roundKeys);
                } else {
                    for (uint32_t round = finishRound; round < rounds; ++round) {
                        const __m512i key = _mm512_broadcast_i32x4(_mm_loadu_si128(
                            reinterpret_cast<const __m128i*>(roundKeys + round * 16)));
                        c0 = _mm512_aesenc_epi128(c0, key);
                        c1 = _mm512_aesenc_epi128(c1, key);
                        c2 = _mm512_aesenc_epi128(c2, key);
                        c3 = _mm512_aesenc_epi128(c3, key);
                    }
                }
                const size_t offset = groupIndex * 256;
                c0 = _mm512_xor_si512(_mm512_aesenclast_epi128(c0, last),
                    _mm512_loadu_si512(in + offset + 0));
                c1 = _mm512_xor_si512(_mm512_aesenclast_epi128(c1, last),
                    _mm512_loadu_si512(in + offset + 64));
                c2 = _mm512_xor_si512(_mm512_aesenclast_epi128(c2, last),
                    _mm512_loadu_si512(in + offset + 128));
                c3 = _mm512_xor_si512(_mm512_aesenclast_epi128(c3, last),
                    _mm512_loadu_si512(in + offset + 192));
                _mm512_storeu_si512(out + offset + 0, c0);
                _mm512_storeu_si512(out + offset + 64, c1);
                _mm512_storeu_si512(out + offset + 128, c2);
                _mm512_storeu_si512(out + offset + 192, c3);

                counterValue += 16;
            }

            y = hashWide16(out + (groups - 1) * 256, powers, y);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(accumulator), y);
            counter[12] = uint8_t(counterValue >> 24);
            counter[13] = uint8_t(counterValue >> 16);
            counter[14] = uint8_t(counterValue >> 8);
            counter[15] = uint8_t(counterValue);
            return groups * 256;
        }
#endif

        /* GCTR (SP 800-38D 6.5): XORs the keystream of successive counter blocks, starting at icb,
         * over `length` bytes. Written so `out` may alias `in` exactly, which is what lets a
         * receiver decrypt in place. */
        void applyCounterStream(
            const uint8_t* roundKeys, uint32_t rounds, const uint8_t icb[16],
            const uint8_t* in, uint8_t* out, size_t length
        ) {
            uint8_t counter[16];
            uint8_t keystream[16];

            std::memcpy(counter, icb, sizeof(counter));

            const size_t fullBlocks = length / 16;
            size_t offset = 0;
            if (fullBlocks >= 4) {
                AesCore::xorCtrBulk(
                    in, out, fullBlocks, counter, roundKeys, rounds);
                offset = fullBlocks * 16;
            }

            while (offset < length) {
                AesCore::encryptBlock(counter, keystream, roundKeys, rounds);

                const size_t remaining = length - offset;
                const size_t take = (remaining < 16) ? remaining : 16;

                // A combine, not a copy: memcpy cannot express it, so this stays a byte loop (as
                // CbcTransformer's chaining XOR does), through raw pointers rather than spans.
                for (size_t i = 0; i < take; ++i) {
                    out[offset + i] = uint8_t(in[offset + i] ^ keystream[i]);
                }

                offset += take;
                inc32(counter);
            }

            CSecure::zero(SByteSpan(counter, sizeof(counter)));
            CSecure::zero(SByteSpan(keystream, sizeof(keystream)));
        }

        /* GHASH over `A || pad(A) || C || pad(C) || [len(A)]_64 || [len(C)]_64` (SP 800-38D 7.1
         * step 5), with both lengths in *bits* and big-endian.
         *
         * The padding closes a partial block rather than extending the message, which is why it
         * goes through padToBlock() rather than pushing zeros -- pushing them would be
         * indistinguishable from the field itself ending in zeros, and keeping the two fields from
         * running into one another is the whole point. */
        void computeHash(
            const uint8_t subkey[16], const SReadOnlyByteSpan& aad,
            const uint8_t preparedPowers[16][16], const uint8_t* ciphertext,
            size_t ciphertextLength, uint8_t out[16]
        ) {
            Ghash hash;
            hash.reset(subkey, preparedPowers);

            hash.push(aad.data, aad.size);
            hash.padToBlock();

            hash.push(ciphertext, ciphertextLength);
            hash.padToBlock();

            uint8_t lengths[16];
            storeBE64(lengths + 0, uint64_t(aad.size) * 8);
            storeBE64(lengths + 8, uint64_t(ciphertextLength) * 8);

            hash.push(lengths, sizeof(lengths));
            hash.finish(out);
        }

    } // namespace

    /* Constructs an unkeyed context. */
    CAesGcm::CAesGcm() : _rounds(0), _keyBytes(0), _ghashPowersReady(false) {
        std::memset(_roundKeys, 0, sizeof(_roundKeys));
        std::memset(_subkey, 0, sizeof(_subkey));
        std::memset(_ghashPowers, 0, sizeof(_ghashPowers));
    }

    /* Clears the key schedule and the GHASH subkey. */
    CAesGcm::~CAesGcm() {
        CSecure::zero(SByteSpan(_roundKeys, sizeof(_roundKeys)));
        CSecure::zero(SByteSpan(_subkey, sizeof(_subkey)));
        CSecure::zero(SByteSpan(
            reinterpret_cast<uint8_t*>(_ghashPowers), sizeof(_ghashPowers)));
    }

    /* Keys this context. */
    bool CAesGcm::reset(const SReadOnlyByteSpan& key) {
        // --> Inside a member, since ROUND_KEY_BYTES is private: the header has to state the
        // buffer's size without naming AesCore (a src/-private type), so this is where the two
        // are held to each other.
        static_assert(
            ROUND_KEY_BYTES == AesCore::MAX_ROUND_KEY_BYTES,
            "CAesGcm's round-key buffer must hold AesCore's largest schedule"
        );

        _rounds = 0;
        _keyBytes = 0;
        _ghashPowersReady = false;
        CSecure::zero(SByteSpan(_roundKeys, sizeof(_roundKeys)));
        CSecure::zero(SByteSpan(_subkey, sizeof(_subkey)));
        CSecure::zero(SByteSpan(
            reinterpret_cast<uint8_t*>(_ghashPowers), sizeof(_ghashPowers)));

        if (!key.data) {
            return false;
        }
        if (key.size != KEY_BYTES_128 && key.size != KEY_BYTES_192 && key.size != KEY_BYTES_256) {
            return false;
        }

        uint32_t rounds = 0;
        if (!AesCore::expandKey(key.data, key.size, _roundKeys, rounds)) {
            return false;
        }

        // H = E_K(0^128). GHASH's key, derived from the block cipher rather than given -- which
        // is why it must be recomputed on every re-key and cleared with the schedule.
        uint8_t zeroBlock[BLOCK_BYTES];
        std::memset(zeroBlock, 0, sizeof(zeroBlock));
        AesCore::encryptBlock(zeroBlock, _subkey, _roundKeys, rounds);

        Ghash preparedHash;
        preparedHash.reset(_subkey);
        uint8_t preparedAccumulator[BLOCK_BYTES];
        _ghashPowersReady = preparedHash.exportWideState(
            preparedAccumulator, _ghashPowers);
        CSecure::zero(SByteSpan(preparedAccumulator, sizeof(preparedAccumulator)));

        _rounds = rounds;
        _keyBytes = key.size;
        return true;
    }

    /* Whether a key is held. */
    bool CAesGcm::keyed() const {
        return _rounds != 0;
    }

    /* The held key's length. */
    size_t CAesGcm::keyBytes() const {
        return _keyBytes;
    }

    /* The GHASH subkey H = E_K(0^128). */
    bool CAesGcm::deriveSubkey(const SByteSpan& out) const {
        if (!keyed() || out.size != BLOCK_BYTES || !out.data) {
            return false;
        }

        std::memcpy(out.data, _subkey, BLOCK_BYTES);
        return true;
    }

    /* Encrypts and authenticates. */
    bool CAesGcm::seal(
        const SReadOnlyByteSpan& iv, const SReadOnlyByteSpan& aad,
        const SReadOnlyByteSpan& in, const SByteSpan& out, const SByteSpan& tag
    ) const {
        if (!keyed() || iv.size != IV_BYTES || !iv.data) {
            return false;
        }
        if (out.size != in.size) {
            return false;
        }
        if (in.size != 0 && (!in.data || !out.data)) {
            return false;
        }
        if (tag.size < MIN_TAG_BYTES || tag.size > TAG_BYTES || !tag.data) {
            return false;
        }
        if (aad.size != 0 && !aad.data) {
            return false;
        }
        if (uint64_t(in.size) > MAX_PAYLOAD_BYTES) {
            return false;
        }

        // J0 = IV || 0^31 || 1, the 96-bit-IV case of SP 800-38D 7.1 step 2. J0 itself is never a
        // payload counter: it produces the tag's mask, and the payload starts at J0 + 1.
        uint8_t j0[BLOCK_BYTES];
        std::memcpy(j0, iv.data, IV_BYTES);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;

        uint8_t counter[BLOCK_BYTES];
        std::memcpy(counter, j0, sizeof(counter));
        inc32(counter);

        uint8_t mask[BLOCK_BYTES];
        bool maskReady = false;
#if defined(CERTPP_GCM_WIDE_AVAILABLE)
        if (in.size == 4 * BLOCK_BYTES && AesCore::hasAesNi()) {
            seal4AndMask(_roundKeys, _rounds, j0, in.data, out.data, mask);
            maskReady = true;
        }
#endif

        uint8_t hash[BLOCK_BYTES];
        if (in.size >= 16 * BLOCK_BYTES) {
            bool fused = false;
#if defined(CERTPP_GCM_WIDE_AVAILABLE)
            if (_ghashPowersReady) {
                Ghash authenticator;
                authenticator.reset(_subkey, _ghashPowers);
                authenticator.push(aad.data, aad.size);
                authenticator.padToBlock();
                uint8_t accumulator[BLOCK_BYTES];
                uint8_t powers16[16][BLOCK_BYTES];
                if (authenticator.exportWideState(accumulator, powers16)) {
                const size_t consumed = sealWideGroups(
                    _roundKeys, _rounds, counter, _ghashPowers, accumulator,
                    in.data, out.data, in.size);
                authenticator.replaceAccumulator(accumulator);
                if (consumed < in.size) {
                    applyCounterStream(
                        _roundKeys, _rounds, counter,
                        in.data + consumed, out.data + consumed, in.size - consumed);
                    authenticator.push(out.data + consumed, in.size - consumed);
                }
                authenticator.padToBlock();
                uint8_t lengths[BLOCK_BYTES];
                storeBE64(lengths + 0, uint64_t(aad.size) * 8);
                storeBE64(lengths + 8, uint64_t(in.size) * 8);
                authenticator.push(lengths, sizeof(lengths));
                authenticator.finish(hash);
                fused = true;
                CSecure::zero(SByteSpan(accumulator, sizeof(accumulator)));
                CSecure::zero(SByteSpan(
                    reinterpret_cast<uint8_t*>(powers16), sizeof(powers16)));
                }
            }
#endif
            if (!fused) {
                applyCounterStream(_roundKeys, _rounds, counter, in.data, out.data, in.size);
                computeHash(_subkey, aad,
                    _ghashPowersReady ? _ghashPowers : nullptr,
                    out.data, out.size, hash);
            }
        } else {
            // Small records avoid a second helper setup and authenticate immediately after CTR.
            Ghash authenticator;
            authenticator.reset(
                _subkey, _ghashPowersReady ? _ghashPowers : nullptr);
            authenticator.push(aad.data, aad.size);
            authenticator.padToBlock();
            if (in.size != 0) {
                if (!maskReady) {
                    applyCounterStream(
                        _roundKeys, _rounds, counter, in.data, out.data, in.size);
                }
                authenticator.push(out.data, out.size);
            }
            authenticator.padToBlock();

            uint8_t lengths[BLOCK_BYTES];
            storeBE64(lengths + 0, uint64_t(aad.size) * 8);
            storeBE64(lengths + 8, uint64_t(in.size) * 8);
            authenticator.push(lengths, sizeof(lengths));
            authenticator.finish(hash);
        }

        if (!maskReady) {
            AesCore::encryptBlock(j0, mask, _roundKeys, _rounds);
        }

        // A short tag is the full one with its tail dropped (SP 800-38D 5.2.1.2's MSB_t), not a
        // differently computed value.
        for (size_t i = 0; i < tag.size; ++i) {
            tag.data[i] = uint8_t(hash[i] ^ mask[i]);
        }

        CSecure::zero(SByteSpan(hash, sizeof(hash)));
        CSecure::zero(SByteSpan(mask, sizeof(mask)));
        CSecure::zero(SByteSpan(counter, sizeof(counter)));

        return true;
    }

    /* Verifies and decrypts. */
    bool CAesGcm::open(
        const SReadOnlyByteSpan& iv, const SReadOnlyByteSpan& aad,
        const SReadOnlyByteSpan& in, const SReadOnlyByteSpan& tag, const SByteSpan& out
    ) const {
        if (!keyed() || iv.size != IV_BYTES || !iv.data) {
            return false;
        }
        if (out.size != in.size) {
            return false;
        }
        if (in.size != 0 && (!in.data || !out.data)) {
            return false;
        }
        if (tag.size < MIN_TAG_BYTES || tag.size > TAG_BYTES || !tag.data) {
            return false;
        }
        if (aad.size != 0 && !aad.data) {
            return false;
        }
        if (uint64_t(in.size) > MAX_PAYLOAD_BYTES) {
            return false;
        }

        uint8_t j0[BLOCK_BYTES];
        std::memcpy(j0, iv.data, IV_BYTES);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;

        uint8_t hash[BLOCK_BYTES];
        computeHash(_subkey, aad,
            _ghashPowersReady ? _ghashPowers : nullptr,
            in.data, in.size, hash);

        uint8_t mask[BLOCK_BYTES];
        AesCore::encryptBlock(j0, mask, _roundKeys, _rounds);

        uint8_t expected[BLOCK_BYTES];
        for (size_t i = 0; i < BLOCK_BYTES; ++i) {
            expected[i] = uint8_t(hash[i] ^ mask[i]);
        }

        CSecure::zero(SByteSpan(hash, sizeof(hash)));
        CSecure::zero(SByteSpan(mask, sizeof(mask)));

        // --> Verify before writing anything. The tag covers the ciphertext, so it can be checked
        // while `in` is still intact -- and because `out` is allowed to alias `in`, a
        // decrypt-then-verify order would overwrite the caller's only copy of the ciphertext with
        // unauthenticated plaintext before discovering the forgery. Through CSecure, not memcmp: a
        // comparison that stops at the first difference reveals how much of a forged tag was
        // right, which is enough to build one byte by byte. Only tag.size bytes are compared, so a
        // truncated tag is checked against the same prefix the sender would have produced.
        const bool authentic = CSecure::equals(
            SReadOnlyByteSpan(expected, tag.size), tag);

        CSecure::zero(SByteSpan(expected, sizeof(expected)));

        if (!authentic) {
            return false;
        }

        if (in.size != 0) {
            uint8_t counter[BLOCK_BYTES];
            std::memcpy(counter, j0, sizeof(counter));
            inc32(counter);

            applyCounterStream(_roundKeys, _rounds, counter, in.data, out.data, in.size);

            CSecure::zero(SByteSpan(counter, sizeof(counter)));
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
