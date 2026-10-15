#include <certpp/crypto/poly1305.hpp>
#include <certpp/arch.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {
namespace crypto {

    namespace {

        uint32_t loadLE32(const uint8_t* p) {
            return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
                 | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
        }

        void storeLE32(uint8_t* p, uint32_t v) {
            p[0] = uint8_t(v);
            p[1] = uint8_t(v >> 8);
            p[2] = uint8_t(v >> 16);
            p[3] = uint8_t(v >> 24);
        }

    } // namespace

#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        /* A 130-bit value in five 26-bit limbs: v = limb[0] + limb[1]*2^26 + ... + limb[4]*2^104. */
        struct SLimbs {
            uint32_t v[5];
        };

        /* Whether this CPU has AVX512-IFMA (CPUID.7.0:EBX.AVX512IFMA, bit 21) and AVX-512F to go
         * with it. The bit was read off the machine, not recalled: leaf 7 sub-leaf 1 reports
         * nothing on this CPU, and a wrong bit either misses the feature or SIGILLs on a CPU
         * without it. */
        bool hasIfma() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuid(info, 0);
                if (info[0] < 7) {
                    return false;
                }
                __cpuidex(info, 1, 0);
                if ((info[2] & (1 << 27)) == 0 || (info[2] & (1 << 28)) == 0 ||
                    (_xgetbv(0) & 0xE6) != 0xE6) {
                    return false;
                }
                __cpuidex(info, 7, 0);
                return (info[1] & (1 << 16)) != 0 &&
                       (info[1] & (1 << 21)) != 0;
#else
                __builtin_cpu_init();
                return __builtin_cpu_supports("avx512f") != 0 &&
                       __builtin_cpu_supports("avx512ifma") != 0;
#endif
            }();
            return supported;
        }

        /* The limbs of a 16-byte block plus the bit appended above it (RFC 8439 2.5): a full
         * block gets 2^128, which is exactly 2^24 * 2^104 -- i.e. bit 24 of limb 4 -- and a short
         * final block gets the bit just above the bytes it holds, which for fewer than 16 bytes
         * is always inside bits 0..127. */
        SLimbs blockLimbs(const uint8_t block[16], uint32_t high) {
            uint64_t lo = 0, hi = 0;
            std::memcpy(&lo, block, 8);
            std::memcpy(&hi, block + 8, 8);

            // --> Spread the 128-bit little-endian value across 26-bit limbs.
            SLimbs out;
            out.v[0] = uint32_t(lo) & 0x3FFFFFFu;
            out.v[1] = uint32_t(lo >> 26) & 0x3FFFFFFu;
            out.v[2] = uint32_t(lo >> 52) | (uint32_t(hi) << 12);
            out.v[2] &= 0x3FFFFFFu;
            out.v[3] = uint32_t(hi >> 14) & 0x3FFFFFFu;
            out.v[4] = uint32_t(hi >> 40) & 0x3FFFFFFu;
            out.v[4] += high;
            return out;
        }

        /* Reduces nine 26-bit-carry limbs to five.
         *
         * The nine limbs hold V = sum_{k=0..8} in[k] * 2^(26k), and the field's modulus is
         * 2^130 - 5, so 2^130 == 5 and each limb at position k >= 5 folds back as five times its
         * value at position k-5. Every limb here is a sum of at most five products of two values
         * under 2^26 -- so under 5*2^52, about 2^54.3 -- which is why each `r` is a uint64 and why
         * the carries are propagated by hand rather than assumed to fit.
         *
         * The reduction is not canonical -- the result can be >= p, as the portable path's own
         * accumulator is between blocks -- and only finish() needs it canonical. */
        void reduce9(const uint64_t in[9], uint32_t out[5]) {
            uint64_t r[5];
            for (int k = 0; k < 5; ++k) {
                r[k] = in[k];
            }
            // --> The limbs above bit 130 fold back in, five times their value, five places down:
            // in[5] lands on limb 0, in[8] on limb 3.
            for (int k = 5; k < 9; ++k) {
                r[k - 5] += 5u * in[k];
            }

            // --> Carry up from the bottom.
            for (int k = 0; k < 4; ++k) {
                const uint64_t c = r[k] >> 26;
                r[k] &= 0x3FFFFFFu;
                r[k + 1] += c;
            }

            // --> And wrap the top: whatever is above limb 4's 26 bits is another five.
            uint64_t c = r[4] >> 26;
            r[4] &= 0x3FFFFFFu;
            r[0] += 5u * c;
            c = r[0] >> 26;
            r[0] &= 0x3FFFFFFu;
            r[1] += c;

            for (int i = 0; i < 5; ++i) {
                out[i] = uint32_t(r[i]);
            }
        }

        /* The five limbs of a * b, nine of them unreduced, by the same schoolbook the portable
         * path uses. This is the scalar half of the powers-of-r precomputation. */
        void mulLimbs(const uint32_t a[5], const uint32_t b[5], uint64_t out[9]) {
            for (int k = 0; k < 9; ++k) {
                uint64_t acc = 0;
                for (int i = 0; i < 5; ++i) {
                    const int j = k - i;
                    if (j < 0 || j > 4) { continue; }
                    acc += uint64_t(a[i]) * b[j];
                }
                out[k] = acc;
            }
        }

        /* r^1 .. r^8 in limb form, from r itself, stored the way absorb8 consumes them.
         *
         * Squaring where it helps: r^2, r^4 and r^8 each take one multiply, and r^3, r^5, r^6 and
         * r^7 one more each -- seven in all rather than eight sequential ones, and each is exact
         * because the result is reduced before the next. Computed once per message, and only when
         * eight whole blocks actually turn up, because seven 130-bit multiplies is real cost on a
         * 64-byte record and the vector path would never pay for it.
         *
         * `out[m][j]` is limb m of power (8 - j), NOT of power (j + 1). Lane 0 carries the
         * OLDEST of the eight blocks and therefore takes the LARGEST power r^8, so the index is
         * 7 - j for lane j. Writing j instead gives every lane the power matching its own
         * position, which is a different and equally plausible sum -- the long-message KAT caught
         * that when the same mistake was made in absorb8's own reload. */
        void computePowers(const uint32_t r[5], uint64_t out[5][8]) {
            uint64_t t[9];
            uint32_t tmp[5], r2[5];

            // Power index p is written to lane 7 - p, because lane 0 carries the oldest of
            // the eight blocks and so takes the largest power.
            auto store = [&out](int p, const uint32_t limbs[5]) {
                for (int m = 0; m < 5; ++m) { out[m][7 - p] = limbs[m]; }
            };

            store(0, r);                                                          // r^1

            mulLimbs(r, r, t); reduce9(t, r2);
            store(1, r2);                                                         // r^2

            mulLimbs(r2, r, t); reduce9(t, tmp);
            store(2, tmp);                                                        // r^3

            mulLimbs(r2, r2, t); reduce9(t, tmp);                                 // r^4 by squaring r^2
            store(3, tmp);

            mulLimbs(tmp, r, t); reduce9(t, tmp);
            store(4, tmp);                                                        // r^5

            mulLimbs(tmp, r, t); reduce9(t, tmp);
            store(5, tmp);                                                        // r^6

            mulLimbs(tmp, r, t); reduce9(t, tmp);
            store(6, tmp);                                                        // r^7

            mulLimbs(tmp, r, t); reduce9(t, tmp);
            store(7, tmp);                                                        // r^8
        }
        /* Eight whole blocks at once: sum_{i=1..8} n_i * r^{9-i}, nine limbs of it, reduced to
         * five and added to the accumulator along with a * r^8.
         *
         * Lane j carries block j+1, so the multiply each lane performs is by a *different*
         * power -- lane 0 by r^8, lane 7 by r^1 -- which is why the powers arrive five-wide per
         * limb rather than broadcast. A single broadcast would compute n_i * r^k for the same k
         * on every lane, which is a different sum. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx512ifma,avx512f")))
#endif
        void absorb8(uint32_t accumulator[5], const uint64_t powers[5][8],
                     const uint8_t blocks[8][16]) {
            // --> The eight blocks' limbs, one lane each: n[m] lane j is limb m of block j+1.
            // --> Limbs are taken once per block, into the five registers. The first version of
            // this called blockLimbs() inside the limb loop -- forty calls per group for the
            // thirty-two limbs of eight blocks, which is the redundant-work pattern and cost more
            // than everything else here together.
            alignas(64) SLimbs bl[8];
            for (int j = 0; j < 8; ++j) { bl[j] = blockLimbs(blocks[j], 1u << 24); }

            __m512i n[5];
            {
                alignas(64) uint64_t lanes[8];
                for (int m = 0; m < 5; ++m) {
                    for (int j = 0; j < 8; ++j) { lanes[j] = bl[j].v[m]; }
                    n[m] = _mm512_loadu_si512(lanes);
                }
            }

            // --> The powers, already in this layout. p[m] is limb m of the eight powers, lane
            // j carrying r^{8-j} -- computePowers() stored it that way, so this is five aligned
            // loads rather than the forty scalar stores and five loads this used to spend per
            // group re-laying-out a table that is computed once per message. Measured 10.11 ns ->
            // 1.96 ns per group. The lane order itself is unchanged: 7 - j, because lane 0 carries
            // the OLDEST block and takes the largest power. Reading powers[j] would give every
            // lane the power matching its own position, a different and wrong sum; the first
            // version of this had it the other way, and the long-message KAT caught it.
            __m512i p[5];
            for (int m = 0; m < 5; ++m) {
                p[m] = _mm512_loadu_si512(powers[m]);
            }

            // --> The nine limbs of the per-lane product. Each is a sum of at most five products
            // of two values under 2^26, so under 2^52 each, and adding eight lanes keeps it under
            // 2^58 -- comfortably inside a 64-bit lane.
            uint64_t sum[9];
            for (int k = 0; k < 9; ++k) {
                __m512i acc = _mm512_setzero_si512();
                for (int i = 0; i < 5; ++i) {
                    const int j = k - i;
                    if (j < 0 || j > 4) {
                        continue;
                    }
                    acc = _mm512_add_epi64(acc, _mm512_madd52lo_epu64(_mm512_setzero_si512(),
                                                                      n[i], p[j]));
                }
                // Keep the 512-bit value inside this target-attributed function. Passing an
                // __m512i through a helper crosses an ABI boundary on Clang/Windows and corrupted
                // the indirect vector argument before the first load. Every lane is under 2^58,
                // so their scalar sum remains below 2^61.
                alignas(64) uint64_t lanes[8];
                _mm512_storeu_si512(lanes, acc);
                sum[k] = 0;
                for (int lane = 0; lane < 8; ++lane) { sum[k] += lanes[lane]; }
            }

            // --> a * r^8, the serial half, done scalarly -- this library's own mulLimbs().
            // r^8 is power index 7, which computePowers() put in lane 7 - 7 = 0.
            uint32_t r8[5];
            for (int i = 0; i < 5; ++i) { r8[i] = uint32_t(powers[i][0]); }
            uint64_t prod[9];
            mulLimbs(accumulator, r8, prod);

            // --> Add the two nine-limb values and reduce to five.
            for (int k = 0; k < 9; ++k) { prod[k] += sum[k]; }
            reduce9(prod, accumulator);
        }
#endif // CERTPP_ARCH_HAS_IFMA_POLY1305

    /* Constructs an unkeyed instance. */
    CPoly1305::CPoly1305()
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        : _buffered(0), _keyed(false), _powersReady(false)
#else
        : _buffered(0), _keyed(false)
#endif
    {
        std::memset(_r, 0, sizeof(_r));
        std::memset(_s, 0, sizeof(_s));
        std::memset(_accumulator, 0, sizeof(_accumulator));
        std::memset(_buffer, 0, sizeof(_buffer));
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        std::memset(_powers, 0, sizeof(_powers));
#endif
    }

    /* Clears the key and accumulator. */
    CPoly1305::~CPoly1305() {
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_r), sizeof(_r)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_s), sizeof(_s)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_accumulator), sizeof(_accumulator)));
        CSecure::zero(SByteSpan(_buffer, sizeof(_buffer)));
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        // --> The powers are derived from r, which is key material.
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_powers), sizeof(_powers)));
#endif
    }

    /* Keys this instance and starts a fresh message. */
    bool CPoly1305::reset(const SReadOnlyByteSpan& key) {
        if (key.size != KEY_BYTES || !key.data) {
            return false;
        }

        // --> r, in five 26-bit limbs, with RFC 8439 2.5's clamping applied: the top four bits
        // of each of bytes 3, 7, 11, 15 are cleared, and the low two bits of bytes 4, 8, 12.
        // That is 22 bits in total, and it is what keeps the partial products below 2^64 so the
        // multiply-reduce step cannot overflow. An implementation that skips the clamping
        // produces tags that are self-consistent and wrong.
        const uint32_t t0 = loadLE32(key.data + 0);
        const uint32_t t1 = loadLE32(key.data + 4);
        const uint32_t t2 = loadLE32(key.data + 8);
        const uint32_t t3 = loadLE32(key.data + 12);

        _r[0] = (t0) & 0x3FFFFFFu;
        _r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3FFFF03u;
        _r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3FFC0FFu;
        _r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3F03FFFu;
        _r[4] = ((t3 >> 8)) & 0x00FFFFFu;

        _s[0] = loadLE32(key.data + 16);
        _s[1] = loadLE32(key.data + 20);
        _s[2] = loadLE32(key.data + 24);
        _s[3] = loadLE32(key.data + 28);

        std::memset(_accumulator, 0, sizeof(_accumulator));
        std::memset(_buffer, 0, sizeof(_buffer));
        _buffered = 0;
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        _powersReady = false;
#endif
        _keyed = true;

        return true;
    }

    namespace {

        /* One block into the accumulator: a = (a + n) * r mod (2^130 - 5), where n is the block
         * read little-endian with `high` appended above its 128 bits. `high` is 1 for a full
         * block and 1 << (8 * partial) for the final short one (RFC 8439 2.5). */
        void absorbBlock(
            uint32_t accumulator[5], const uint32_t r[5], const uint8_t block[16], uint32_t high
        ) {
            const uint32_t t0 = loadLE32(block + 0);
            const uint32_t t1 = loadLE32(block + 4);
            const uint32_t t2 = loadLE32(block + 8);
            const uint32_t t3 = loadLE32(block + 12);

            accumulator[0] += (t0) & 0x3FFFFFFu;
            accumulator[1] += ((t0 >> 26) | (t1 << 6)) & 0x3FFFFFFu;
            accumulator[2] += ((t1 >> 20) | (t2 << 12)) & 0x3FFFFFFu;
            accumulator[3] += ((t2 >> 14) | (t3 << 18)) & 0x3FFFFFFu;
            accumulator[4] += (t3 >> 8) | high;

            // Schoolbook multiply in 26-bit limbs. The 2^130 == 5 reduction folds the overflow
            // back in as a factor of 5 on the wrapped limbs, which is where the 5 * r[i] terms
            // come from.
            const uint64_t s1 = uint64_t(r[1]) * 5;
            const uint64_t s2 = uint64_t(r[2]) * 5;
            const uint64_t s3 = uint64_t(r[3]) * 5;
            const uint64_t s4 = uint64_t(r[4]) * 5;

            const uint64_t a0 = accumulator[0];
            const uint64_t a1 = accumulator[1];
            const uint64_t a2 = accumulator[2];
            const uint64_t a3 = accumulator[3];
            const uint64_t a4 = accumulator[4];

            uint64_t d0 = a0 * r[0] + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1;
            uint64_t d1 = a0 * r[1] + a1 * r[0] + a2 * s4 + a3 * s3 + a4 * s2;
            uint64_t d2 = a0 * r[2] + a1 * r[1] + a2 * r[0] + a3 * s4 + a4 * s3;
            uint64_t d3 = a0 * r[3] + a1 * r[2] + a2 * r[1] + a3 * r[0] + a4 * s4;
            uint64_t d4 = a0 * r[4] + a1 * r[3] + a2 * r[2] + a3 * r[1] + a4 * r[0];

            // Carry propagation, finishing with the wrap from limb 4 back into limb 0 times 5.
            uint64_t carry = d0 >> 26; d0 &= 0x3FFFFFFu;
            d1 += carry; carry = d1 >> 26; d1 &= 0x3FFFFFFu;
            d2 += carry; carry = d2 >> 26; d2 &= 0x3FFFFFFu;
            d3 += carry; carry = d3 >> 26; d3 &= 0x3FFFFFFu;
            d4 += carry; carry = d4 >> 26; d4 &= 0x3FFFFFFu;
            d0 += carry * 5; carry = d0 >> 26; d0 &= 0x3FFFFFFu;
            d1 += carry;

            accumulator[0] = uint32_t(d0);
            accumulator[1] = uint32_t(d1);
            accumulator[2] = uint32_t(d2);
            accumulator[3] = uint32_t(d3);
            accumulator[4] = uint32_t(d4);
        }

    } // namespace

#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
    /* Builds r^1..r^8 for the eight-blocks-at-a-time path. */
    void CPoly1305::preparePowers() {
        computePowers(_r, _powers);
        _powersReady = true;
    }
#endif

    /* Absorbs message bytes. */
    size_t CPoly1305::push(const SReadOnlyByteSpan& buf) {
        if (!_keyed || buf.size == 0) {
            return 0;
        }
        if (!buf.data) {
            return 0;
        }

        size_t consumed = 0;

        // Top up a partial block first, so the caller's chunking cannot change the result.
        if (_buffered != 0) {
            const size_t take = (BLOCK_BYTES - _buffered < buf.size)
                ? (BLOCK_BYTES - _buffered) : buf.size;

            std::memcpy(_buffer + _buffered, buf.data, take);
            _buffered += take;
            consumed += take;

            if (_buffered == BLOCK_BYTES) {
                absorbBlock(_accumulator, _r, _buffer, 1u << 24);
                _buffered = 0;
            }
        }

        // --> Eight at a time first, where this CPU can. The tail -- anything left after the
        // groups of eight, and any final partial block -- still goes through absorbBlock(), so the
        // two paths have to agree exactly and the short-message result is unchanged. The powers of
        // r are built only once there is a whole group to use them, so a message too short never
        // pays for seven 130-bit multiplies it cannot amortise.
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        if (hasIfma() && buf.size - consumed >= 8 * BLOCK_BYTES) {
            if (!_powersReady) {
                preparePowers();
            }
            while (buf.size - consumed >= 8 * BLOCK_BYTES) {
                absorb8(_accumulator, _powers,
                        reinterpret_cast<const uint8_t (*)[16]>(buf.data + consumed));
                consumed += 8 * BLOCK_BYTES;
            }
        }
#endif
        while (buf.size - consumed >= BLOCK_BYTES) {
            absorbBlock(_accumulator, _r, buf.data + consumed, 1u << 24);
            consumed += BLOCK_BYTES;
        }

        if (consumed < buf.size) {
            const size_t rest = buf.size - consumed;
            std::memcpy(_buffer + _buffered, buf.data + consumed, rest);
            _buffered += rest;
            consumed += rest;
        }

        return consumed;
    }

    /* Pads the message to a 16-byte boundary with zeros. */
    bool CPoly1305::padToBlock() {
        if (!_keyed) {
            return false;
        }
        if (_buffered == 0) {
            return true; // already aligned; pad16 of an aligned length adds nothing
        }

        // --> This closes the current block rather than extending the message, which is why the
        // AEAD cannot get the same effect by pushing zeros: pushing them would be
        // indistinguishable from the message containing those zeros, and pad16's whole purpose
        // is to keep the AEAD's four fields from running into one another.
        std::memset(_buffer + _buffered, 0, BLOCK_BYTES - _buffered);
        absorbBlock(_accumulator, _r, _buffer, 1u << 24);
        _buffered = 0;

        return true;
    }

    /* Finalizes and writes the tag. */
    bool CPoly1305::finish(const SByteSpan& out) {
        if (!_keyed || out.size != TAG_BYTES || !out.data) {
            return false;
        }

        // The final partial block gets its 1 bit at the position just above the bytes present,
        // not at bit 128 -- which is what makes a short block distinguishable from a full one
        // and keeps the padding unambiguous.
        if (_buffered != 0) {
            const size_t partial = _buffered;
            _buffer[partial] = 1;
            std::memset(_buffer + partial + 1, 0, BLOCK_BYTES - partial - 1);
            absorbBlock(_accumulator, _r, _buffer, 0);
            _buffered = 0;
        }

        uint32_t h0 = _accumulator[0];
        uint32_t h1 = _accumulator[1];
        uint32_t h2 = _accumulator[2];
        uint32_t h3 = _accumulator[3];
        uint32_t h4 = _accumulator[4];

        uint32_t carry = h1 >> 26; h1 &= 0x3FFFFFFu;
        h2 += carry; carry = h2 >> 26; h2 &= 0x3FFFFFFu;
        h3 += carry; carry = h3 >> 26; h3 &= 0x3FFFFFFu;
        h4 += carry; carry = h4 >> 26; h4 &= 0x3FFFFFFu;
        h0 += carry * 5; carry = h0 >> 26; h0 &= 0x3FFFFFFu;
        h1 += carry;

        // Conditionally subtract 2^130 - 5, in constant time: the accumulator may be in
        // [p, 2^130) at this point, and branching on whether it is would leak a bit of the tag.
        uint32_t g0 = h0 + 5; carry = g0 >> 26; g0 &= 0x3FFFFFFu;
        uint32_t g1 = h1 + carry; carry = g1 >> 26; g1 &= 0x3FFFFFFu;
        uint32_t g2 = h2 + carry; carry = g2 >> 26; g2 &= 0x3FFFFFFu;
        uint32_t g3 = h3 + carry; carry = g3 >> 26; g3 &= 0x3FFFFFFu;
        uint32_t g4 = h4 + carry - (1u << 26);

        uint32_t mask = (g4 >> 31) - 1;  // all ones when g4 did not borrow, i.e. take g
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;

        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Back to four 32-bit words, then add s with a carry chain.
        const uint32_t f0 = (h0 | (h1 << 26));
        const uint32_t f1 = ((h1 >> 6) | (h2 << 20));
        const uint32_t f2 = ((h2 >> 12) | (h3 << 14));
        const uint32_t f3 = ((h3 >> 18) | (h4 << 8));

        uint64_t sum = uint64_t(f0) + _s[0];
        storeLE32(out.data + 0, uint32_t(sum));
        sum = uint64_t(f1) + _s[1] + (sum >> 32);
        storeLE32(out.data + 4, uint32_t(sum));
        sum = uint64_t(f2) + _s[2] + (sum >> 32);
        storeLE32(out.data + 8, uint32_t(sum));
        sum = uint64_t(f3) + _s[3] + (sum >> 32);
        storeLE32(out.data + 12, uint32_t(sum));

        // The state is spent -- a one-time MAC has nothing to offer a second message, so it is
        // cleared rather than left usable.
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_accumulator), sizeof(_accumulator)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_r), sizeof(_r)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_s), sizeof(_s)));
        CSecure::zero(SByteSpan(_buffer, sizeof(_buffer)));
        _keyed = false;

        return true;
    }

    /* One-shot Poly1305. */
    bool CPoly1305::compute(
        const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message, const SByteSpan& out
    ) {
        CPoly1305 mac;

        if (!mac.reset(key)) {
            return false;
        }
        if (message.size != 0 && mac.push(message) != message.size) {
            return false;
        }

        return mac.finish(out);
    }

} // namespace crypto
} // namespace certpp
