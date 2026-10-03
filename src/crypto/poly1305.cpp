#include <certpp/crypto/poly1305.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

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

    /* Constructs an unkeyed instance. */
    CPoly1305::CPoly1305() : _buffered(0), _keyed(false) {
        std::memset(_r, 0, sizeof(_r));
        std::memset(_s, 0, sizeof(_s));
        std::memset(_accumulator, 0, sizeof(_accumulator));
        std::memset(_buffer, 0, sizeof(_buffer));
    }

    /* Clears the key and accumulator. */
    CPoly1305::~CPoly1305() {
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_r), sizeof(_r)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_s), sizeof(_s)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_accumulator), sizeof(_accumulator)));
        CSecure::zero(SByteSpan(_buffer, sizeof(_buffer)));
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
