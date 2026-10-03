#include <certpp/crypto/siphash.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* The four initialization constants, which are the ASCII of "somepseudorandomlygenerated
         * bytes" in four little-endian 64-bit pieces. */
        constexpr uint64_t IV0 = 0x736f6d6570736575ull;
        constexpr uint64_t IV1 = 0x646f72616e646f6dull;
        constexpr uint64_t IV2 = 0x6c7967656e657261ull;
        constexpr uint64_t IV3 = 0x7465646279746573ull;

        /* Number of SipRounds per message block ("2" in SipHash-2-4). */
        constexpr uint32_t COMPRESSION_ROUNDS = 2;

        /* Number of SipRounds after the last block ("4" in SipHash-2-4). */
        constexpr uint32_t FINALIZATION_ROUNDS = 4;

        uint64_t rotl(uint64_t value, uint32_t count) {
            return (value << count) | (value >> (64 - count));
        }

        uint64_t loadLE64(const uint8_t* p) {
            return uint64_t(p[0]) | (uint64_t(p[1]) << 8)
                 | (uint64_t(p[2]) << 16) | (uint64_t(p[3]) << 24)
                 | (uint64_t(p[4]) << 32) | (uint64_t(p[5]) << 40)
                 | (uint64_t(p[6]) << 48) | (uint64_t(p[7]) << 56);
        }

        void storeLE64(uint8_t* p, uint64_t v) {
            for (size_t i = 0; i < 8; ++i) {
                p[i] = uint8_t(v >> (8 * i));
            }
        }

        /* One SipRound: the ARX permutation of the four state words. The two halves (v0/v1 and
         * v2/v3) each mix internally, then cross over, and v0 and v2 are rotated by 32 to swap
         * their own halves -- which is what carries a change in any one word to all four within
         * two rounds. The rotation amounts are not interchangeable and not symmetric between the
         * halves: 13 and 17 on v1, 16 and 21 on v3. */
        void sipRound(uint64_t v[4]) {
            v[0] += v[1];
            v[1] = rotl(v[1], 13);
            v[1] ^= v[0];
            v[0] = rotl(v[0], 32);

            v[2] += v[3];
            v[3] = rotl(v[3], 16);
            v[3] ^= v[2];

            v[0] += v[3];
            v[3] = rotl(v[3], 21);
            v[3] ^= v[0];

            v[2] += v[1];
            v[1] = rotl(v[1], 17);
            v[1] ^= v[2];
            v[2] = rotl(v[2], 32);
        }

        /* Absorbs one 8-byte block: XOR into v3, c rounds, XOR into v0. */
        void absorbBlock(uint64_t v[4], uint64_t block) {
            v[3] ^= block;
            for (uint32_t i = 0; i < COMPRESSION_ROUNDS; ++i) {
                sipRound(v);
            }
            v[0] ^= block;
        }

    } // namespace

    /* Constructs an unkeyed instance. */
    CSipHash::CSipHash() : _k0(0), _k1(0), _buffered(0), _totalLen(0), _keyed(false) {
        std::memset(_v, 0, sizeof(_v));
        std::memset(_buffer, 0, sizeof(_buffer));
    }

    /* Clears the key and state. */
    CSipHash::~CSipHash() {
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(&_k0), sizeof(_k0)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(&_k1), sizeof(_k1)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_v), sizeof(_v)));
        CSecure::zero(SByteSpan(_buffer, sizeof(_buffer)));
    }

    /* Keys this instance and starts a fresh message. */
    bool CSipHash::reset(const SReadOnlyByteSpan& key) {
        if (key.size != KEY_BYTES || !key.data) {
            return false;
        }

        _k0 = loadLE64(key.data + 0);
        _k1 = loadLE64(key.data + 8);
        _keyed = true;

        return reset();
    }

    /* Starts a fresh message under the key already in place. */
    bool CSipHash::reset() {
        if (!_keyed) {
            return false;
        }

        // --> k0 keys v0 and v2, k1 keys v1 and v3; each key half is used twice, which is why a
        // 128-bit key fills 256 bits of state.
        _v[0] = IV0 ^ _k0;
        _v[1] = IV1 ^ _k1;
        _v[2] = IV2 ^ _k0;
        _v[3] = IV3 ^ _k1;

        std::memset(_buffer, 0, sizeof(_buffer));
        _buffered = 0;
        _totalLen = 0;

        return true;
    }

    /* Absorbs message bytes. */
    size_t CSipHash::push(const SReadOnlyByteSpan& buf) {
        if (!_keyed || buf.size == 0 || !buf.data) {
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
                absorbBlock(_v, loadLE64(_buffer));
                _buffered = 0;
            }
        }

        while (buf.size - consumed >= BLOCK_BYTES) {
            absorbBlock(_v, loadLE64(buf.data + consumed));
            consumed += BLOCK_BYTES;
        }

        if (consumed < buf.size) {
            const size_t rest = buf.size - consumed;
            std::memcpy(_buffer + _buffered, buf.data + consumed, rest);
            _buffered += rest;
            consumed += rest;
        }

        _totalLen += consumed;

        return consumed;
    }

    /* Finalizes the current message and writes the 64-bit output little-endian. */
    bool CSipHash::finish(const SByteSpan& out) {
        if (!_keyed || out.size != TAG_BYTES || !out.data) {
            return false;
        }

        // --> Finalize a copy of the state. SipHash's key survives finish(), and so does the
        // message in progress: calling finish() twice gives the same answer, and pushing more
        // afterwards extends the same message rather than resuming from a wrecked state.
        uint64_t v[4] = { _v[0], _v[1], _v[2], _v[3] };

        // The last block is always present, even for an empty or block-aligned message: it holds
        // whatever bytes remain in the low positions and the message length mod 256 in the top
        // byte. That length byte is the whole of SipHash's padding -- there is no 0x80 marker and
        // no bit count -- so an implementation that merely zero-pads the short block gives one
        // message and its zero-extension the same output (the empty message and a single 0x00
        // byte being the smallest such pair), which is self-consistent and wrong. The modulus is
        // only 256 because the top byte is all the room there is; two messages whose lengths are
        // congruent mod 256 still differ in how many blocks were absorbed before this one.
        uint8_t last[BLOCK_BYTES];
        std::memcpy(last, _buffer, _buffered);
        std::memset(last + _buffered, 0, BLOCK_BYTES - _buffered);

        uint64_t block = loadLE64(last);
        block = (block & 0x00FFFFFFFFFFFFFFull) | (uint64_t(_totalLen & 0xFF) << 56);

        absorbBlock(v, block);

        v[2] ^= 0xFF;
        for (uint32_t i = 0; i < FINALIZATION_ROUNDS; ++i) {
            sipRound(v);
        }

        storeLE64(out.data, v[0] ^ v[1] ^ v[2] ^ v[3]);

        return true;
    }

    /* One-shot SipHash-2-4. */
    bool CSipHash::compute(
        const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message, const SByteSpan& out
    ) {
        CSipHash prf;

        if (!prf.reset(key)) {
            return false;
        }
        if (message.size != 0 && prf.push(message) != message.size) {
            return false;
        }

        return prf.finish(out);
    }

} // namespace crypto
} // namespace certpp
