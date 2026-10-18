#include "fe448.hpp"

#include <array>
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        constexpr uint64_t MASK = (uint64_t(1) << Fe448::WIDTH) - 1;
        constexpr size_t HALF = Fe448::LIMBS / 2;

#if defined(CERTPP_ARCH_NATIVE_64x64_TO_128)
        using Wide = unsigned __int128;
#else
        using Wide = uint64_t;
#endif

        constexpr uint64_t modulusLimb(size_t index) {
            return index == HALF ? MASK - 1 : MASK;
        }

        void conditionalSubtractP(Fe448& value) {
            uint64_t difference[Fe448::LIMBS];
            int64_t borrow = 0;
            for (size_t i = 0; i < Fe448::LIMBS; ++i) {
                const int64_t limb = int64_t(value.limbs[i])
                    - int64_t(modulusLimb(i)) - borrow;
                difference[i] = uint64_t(limb) & MASK;
                borrow = limb < 0 ? 1 : 0;
            }

            const uint64_t keepOriginal = uint64_t(0) - uint64_t(borrow);
            for (size_t i = 0; i < Fe448::LIMBS; ++i) {
                value.limbs[i] = (value.limbs[i] & keepOriginal)
                    | (difference[i] & ~keepOriginal);
            }
        }

        void reduce(Fe448& out, Wide* t, size_t count) {
            for (size_t k = count; k-- > Fe448::LIMBS; ) {
                const Wide high = t[k];
                t[k] = 0;
                t[k - Fe448::LIMBS] += high;
                t[k - HALF] += high;
            }

            for (int round = 0; round < 4; ++round) {
                for (size_t i = 0; i + 1 < Fe448::LIMBS; ++i) {
                    const Wide carry = t[i] >> Fe448::WIDTH;
                    t[i] &= Wide(MASK);
                    t[i + 1] += carry;
                }
                const Wide carry = t[Fe448::LIMBS - 1] >> Fe448::WIDTH;
                t[Fe448::LIMBS - 1] &= Wide(MASK);
                t[0] += carry;
                t[HALF] += carry;
            }

            for (size_t i = 0; i < Fe448::LIMBS; ++i) {
                out.limbs[i] = uint64_t(t[i]);
            }
            conditionalSubtractP(out);
        }

        std::array<Fe448, 8> powTwoPowerMinusOneBlocks(const Fe448& a) {
            std::array<Fe448, 8> blocks;
            blocks[0] = a; // a^(2^1 - 1)
            size_t length = 1;
            for (size_t i = 1; i < blocks.size(); ++i) {
                Fe448 work = blocks[i - 1];
                for (size_t square = 0; square < length; ++square) {
                    Fe448::square(work, work);
                }
                Fe448::mul(blocks[i], work, blocks[i - 1]);
                length *= 2;
            }
            return blocks;
        }

        Fe448 powTwoNMinusOne(
            size_t n, const std::array<Fe448, 8>& blocks
        ) {
            Fe448 result;
            result.setOne();
            bool started = false;
            for (size_t i = blocks.size(); i-- > 0; ) {
                const size_t length = size_t(1) << i;
                if ((n & length) == 0) {
                    continue;
                }
                if (!started) {
                    result = blocks[i];
                    started = true;
                    continue;
                }
                for (size_t square = 0; square < length; ++square) {
                    Fe448::square(result, result);
                }
                Fe448::mul(result, result, blocks[i]);
            }
            return result;
        }

        void powPMinus2(Fe448& out, const Fe448& a) {
            const auto blocks = powTwoPowerMinusOneBlocks(a);
            Fe448 result = powTwoNMinusOne(223, blocks);
            Fe448::square(result, result); // append exponent bit 224 == 0
            for (size_t i = 0; i < 222; ++i) {
                Fe448::square(result, result);
            }
            Fe448::mul(result, result, powTwoNMinusOne(222, blocks));
            Fe448::square(result, result); // exponent bit 1 == 0
            Fe448::square(result, result);
            Fe448::mul(out, result, a);    // exponent bit 0 == 1
        }

        void powPMinus3Over4(Fe448& out, const Fe448& a) {
            const auto blocks = powTwoPowerMinusOneBlocks(a);
            Fe448 result = powTwoNMinusOne(223, blocks);
            Fe448::square(result, result); // exponent bit 222 == 0
            for (size_t i = 0; i < 222; ++i) {
                Fe448::square(result, result);
            }
            Fe448::mul(out, result, powTwoNMinusOne(222, blocks));
        }

    } // namespace

    void Fe448::setZero() {
        std::memset(limbs, 0, sizeof(limbs));
    }

    void Fe448::setOne() {
        setZero();
        limbs[0] = 1;
    }

    bool Fe448::fromBytes(const uint8_t in[BYTES]) {
        setZero();
        for (size_t byte = 0; byte < BYTES; ++byte) {
            const size_t bit = byte * 8;
            const size_t limb = bit / WIDTH;
            const unsigned shift = unsigned(bit % WIDTH);
            limbs[limb] |= uint64_t(in[byte]) << shift;
            if (shift + 8 > WIDTH) {
                limbs[limb + 1] |= uint64_t(in[byte]) >> (WIDTH - shift);
            }
        }
        for (size_t i = 0; i < LIMBS; ++i) {
            limbs[i] &= MASK;
        }

        int64_t borrow = 0;
        for (size_t i = 0; i < LIMBS; ++i) {
            const int64_t limb = int64_t(limbs[i]) - int64_t(modulusLimb(i)) - borrow;
            borrow = limb < 0 ? 1 : 0;
        }
        return borrow != 0;
    }

    void Fe448::toBytes(uint8_t out[BYTES]) const {
        Fe448 reduced = *this;
        conditionalSubtractP(reduced);
        std::memset(out, 0, BYTES);
        for (size_t byte = 0; byte < BYTES; ++byte) {
            const size_t bit = byte * 8;
            const size_t limb = bit / WIDTH;
            const unsigned shift = unsigned(bit % WIDTH);
            uint64_t value = reduced.limbs[limb] >> shift;
            if (shift + 8 > WIDTH) {
                value |= reduced.limbs[limb + 1] << (WIDTH - shift);
            }
            out[byte] = uint8_t(value);
        }
    }

    void Fe448::add(Fe448& out, const Fe448& a, const Fe448& b) {
        Wide t[LIMBS] = {};
        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] = Wide(a.limbs[i]) + b.limbs[i];
        }
        reduce(out, t, LIMBS);
    }

    void Fe448::sub(Fe448& out, const Fe448& a, const Fe448& b) {
        Wide t[LIMBS] = {};
        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] = Wide(a.limbs[i]) + Wide(2) * modulusLimb(i) - b.limbs[i];
        }
        reduce(out, t, LIMBS);
    }

    void Fe448::mul(Fe448& out, const Fe448& a, const Fe448& b) {
        Wide t[2 * LIMBS - 1] = {};
        for (size_t i = 0; i < LIMBS; ++i) {
            for (size_t j = 0; j < LIMBS; ++j) {
                t[i + j] += Wide(a.limbs[i]) * b.limbs[j];
            }
        }
        reduce(out, t, 2 * LIMBS - 1);
    }

    void Fe448::square(Fe448& out, const Fe448& a) {
        mul(out, a, a);
    }

    void Fe448::mulSmall(Fe448& out, const Fe448& a, uint32_t b) {
        Wide t[LIMBS] = {};
        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] = Wide(a.limbs[i]) * b;
        }
        reduce(out, t, LIMBS);
    }

    void Fe448::neg(Fe448& out, const Fe448& a) {
        Fe448 zero;
        zero.setZero();
        sub(out, zero, a);
    }

    void Fe448::conditionalSwap(bool swap, Fe448& a, Fe448& b) {
        const uint64_t mask = uint64_t(0) - uint64_t(swap);
        for (size_t i = 0; i < LIMBS; ++i) {
            const uint64_t difference = (a.limbs[i] ^ b.limbs[i]) & mask;
            a.limbs[i] ^= difference;
            b.limbs[i] ^= difference;
        }
    }

    void Fe448::invert(Fe448& out, const Fe448& a) {
        powPMinus2(out, a);
    }

    bool Fe448::squareRootRatio(Fe448& out, const Fe448& u, const Fe448& v) {
        if (v.isZero()) {
            out.setZero();
            return false;
        }

        // r = u*v*(u*v^3)^((p-3)/4), valid for p == 3 (mod 4).
        Fe448 v2, v3, uv3, power, uv;
        square(v2, v);
        mul(v3, v2, v);
        mul(uv3, u, v3);
        powPMinus3Over4(power, uv3);
        mul(uv, u, v);
        mul(out, uv, power);

        Fe448 check;
        square(check, out);
        mul(check, check, v);
        return check.isEqual(u);
    }

    bool Fe448::isZero() const {
        uint64_t combined = 0;
        for (size_t i = 0; i < LIMBS; ++i) {
            combined |= limbs[i];
        }
        return combined == 0;
    }

    bool Fe448::isEqual(const Fe448& other) const {
        uint64_t difference = 0;
        for (size_t i = 0; i < LIMBS; ++i) {
            difference |= limbs[i] ^ other.limbs[i];
        }
        return difference == 0;
    }

    bool Fe448::isOdd() const {
        return (limbs[0] & 1) != 0;
    }

} // namespace crypto
} // namespace certpp
