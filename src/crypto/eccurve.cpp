#include <certpp/crypto/eccurve.hpp>
#include "fastprimefield.hpp"
#include <cstring>
#include <utility>

#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && !defined(CERTPP_DISABLE_HWACCEL_AVX512) && \
    defined(__clang__) && (defined(__x86_64__) || defined(_M_X64))
#define CERTPP_P256_COMB_AVX512 1
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {
namespace crypto {

#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
    namespace {

        /* Stack-resident Montgomery field arithmetic for the prime curves. CBigNum remains the
         * public representation and handles conversions at the scalar-multiplication boundary;
         * the several thousand operations inside the point loop stay in fixed-width 64-bit
         * limbs, avoiding heap-backed temporaries and repeated 32/64-bit packing. Nine limbs cover
         * the largest built-in prime field, P-521. */
        class FastPrimeField {
        public:
            static constexpr size_t MAX_LIMBS = 9;

            struct Value {
                uint64_t limbs[MAX_LIMBS] = {};
            };

        private:
            size_t _count = 0;
            uint64_t _modulus[MAX_LIMBS] = {};
            uint64_t _n0inv = 0;
            bool _p256 = false;

            static uint64_t subtractRaw(
                Value& out, const Value& left, const uint64_t* right, size_t count
            ) {
                uint64_t borrow = 0;
                for (size_t i = 0; i < count; ++i) {
                    const uint64_t first = left.limbs[i] - right[i];
                    const uint64_t borrow1 = left.limbs[i] < right[i];
                    const uint64_t second = first - borrow;
                    const uint64_t borrow2 = first < borrow;
                    out.limbs[i] = second;
                    borrow = borrow1 | borrow2;
                }
                return borrow;
            }

#if defined(__GNUC__) || defined(__clang__)
            __attribute__((always_inline))
#endif
            Value mulP256(const Value& left, const Value& right) const {
                using Wide = unsigned __int128;
                uint64_t t[6] = {};

                // Keep the four-limb trip counts visible to the optimizer. The generic field
                // accepts every built-in prime up to P-521, so its runtime count prevents the
                // compiler from fully unrolling P-256's hottest multiply-accumulate loop.
                for (size_t i = 0; i < 4; ++i) {
                    Wide carry = 0;
                    for (size_t j = 0; j < 4; ++j) {
                        const Wide product = Wide(t[j])
                            + Wide(left.limbs[j]) * right.limbs[i] + carry;
                        t[j] = uint64_t(product);
                        carry = product >> 64;
                    }
                    Wide top = Wide(t[4]) + carry;
                    t[4] = uint64_t(top);
                    t[5] = uint64_t(top >> 64);

                    // P-256 has p[0] == -1 and n0inv == 1. Its other non-zero limbs are
                    // 2^32-1 and 2^64-2^32+1, so shifts and additions replace four products.
                    const uint64_t multiplier = t[0];
                    Wide value = Wide(t[1]) + (Wide(multiplier) << 32);
                    t[0] = uint64_t(value);
                    carry = value >> 64;

                    value = Wide(t[2]) + carry;
                    t[1] = uint64_t(value);
                    carry = value >> 64;

                    const Wide sparseProduct = (Wide(multiplier) << 64)
                        - (Wide(multiplier) << 32) + multiplier;
                    value = Wide(t[3]) + sparseProduct + carry;
                    t[2] = uint64_t(value);
                    carry = value >> 64;

                    top = Wide(t[4]) + carry;
                    t[3] = uint64_t(top);
                    t[4] = t[5] + uint64_t(top >> 64);
                }

                Value candidate;
                for (size_t i = 0; i < 4; ++i) {
                    candidate.limbs[i] = t[i];
                }
                Value reduced;
                const uint64_t borrow = subtractRaw(reduced, candidate, _modulus, 4);
                const uint64_t useReduced = uint64_t(t[4] != 0) | (borrow ^ uint64_t(1));
                const uint64_t mask = uint64_t(0) - useReduced;
                for (size_t i = 0; i < 4; ++i) {
                    candidate.limbs[i] ^=
                        (candidate.limbs[i] ^ reduced.limbs[i]) & mask;
                }
                return candidate;
            }

            template<size_t COUNT>
            Value mulFixed(const Value& left, const Value& right) const {
                using Wide = unsigned __int128;
                uint64_t t[COUNT + 2] = {};

                for (size_t i = 0; i < COUNT; ++i) {
                    Wide carry = 0;
                    for (size_t j = 0; j < COUNT; ++j) {
                        const Wide value = Wide(t[j])
                            + Wide(left.limbs[j]) * right.limbs[i] + carry;
                        t[j] = uint64_t(value);
                        carry = value >> 64;
                    }
                    Wide top = Wide(t[COUNT]) + carry;
                    t[COUNT] = uint64_t(top);
                    t[COUNT + 1] = uint64_t(top >> 64);

                    const uint64_t multiplier = t[0] * _n0inv;
                    carry = 0;
                    for (size_t j = 0; j < COUNT; ++j) {
                        const Wide value = Wide(t[j])
                            + Wide(multiplier) * _modulus[j] + carry;
                        if (j != 0) {
                            t[j - 1] = uint64_t(value);
                        }
                        carry = value >> 64;
                    }
                    top = Wide(t[COUNT]) + carry;
                    t[COUNT - 1] = uint64_t(top);
                    t[COUNT] = t[COUNT + 1] + uint64_t(top >> 64);
                }

                Value candidate;
                for (size_t i = 0; i < COUNT; ++i) {
                    candidate.limbs[i] = t[i];
                }
                Value reduced;
                const uint64_t borrow = subtractRaw(reduced, candidate, _modulus, COUNT);
                const uint64_t useReduced = uint64_t(t[COUNT] != 0) | (borrow ^ uint64_t(1));
                const uint64_t mask = uint64_t(0) - useReduced;
                for (size_t i = 0; i < COUNT; ++i) {
                    candidate.limbs[i] ^=
                        (candidate.limbs[i] ^ reduced.limbs[i]) & mask;
                }
                return candidate;
            }

        public:
            explicit FastPrimeField(const CBigNum& modulus) {
                const size_t count = (modulus.bitLength() + 63) / 64;
                if (count == 0 || count > MAX_LIMBS || modulus.isEven()) {
                    return;
                }

                Value packed;
                if (!load(modulus, packed, count)) {
                    return;
                }
                _count = count;
                std::memcpy(_modulus, packed.limbs, count * sizeof(uint64_t));

                uint64_t inverse = _modulus[0];
                for (size_t i = 0; i < 6; ++i) {
                    inverse *= uint64_t(2) - _modulus[0] * inverse;
                }
                _n0inv = uint64_t(0) - inverse;
                _p256 = _count == 4
                    && _modulus[0] == UINT64_C(0xffffffffffffffff)
                    && _modulus[1] == UINT64_C(0x00000000ffffffff)
                    && _modulus[2] == UINT64_C(0x0000000000000000)
                    && _modulus[3] == UINT64_C(0xffffffff00000001);
            }

            bool valid() const {
                return _count != 0;
            }

            size_t count() const {
                return _count;
            }

            static bool load(const CBigNum& value, Value& out, size_t count) {
                uint8_t bytes[MAX_LIMBS * sizeof(uint64_t)] = {};
                if (!value.toLittleEndian(SByteSpan(bytes, count * sizeof(uint64_t)))) {
                    return false;
                }
                for (size_t i = 0; i < count; ++i) {
                    uint64_t limb = 0;
                    for (size_t j = 0; j < sizeof(uint64_t); ++j) {
                        limb |= uint64_t(bytes[i * sizeof(uint64_t) + j]) << (8 * j);
                    }
                    out.limbs[i] = limb;
                }
                return true;
            }

            bool load(const CBigNum& value, Value& out) const {
                return load(value, out, _count);
            }

            CBigNum store(const Value& value) const {
                uint8_t bytes[MAX_LIMBS * sizeof(uint64_t)] = {};
                for (size_t i = 0; i < _count; ++i) {
                    uint64_t limb = value.limbs[i];
                    for (size_t j = 0; j < sizeof(uint64_t); ++j) {
                        bytes[i * sizeof(uint64_t) + j] = uint8_t(limb >> (8 * j));
                    }
                }
                return CBigNum::fromLittleEndian(
                    SReadOnlyByteSpan(bytes, _count * sizeof(uint64_t)));
            }

            Value add(const Value& left, const Value& right) const {
                Value sum;
                unsigned __int128 carry = 0;
                for (size_t i = 0; i < _count; ++i) {
                    const unsigned __int128 value =
                        static_cast<unsigned __int128>(left.limbs[i]) + right.limbs[i] + carry;
                    sum.limbs[i] = uint64_t(value);
                    carry = value >> 64;
                }

                Value reduced;
                const uint64_t borrow = subtractRaw(reduced, sum, _modulus, _count);
                const uint64_t useReduced = uint64_t(carry) | (borrow ^ uint64_t(1));
                const uint64_t mask = uint64_t(0) - useReduced;
                for (size_t i = 0; i < _count; ++i) {
                    sum.limbs[i] ^= (sum.limbs[i] ^ reduced.limbs[i]) & mask;
                }
                return sum;
            }

            Value sub(const Value& left, const Value& right) const {
                Value difference;
                const uint64_t borrow = subtractRaw(difference, left, right.limbs, _count);
                const uint64_t mask = uint64_t(0) - borrow;
                unsigned __int128 carry = 0;
                for (size_t i = 0; i < _count; ++i) {
                    const unsigned __int128 value = static_cast<unsigned __int128>(
                        difference.limbs[i]) + (_modulus[i] & mask) + carry;
                    difference.limbs[i] = uint64_t(value);
                    carry = value >> 64;
                }
                return difference;
            }

            Value dbl(const Value& value) const {
                return add(value, value);
            }

#if defined(__GNUC__) || defined(__clang__)
            __attribute__((always_inline))
#endif
            Value mul(const Value& left, const Value& right) const {
                // Point formulas call this thousands of times. Keeping the field selector and
                // P-256's sparse four-limb body in the caller removes that boundary and lets the
                // optimizer retain adjacent coordinates and carries in registers.
                if (_p256) {
                    return mulP256(left, right);
                }
                switch (_count) {
                    case 1: return mulFixed<1>(left, right);
                    case 2: return mulFixed<2>(left, right);
                    case 3: return mulFixed<3>(left, right);
                    case 4: return mulFixed<4>(left, right);
                    case 5: return mulFixed<5>(left, right);
                    case 6: return mulFixed<6>(left, right);
                    case 7: return mulFixed<7>(left, right);
                    case 8: return mulFixed<8>(left, right);
                    case 9: return mulFixed<9>(left, right);
                    default: return Value();
                }
            }

            Value inverse(const Value& value, const Value& one) const {
                Value exponent;
                std::memcpy(exponent.limbs, _modulus, _count * sizeof(uint64_t));
                uint64_t borrow = 2;
                for (size_t i = 0; i < _count; ++i) {
                    const uint64_t before = exponent.limbs[i];
                    exponent.limbs[i] -= borrow;
                    borrow = before < borrow;
                }

                // p-2 is public and fixed for the field. A four-bit table halves the multiply
                // count of binary Fermat inversion without introducing any secret-dependent
                // lookup: the selected nibble depends only on the public modulus.
                Value powers[16];
                powers[0] = one;
                powers[1] = value;
                for (size_t i = 2; i < 16; ++i) {
                    powers[i] = mul(powers[i - 1], value);
                }

                Value result = one;
                const size_t windows = _count * 16;
                for (size_t window = windows; window-- > 0; ) {
                    result = mul(result, result);
                    result = mul(result, result);
                    result = mul(result, result);
                    result = mul(result, result);
                    const size_t bit = window * 4;
                    const unsigned digit = unsigned(
                        (exponent.limbs[bit / 64] >> (bit % 64)) & uint64_t(0xf));
                    if (digit != 0) {
                        result = mul(result, powers[digit]);
                    }
                }
                return result;
            }

            uint64_t isZero(const Value& value) const {
                uint64_t combined = 0;
                for (size_t i = 0; i < _count; ++i) {
                    combined |= value.limbs[i];
                }
                return ((combined | (uint64_t(0) - combined)) >> 63) ^ uint64_t(1);
            }

            uint64_t equal(const Value& left, const Value& right) const {
                uint64_t difference = 0;
                for (size_t i = 0; i < _count; ++i) {
                    difference |= left.limbs[i] ^ right.limbs[i];
                }
                return ((difference | (uint64_t(0) - difference)) >> 63) ^ uint64_t(1);
            }

            void conditionalSwap(uint64_t swap, Value& left, Value& right) const {
                const uint64_t mask = uint64_t(0) - swap;
                for (size_t i = 0; i < _count; ++i) {
                    const uint64_t difference = (left.limbs[i] ^ right.limbs[i]) & mask;
                    left.limbs[i] ^= difference;
                    right.limbs[i] ^= difference;
                }
            }

            void conditionalAssign(uint64_t assign, Value& destination, const Value& source) const {
                const uint64_t mask = uint64_t(0) - assign;
                for (size_t i = 0; i < _count; ++i) {
                    destination.limbs[i] ^=
                        (destination.limbs[i] ^ source.limbs[i]) & mask;
                }
            }
        };

        struct FastEcPoint {
            FastPrimeField::Value x;
            FastPrimeField::Value y;
            FastPrimeField::Value z;
        };

        struct FastP256CombTable {
            static constexpr size_t WINDOW_BITS = 8;
            static constexpr size_t SCALAR_ROWS = 256 / WINDOW_BITS;
            static constexpr size_t ROWS = SCALAR_ROWS + 1;
            static constexpr size_t ENTRIES = (size_t(1) << (WINDOW_BITS - 1)) + 1;
            struct AffinePoint {
                uint64_t x[4] = {};
                uint64_t y[4] = {};
            };
            AffinePoint points[ROWS][ENTRIES];
            bool valid = false;
        };

#if defined(CERTPP_P256_COMB_AVX512)
        bool hasP256CombAvx512() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuid(info, 0);
                if (info[0] < 7) {
                    return false;
                }
                __cpuidex(info, 1, 0);
                if ((info[2] & (1 << 27)) == 0 || (info[2] & (1 << 28)) == 0
                    || (_xgetbv(0) & 0xe6) != 0xe6) {
                    return false;
                }
                __cpuidex(info, 7, 0);
                return (info[1] & (1 << 16)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)
                    || (ecx & (1u << 27)) == 0 || (ecx & (1u << 28)) == 0) {
                    return false;
                }
                uint32_t xcr0Low, xcr0High;
                __asm__ volatile("xgetbv" : "=a"(xcr0Low), "=d"(xcr0High) : "c"(0));
                (void)xcr0High;
                if ((xcr0Low & 0xe6) != 0xe6
                    || !__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ebx & (1u << 16)) != 0;
#endif
            }();
            return supported;
        }

        __attribute__((target("avx512f")))
        void selectP256CombAvx512(
            const FastP256CombTable::AffinePoint* row, size_t digit,
            FastP256CombTable::AffinePoint& out
        ) {
            __m512i selected = _mm512_loadu_si512(
                reinterpret_cast<const void*>(&row[0]));
            for (size_t i = 1; i < FastP256CombTable::ENTRIES; ++i) {
                const uint64_t difference = uint64_t(i ^ digit);
                const uint64_t nonZero = (difference | (uint64_t(0) - difference)) >> 63;
                const __mmask8 mask = __mmask8(uint8_t(nonZero - 1));
                const __m512i candidate = _mm512_loadu_si512(
                    reinterpret_cast<const void*>(&row[i]));
                selected = _mm512_mask_mov_epi64(selected, mask, candidate);
            }
            _mm512_storeu_si512(reinterpret_cast<void*>(&out), selected);
        }
#endif

        FastEcPoint fastInfinity(
            const FastPrimeField& field, const FastPrimeField::Value& one
        ) {
            FastEcPoint result;
            result.x = one;
            result.y = one;
            return result;
        }

        void fastConditionalSwap(
            const FastPrimeField& field, uint64_t swap, FastEcPoint& left, FastEcPoint& right
        ) {
            field.conditionalSwap(swap, left.x, right.x);
            field.conditionalSwap(swap, left.y, right.y);
            field.conditionalSwap(swap, left.z, right.z);
        }

        void fastConditionalAssign(
            const FastPrimeField& field, uint64_t assign,
            FastEcPoint& destination, const FastEcPoint& source
        ) {
            field.conditionalAssign(assign, destination.x, source.x);
            field.conditionalAssign(assign, destination.y, source.y);
            field.conditionalAssign(assign, destination.z, source.z);
        }

        FastEcPoint fastNegate(
            const FastEcPoint& point, const FastPrimeField& field
        ) {
            FastEcPoint result = point;
            result.y = field.sub(FastPrimeField::Value(), result.y);
            return result;
        }

        TArray<int8_t> computeWnaf(const CBigNum& scalar, unsigned width) {
            const unsigned window = unsigned(1) << width;
            const unsigned halfWindow = window >> 1;
            CBigNum remaining(scalar);
            TArray<int8_t> digits;
            if (!digits.resize(scalar.bitLength() + 1)) {
                return digits;
            }
            for (size_t i = 0; i < digits.size(); ++i) {
                digits[i] = 0;
            }

            size_t position = 0;
            while (!remaining.isZero()) {
                if (!remaining.isEven()) {
                    unsigned low = 0;
                    for (unsigned bit = 0; bit < width; ++bit) {
                        low |= unsigned(remaining.testBit(bit)) << bit;
                    }
                    int digit = int(low);
                    if (low >= halfWindow) {
                        digit -= int(window);
                        remaining.add(CBigNum(uint64_t(-digit)));
                    } else {
                        remaining.sub(CBigNum(uint64_t(digit)));
                    }
                    digits[position] = int8_t(digit);
                }
                remaining.shr(1);
                ++position;
            }
            return digits;
        }

        FastEcPoint fastDouble(
            const FastEcPoint& point, const FastPrimeField& field,
            const FastPrimeField::Value& aMont, const FastPrimeField::Value& one,
            bool aMinusThree
        ) {
            if (field.isZero(point.z) || field.isZero(point.y)) {
                return fastInfinity(field, one);
            }

            if (aMinusThree) {
                // dbl-2001-b for short-Weierstrass curves with a == -3.
                const auto delta = field.mul(point.z, point.z);
                const auto gamma = field.mul(point.y, point.y);
                const auto beta = field.mul(point.x, gamma);
                auto alpha = field.mul(
                    field.sub(point.x, delta), field.add(point.x, delta));
                alpha = field.add(field.add(alpha, alpha), alpha);
                const auto x3 = field.sub(field.mul(alpha, alpha),
                    field.dbl(field.dbl(field.dbl(beta))));
                auto z3 = field.mul(field.add(point.y, point.z),
                    field.add(point.y, point.z));
                z3 = field.sub(field.sub(z3, gamma), delta);
                const auto fourBeta = field.dbl(field.dbl(beta));
                auto y3 = field.mul(alpha, field.sub(fourBeta, x3));
                auto eightGammaSquared = field.mul(gamma, gamma);
                eightGammaSquared = field.dbl(field.dbl(field.dbl(eightGammaSquared)));
                y3 = field.sub(y3, eightGammaSquared);
                return FastEcPoint{ x3, y3, z3 };
            }

            const auto aa = field.mul(point.x, point.x);
            const auto b = field.mul(point.y, point.y);
            const auto c = field.mul(b, b);
            const auto xPlusB = field.add(point.x, b);
            auto d = field.sub(field.sub(field.mul(xPlusB, xPlusB), aa), c);
            d = field.dbl(d);

            auto z4 = field.mul(point.z, point.z);
            z4 = field.mul(z4, z4);
            auto e = field.add(field.add(aa, aa), aa);
            e = field.add(e, field.mul(aMont, z4));

            const auto f = field.mul(e, e);
            const auto x3 = field.sub(f, field.dbl(d));
            auto y3 = field.mul(e, field.sub(d, x3));
            auto eightC = field.dbl(c);
            eightC = field.dbl(eightC);
            eightC = field.dbl(eightC);
            y3 = field.sub(y3, eightC);
            auto z3 = field.mul(point.y, point.z);
            z3 = field.dbl(z3);
            return FastEcPoint{ x3, y3, z3 };
        }

        FastEcPoint fastAdd(
            const FastEcPoint& left, const FastEcPoint& right,
            const FastPrimeField& field, const FastPrimeField::Value& aMont,
            const FastPrimeField::Value& one, bool aMinusThree
        ) {
            if (field.isZero(left.z)) {
                return right;
            }
            if (field.isZero(right.z)) {
                return left;
            }

            const auto z1z1 = field.mul(left.z, left.z);
            const auto z2z2 = field.mul(right.z, right.z);
            auto u1 = field.mul(left.x, z2z2);
            const auto u2 = field.mul(right.x, z1z1);
            const auto z2z2z2 = field.mul(z2z2, right.z);
            const auto z1z1z1 = field.mul(z1z1, left.z);
            auto s1 = field.mul(left.y, z2z2z2);
            auto s2 = field.mul(right.y, z1z1z1);
            const auto h = field.sub(u2, u1);
            auto r = field.sub(s2, s1);

            if (field.isZero(h)) {
                if (field.isZero(r)) {
                    return fastDouble(left, field, aMont, one, aMinusThree);
                }
                return fastInfinity(field, one);
            }

            auto i = field.dbl(h);
            i = field.mul(i, i);
            const auto j = field.mul(h, i);
            r = field.dbl(r);
            u1 = field.mul(u1, i);
            auto x3 = field.sub(field.sub(field.mul(r, r), j), field.dbl(u1));
            auto y3 = field.mul(r, field.sub(u1, x3));
            s1 = field.dbl(field.mul(s1, j));
            y3 = field.sub(y3, s1);
            auto z3 = field.add(left.z, right.z);
            z3 = field.sub(field.sub(field.mul(z3, z3), z1z1), z2z2);
            z3 = field.mul(z3, h);
            return FastEcPoint{ x3, y3, z3 };
        }

        FastEcPoint fastAddMixed(
            const FastEcPoint& left, const FastEcPoint& affineRight,
            const FastPrimeField& field, const FastPrimeField::Value& aMont,
            const FastPrimeField::Value& one, bool aMinusThree
        ) {
            if (field.isZero(left.z)) {
                return affineRight;
            }

            // add-2007-bl with Z2 == 1. The fixed-base table is batch-normalized once, so every
            // hot-loop addition avoids the second point's Z products from the general formula.
            const auto z1z1 = field.mul(left.z, left.z);
            const auto u2 = field.mul(affineRight.x, z1z1);
            const auto s2 = field.mul(affineRight.y, field.mul(left.z, z1z1));
            const auto h = field.sub(u2, left.x);
            auto r = field.sub(s2, left.y);

            if (field.isZero(h)) {
                if (field.isZero(r)) {
                    // A fixed-base comb never intentionally adds a point to itself, but retain a
                    // correct exceptional result if an unusual scalar reaches that state.
                    return fastDouble(left, field, aMont, one, aMinusThree);
                }
                return fastInfinity(field, one);
            }

            auto hh = field.mul(h, h);
            auto i = field.dbl(field.dbl(hh));
            const auto j = field.mul(h, i);
            r = field.dbl(r);
            const auto v = field.mul(left.x, i);
            auto x3 = field.sub(field.sub(field.mul(r, r), j), field.dbl(v));
            auto y3 = field.mul(r, field.sub(v, x3));
            y3 = field.sub(y3, field.dbl(field.mul(left.y, j)));
            auto z3 = field.add(left.z, h);
            z3 = field.sub(field.sub(field.mul(z3, z3), z1z1), hh);
            return FastEcPoint{ x3, y3, z3 };
        }

        void fastBatchNormalize(
            FastEcPoint* points, size_t count,
            const FastPrimeField& field, const FastPrimeField::Value& one,
            FastPrimeField::Value* prefixes
        ) {
            FastPrimeField::Value product = one;
            for (size_t i = 0; i < count; ++i) {
                prefixes[i] = product;
                if (!field.isZero(points[i].z)) {
                    product = field.mul(product, points[i].z);
                }
            }

            FastPrimeField::Value inverse = field.inverse(product, one);
            for (size_t i = count; i-- > 0; ) {
                if (field.isZero(points[i].z)) {
                    continue;
                }
                const auto originalZ = points[i].z;
                const auto zInverse = field.mul(inverse, prefixes[i]);
                inverse = field.mul(inverse, originalZ);
                const auto zInverse2 = field.mul(zInverse, zInverse);
                points[i].x = field.mul(points[i].x, zInverse2);
                points[i].y = field.mul(points[i].y, field.mul(zInverse2, zInverse));
                points[i].z = one;
            }
        }

        FastEcPoint fastWindowMultiply(
            const FastEcPoint& basePoint, const CBigNum& scalar, size_t iterations,
            const FastPrimeField& field, const FastPrimeField::Value& aMont,
            const FastPrimeField::Value& one, bool aMinusThree
        ) {
            constexpr size_t WINDOW_BITS = 4;
            constexpr size_t TABLE_SIZE = size_t(1) << WINDOW_BITS;
            FastEcPoint table[TABLE_SIZE];
            table[0] = fastInfinity(field, one);
            table[1] = basePoint;
            for (size_t i = 2; i < TABLE_SIZE; ++i) {
                table[i] = fastAdd(
                    table[i - 1], basePoint, field, aMont, one, aMinusThree);
            }

            FastEcPoint accumulator = fastInfinity(field, one);
            const size_t windows = (iterations + WINDOW_BITS - 1) / WINDOW_BITS;
            for (size_t window = windows; window-- > 0; ) {
                for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                    accumulator = fastDouble(
                        accumulator, field, aMont, one, aMinusThree);
                }

                const size_t bitBase = window * WINDOW_BITS;
                size_t digit = 0;
                for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                    digit |= size_t(scalar.testBit(bitBase + bit)) << bit;
                }

                const size_t nonZero =
                    (digit | (size_t(0) - digit)) >> (sizeof(size_t) * 8 - 1);
                const size_t tableDigit = digit | (nonZero ^ size_t(1));
                FastEcPoint selected = table[1];
                for (size_t i = 2; i < TABLE_SIZE; ++i) {
                    fastConditionalAssign(
                        field, uint64_t(i == tableDigit), selected, table[i]);
                }

                FastEcPoint sum = fastAdd(
                    accumulator, selected, field, aMont, one, aMinusThree);
                fastConditionalAssign(
                    field, uint64_t(nonZero ^ size_t(1)), sum, accumulator);
                accumulator = sum;
            }
            return accumulator;
        }

        SEcPoint fastToAffine(
            const FastEcPoint& point, const FastPrimeField& field,
            const FastPrimeField::Value& one, const CMontgomery& montgomery
        ) {
            if (field.isZero(point.z)) {
                return SEcPoint();
            }

            const auto zInv = field.inverse(point.z, one);
            const auto zInv2 = field.mul(zInv, zInv);
            const auto zInv3 = field.mul(zInv2, zInv);
            CBigNum x = montgomery.fromMont(field.store(field.mul(point.x, zInv2)));
            CBigNum y = montgomery.fromMont(field.store(field.mul(point.y, zInv3)));
            return SEcPoint(std::move(x), std::move(y));
        }

    } // namespace
#endif

    bool FastPrimeInverse(
        const CBigNum& value, const CBigNum& prime, CBigNum& out
    ) {
        if (value.isZero() || prime.isZero() || prime.isEven()) {
            return false;
        }

#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        const CMontgomery montgomery(prime);
        const FastPrimeField field(prime);
        FastPrimeField::Value one;
        FastPrimeField::Value input;
        if (montgomery.isValid() && field.valid()
            && field.load(montgomery.one(), one)
            && field.load(montgomery.toMont(value), input)) {
            out = montgomery.fromMont(field.store(field.inverse(input, one)));
            return !out.isZero();
        }
#endif

        return CBigNum::modInverse(value, prime, out);
    }

    bool PreparePrimeVerifyTable(
        const CEcCurve& curve, const SEcPoint& point, FastPrimeVerifyTable& out
    ) {
        out.clear();
        if (point.infinity) {
            return false;
        }

#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        constexpr size_t TABLE_SIZE = FastPrimeVerifyTable::WNAF_ENTRIES;
        const CMontgomery montgomery(curve.p);
        const FastPrimeField field(curve.p);
        CBigNum pMinusThree(curve.p);
        pMinusThree.sub(CBigNum(uint64_t(3)));
        const bool aMinusThree = curve.a == pMinusThree;
        FastPrimeField::Value one;
        FastPrimeField::Value aMont;
        FastEcPoint base;
        if (!montgomery.isValid() || !field.valid()
            || !field.load(montgomery.one(), one)
            || !field.load(montgomery.toMont(curve.a), aMont)
            || !field.load(montgomery.toMont(point.x), base.x)
            || !field.load(montgomery.toMont(point.y), base.y)) {
            return false;
        }
        base.z = one;

        static const CEcCurve standardP256 = [] {
            CEcCurve result;
            CEcCurve::knownCurves(ECURVE_P256, result);
            return result;
        }();
        const bool useP256Comb = curve.p == standardP256.p
            && curve.a == standardP256.a && curve.b == standardP256.b
            && curve.n == standardP256.n && curve.g.equals(standardP256.g);
        if (useP256Comb) {
            constexpr size_t ROWS = FastPrimeVerifyTable::P256_COMB_ROWS;
            constexpr size_t ENTRIES = FastPrimeVerifyTable::P256_COMB_ENTRIES;
            constexpr size_t WINDOW_BITS = FastPrimeVerifyTable::P256_COMB_WINDOW_BITS;
            constexpr size_t POINTS = ROWS * ENTRIES;
            const auto buildP256Comb = [&](FastPrimeVerifyTable& destination) {
                TArray<FastEcPoint> projective;
                TArray<FastPrimeField::Value> prefixes;
                if (!projective.resize(POINTS) || !prefixes.resize(POINTS)) {
                    return false;
                }
                FastEcPoint windowBase = base;
                for (size_t rowIndex = 0; rowIndex < ROWS; ++rowIndex) {
                    FastEcPoint* row = projective.begin() + rowIndex * ENTRIES;
                    row[0] = windowBase;
                    for (size_t digit = 1; digit < ENTRIES; ++digit) {
                        row[digit] = fastAdd(
                            row[digit - 1], windowBase, field, aMont, one, aMinusThree);
                    }
                    for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                        windowBase = fastDouble(windowBase, field, aMont, one, aMinusThree);
                    }
                }
                fastBatchNormalize(projective.begin(), POINTS, field, one, prefixes.begin());
                if (!destination.resizeP256Comb(field.count())) {
                    return false;
                }
                for (size_t i = 0; i < POINTS; ++i) {
                    std::memcpy(destination.x(i), projective[i].x.limbs,
                        field.count() * sizeof(uint64_t));
                    std::memcpy(destination.y(i), projective[i].y.limbs,
                        field.count() * sizeof(uint64_t));
                }
                return true;
            };
            if (point.equals(standardP256.g)) {
                static const FastPrimeVerifyTable sharedBase = [&] {
                    FastPrimeVerifyTable built;
                    buildP256Comb(built);
                    return built;
                }();
                if (!sharedBase.validFor(field.count())) {
                    return false;
                }
                out.reference(sharedBase);
                return true;
            }
            return buildP256Comb(out);
        }

        FastEcPoint table[TABLE_SIZE];
        table[0] = base;
        const FastEcPoint twice = fastDouble(base, field, aMont, one, aMinusThree);
        for (size_t i = 1; i < TABLE_SIZE; ++i) {
            table[i] = fastAdd(table[i - 1], twice, field, aMont, one, aMinusThree);
        }
        FastPrimeField::Value prefixes[TABLE_SIZE];
        fastBatchNormalize(table, TABLE_SIZE, field, one, prefixes);

        static_assert(TABLE_SIZE == FastPrimeVerifyTable::WNAF_ENTRIES, "table size mismatch");
        if (!out.resizeWnaf(field.count())) {
            return false;
        }
        for (size_t i = 0; i < TABLE_SIZE; ++i) {
            std::memcpy(out.x(i), table[i].x.limbs, field.count() * sizeof(uint64_t));
            std::memcpy(out.y(i), table[i].y.limbs, field.count() * sizeof(uint64_t));
        }
        return true;
#else
        (void)curve;
        return false;
#endif
    }

    bool FastPrimePrivateMultiplyPrepared(
        const CEcCurve& curve, const CBigNum& scalar,
        const FastPrimeVerifyTable& table, SEcPoint& out
    ) {
#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        const CMontgomery montgomery(curve.p);
        const FastPrimeField field(curve.p);
        if (!montgomery.isValid() || !field.valid() || !table.p256Comb
            || !table.validFor(field.count()) || scalar.bitLength() > 256) {
            return false;
        }

        CBigNum pMinusThree(curve.p);
        pMinusThree.sub(CBigNum(uint64_t(3)));
        const bool aMinusThree = curve.a == pMinusThree;
        FastPrimeField::Value one;
        FastPrimeField::Value aMont;
        if (!field.load(montgomery.one(), one)
            || !field.load(montgomery.toMont(curve.a), aMont)) {
            return false;
        }

        constexpr size_t ROWS = FastPrimeVerifyTable::P256_COMB_ROWS;
        constexpr size_t ENTRIES = FastPrimeVerifyTable::P256_COMB_ENTRIES;
        constexpr size_t WINDOW_BITS = FastPrimeVerifyTable::P256_COMB_WINDOW_BITS;
        FastEcPoint accumulator = fastInfinity(field, one);
        for (size_t row = 0; row < ROWS; ++row) {
            size_t digit = 0;
            for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                digit |= size_t(scalar.testBit(row * WINDOW_BITS + bit)) << bit;
            }
            const size_t nonZero =
                (digit | (size_t(0) - digit)) >> (sizeof(size_t) * 8 - 1);
            const size_t tableDigit = digit | (nonZero ^ size_t(1));
            const size_t rowBase = row * ENTRIES;
            FastEcPoint selected;
            std::memcpy(selected.x.limbs, table.x(rowBase),
                field.count() * sizeof(uint64_t));
            std::memcpy(selected.y.limbs, table.y(rowBase),
                field.count() * sizeof(uint64_t));
            for (size_t candidate = 2; candidate <= ENTRIES; ++candidate) {
                FastEcPoint candidatePoint;
                std::memcpy(candidatePoint.x.limbs, table.x(rowBase + candidate - 1),
                    field.count() * sizeof(uint64_t));
                std::memcpy(candidatePoint.y.limbs, table.y(rowBase + candidate - 1),
                    field.count() * sizeof(uint64_t));
                field.conditionalAssign(
                    uint64_t(candidate == tableDigit), selected.x, candidatePoint.x);
                field.conditionalAssign(
                    uint64_t(candidate == tableDigit), selected.y, candidatePoint.y);
            }
            selected.z = one;
            FastEcPoint sum = fastAddMixed(
                accumulator, selected, field, aMont, one, aMinusThree);
            fastConditionalAssign(
                field, uint64_t(nonZero ^ size_t(1)), sum, accumulator);
            accumulator = sum;
        }
        out = fastToAffine(accumulator, field, one, montgomery);
        return true;
#else
        (void)curve;
        (void)scalar;
        (void)table;
        (void)out;
        return false;
#endif
    }

    bool FastPrimeLinearCombinationPrepared(
        const CEcCurve& curve,
        const CBigNum& firstScalar, const FastPrimeVerifyTable& firstTable,
        const CBigNum& secondScalar, const FastPrimeVerifyTable& secondTable,
        SEcPoint& out
    ) {
#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        const CMontgomery montgomery(curve.p);
        const FastPrimeField field(curve.p);
        if (!field.valid() || !firstTable.validFor(field.count())
            || !secondTable.validFor(field.count())) {
            return false;
        }
        CBigNum pMinusThree(curve.p);
        pMinusThree.sub(CBigNum(uint64_t(3)));
        const bool aMinusThree = curve.a == pMinusThree;
        FastPrimeField::Value one;
        FastPrimeField::Value aMont;
        if (!montgomery.isValid() || !field.valid()
            || !field.load(montgomery.one(), one)
            || !field.load(montgomery.toMont(curve.a), aMont)) {
            return false;
        }

        if (firstTable.p256Comb != secondTable.p256Comb) {
            return false;
        }
        if (firstTable.p256Comb && secondTable.p256Comb) {
            if (firstScalar.bitLength() > 256 || secondScalar.bitLength() > 256) {
                return false;
            }
            constexpr size_t ROWS = FastPrimeVerifyTable::P256_COMB_ROWS;
            constexpr size_t ENTRIES = FastPrimeVerifyTable::P256_COMB_ENTRIES;
            constexpr size_t WINDOW_BITS = FastPrimeVerifyTable::P256_COMB_WINDOW_BITS;
            const CBigNum* scalars[2] = { &firstScalar, &secondScalar };
            const FastPrimeVerifyTable* tables[2] = { &firstTable, &secondTable };
            FastEcPoint accumulator = fastInfinity(field, one);
            // Both scalars are derived from the public signature and digest. Direct lookup is
            // therefore appropriate here; private scalar paths continue to scan every candidate.
            for (size_t row = 0; row < ROWS; ++row) {
                for (size_t which = 0; which < 2; ++which) {
                    size_t digit = 0;
                    for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                        digit |= size_t(scalars[which]->testBit(
                            row * WINDOW_BITS + bit)) << bit;
                    }
                    if (digit == 0) {
                        continue;
                    }
                    const size_t index = row * ENTRIES + digit - 1;
                    FastEcPoint addend;
                    std::memcpy(addend.x.limbs, tables[which]->x(index),
                        field.count() * sizeof(uint64_t));
                    std::memcpy(addend.y.limbs, tables[which]->y(index),
                        field.count() * sizeof(uint64_t));
                    addend.z = one;
                    accumulator = fastAddMixed(
                        accumulator, addend, field, aMont, one, aMinusThree);
                }
            }
            out = fastToAffine(accumulator, field, one, montgomery);
            return true;
        }

        const TArray<int8_t> firstDigits = computeWnaf(firstScalar, 8);
        const TArray<int8_t> secondDigits = computeWnaf(secondScalar, 8);
        const size_t iterations = firstDigits.size() > secondDigits.size()
            ? firstDigits.size() : secondDigits.size();
        const FastPrimeVerifyTable* tables[2] = { &firstTable, &secondTable };
        FastEcPoint accumulator = fastInfinity(field, one);
        for (size_t i = iterations; i-- > 0; ) {
            accumulator = fastDouble(accumulator, field, aMont, one, aMinusThree);
            const int digits[2] = {
                i < firstDigits.size() ? firstDigits[i] : 0,
                i < secondDigits.size() ? secondDigits[i] : 0
            };
            for (size_t which = 0; which < 2; ++which) {
                const int digit = digits[which];
                if (digit == 0) {
                    continue;
                }
                const size_t index = size_t(digit < 0 ? -digit : digit) / 2;
                FastEcPoint addend;
                std::memcpy(
                    addend.x.limbs, tables[which]->x(index),
                    field.count() * sizeof(uint64_t));
                std::memcpy(
                    addend.y.limbs, tables[which]->y(index),
                    field.count() * sizeof(uint64_t));
                addend.z = one;
                if (digit < 0) {
                    addend = fastNegate(addend, field);
                }
                accumulator = fastAddMixed(
                    accumulator, addend, field, aMont, one, aMinusThree);
            }
        }
        out = fastToAffine(accumulator, field, one, montgomery);
        return true;
#else
        (void)curve;
        (void)firstScalar;
        (void)firstTable;
        (void)secondScalar;
        (void)secondTable;
        (void)out;
        return false;
#endif
    }

        /* Parses a curve's hardcoded hex constant into a CBigNum at static-init time. The
         * strings are trusted literals (see _knownCurves below), so a parse failure (which
         * fromHex only reports via its bool return) can't actually happen here. */
        CBigNum CEcCurve::parseHex(const char* hex) {
            CBigNum result;
            CBigNum::fromHex(hex, result);
            return result;
        }

        CEcCurve::ECPointJac CEcCurve::infinityJac(const CMontgomery& field) {
            // --> (1 : 1 : 0), with the two ones in Montgomery form (see ECPointJac's comment).
            return ECPointJac{ field.one(), field.one(), CBigNum() };
        }

        CEcCurve::ECPointJac CEcCurve::toJacobian(const SEcPoint& pt, const CMontgomery& field) {
            if (pt.infinity) {
                return infinityJac(field);
            }

            return ECPointJac{ field.toMont(pt.x), field.toMont(pt.y), field.one() };
        }

        SEcPoint CEcCurve::toAffineFromJac(const ECPointJac& pt, const CMontgomery& field) {
            if (pt.z.isZero()) {
                return SEcPoint();
            }

            // --> The modular inversion is the one step of this function that has no Montgomery
            // form, so Z leaves the domain, is inverted by CBigNum's extended Euclid, and the
            // inverse comes straight back in. Everything downstream of it is domain arithmetic
            // again, and only the two affine coordinates convert back out at the end.
            CBigNum zInv;
            CBigNum::modInverse(field.fromMont(pt.z), field.modulus(), zInv);
            zInv = field.toMont(zInv);

            CBigNum zInv2(zInv);
            field.mul(zInv2, zInv);

            CBigNum zInv3(zInv2);
            field.mul(zInv3, zInv);

            CBigNum x(pt.x);
            field.mul(x, zInv2);

            CBigNum y(pt.y);
            field.mul(y, zInv3);

            return SEcPoint(field.fromMont(x), field.fromMont(y));
        }

        /* Jacobian doubling (dbl-2007-bl, Bernstein/Lange, general a -- this library's curves
         * span both a == -3, the NIST/Brainpool r1 default, and arbitrary a for secp256k1/the
         * Brainpool t1 curves, so the a == -3 shortcut isn't used). A point of order 2 (y == 0)
         * has an undefined tangent slope -- doubling it is the point at infinity, same
         * special case doublePoint() above already handles in affine form. */
        CEcCurve::ECPointJac CEcCurve::doublePointJac(
            const ECPointJac& pt, const CMontgomery& field, const CBigNum& aMont
        ) {
            if (pt.z.isZero() || pt.y.isZero()) {
                return infinityJac(field);
            }

            CBigNum A(pt.x);
            field.mul(A, pt.x);

            CBigNum B(pt.y);
            field.mul(B, pt.y);

            // C = B^2; B's original value (y^2) is still needed below (xPlusB), so this can't
            // mutate B in place -- a genuine copy.
            CBigNum C(B);
            field.mul(C, B);

            CBigNum xPlusB(pt.x);
            field.add(xPlusB, B);

            // D = 2*(xPlusB^2 - A - C), built by mutating xPlusB in place (self-squaring, then
            // the rest of the formula) -- xPlusB's pre-square value has no other reader.
            field.mul(xPlusB, xPlusB);
            field.sub(xPlusB, A);
            field.sub(xPlusB, C);
            field.dbl(xPlusB);
            CBigNum& d = xPlusB;

            CBigNum z2(pt.z);
            field.mul(z2, pt.z);

            // z4 = z2^2, by mutating z2 in place -- z2's pre-square value has no other reader.
            field.mul(z2, z2);
            CBigNum& z4 = z2;

            // threeA = 3*A: A's own value is read three times below (it stays fixed while
            // threeA accumulates), so this can't be fused into A itself.
            CBigNum threeA(A);
            field.add(threeA, A);
            field.add(threeA, A);

            CBigNum aZ4(aMont);
            field.mul(aZ4, z4);

            // E = threeA + aZ4, by mutating threeA in place -- its pre-sum value has no other
            // reader.
            field.add(threeA, aZ4);
            CBigNum& e = threeA;

            // F = E^2; E's own value is still needed below (y3), so this can't mutate e in
            // place -- a genuine copy.
            CBigNum F(e);
            field.mul(F, e);

            // twoD = 2*D; d's own value is still needed below (dMinusX3), so this can't mutate
            // d in place -- a genuine copy.
            CBigNum twoD(d);
            field.dbl(twoD);

            // x3 = F - twoD, by mutating F in place -- its pre-subtraction value has no other
            // reader.
            field.sub(F, twoD);
            CBigNum& x3 = F;

            // dMinusX3 = D - x3, by mutating d in place -- this is d's last read.
            field.sub(d, x3);
            CBigNum& dMinusX3 = d;

            CBigNum y3(e);
            field.mul(y3, dMinusX3);

            // eightC = C*8, by mutating C in place -- this is C's last read. Three doublings
            // rather than a multiplication by a literal 8, because 8 is a plain integer and the
            // operands here are Montgomery-form: multiplying by the constant would need
            // toMont(8), whereas doubling is domain-agnostic (and cheaper besides).
            field.dbl(C);
            field.dbl(C);
            field.dbl(C);
            field.sub(y3, C);

            CBigNum z3(pt.y);
            field.mul(z3, pt.z);
            field.dbl(z3);

            return ECPointJac{ std::move(x3), std::move(y3), std::move(z3) };
        }

        /* Jacobian addition (add-2007-bl, Bernstein/Lange, general Z1/Z2). Falls back to
         * doublePointJac() when both points share the same x-coordinate and the same y (P1 ==
         * P2), and to the point at infinity when they share x but differ in y (P1 == -P2) --
         * same two exceptional cases affine add() above already special-cases. */
        CEcCurve::ECPointJac CEcCurve::addJac(
            const ECPointJac& p1, const ECPointJac& p2, const CMontgomery& field,
            const CBigNum& aMont
        ) {
            if (p1.z.isZero()) {
                return p2;
            }
            if (p2.z.isZero()) {
                return p1;
            }

            // z1z1/z2z2 are each read again all the way at the very end (z3's formula), so they
            // stay alive as their own variables throughout -- no fusion opportunity for them.
            CBigNum z1z1(p1.z);
            field.mul(z1z1, p1.z);

            CBigNum z2z2(p2.z);
            field.mul(z2z2, p2.z);

            // u1 is read twice below (h's construction, then v's construction) -- it survives
            // until the second read, where it's fused away (see "u1 becomes v" below).
            CBigNum u1(p1.x);
            field.mul(u1, z2z2);

            // u2 is read exactly once below (h's construction) -- that's its last read, so h is
            // built by mutating u2 directly rather than copying it.
            CBigNum u2(p2.x);
            field.mul(u2, z1z1);

            CBigNum z2z2z2(z2z2);
            field.mul(z2z2z2, p2.z);

            CBigNum z1z1z1(z1z1);
            field.mul(z1z1z1, p1.z);

            // s1 is read twice below (this file's "r"'s construction, then twoS1J's) -- it
            // survives until the second read, where it's fused away (see "s1 becomes twoS1J"
            // below).
            CBigNum s1(p1.y);
            field.mul(s1, z2z2z2);

            // s2 is read exactly once below (this file's "r"'s construction) -- that's its last
            // read, so "r" is built by mutating s2 directly rather than copying it.
            CBigNum s2(p2.y);
            field.mul(s2, z1z1z1);

            // h = u2 - u1 (this is u2's last read -- mutate in place).
            field.sub(u2, u1);
            CBigNum& h = u2;

            // r = s2 - s1 (this is s2's last read -- mutate in place).
            field.sub(s2, s1);
            CBigNum& r = s2;

            if (h.isZero()) {
                if (r.isZero()) {
                    return doublePointJac(p1, field, aMont);
                }
                return infinityJac(field);
            }

            // i and j are each read twice below (v's/x3's construction, then x3's/twoS1J's) --
            // both stay genuine copies (h/i must still be intact after producing them: h is
            // read again at the very end, i is read again below).
            CBigNum i(h);
            field.dbl(i);
            field.mul(i, i); // (2h)^2

            CBigNum j(h);
            field.mul(j, i);

            field.dbl(r); // r = 2*(s2-s1)

            // v = u1*i (this is u1's first of two remaining reads -- fused into u1 below, at its
            // second/last read).
            field.mul(u1, i);
            CBigNum& v = u1;

            CBigNum x3(r);
            field.mul(x3, r);
            field.sub(x3, j);

            CBigNum twoV(v);
            field.dbl(twoV);
            field.sub(x3, twoV);

            // vMinusX3 = v - x3 (this is v's/u1's last read -- mutate in place).
            field.sub(v, x3);
            CBigNum& vMinusX3 = v;

            // y3 = r*vMinusX3 (this is r's/s2's last read -- mutate in place).
            field.mul(r, vMinusX3);
            CBigNum& y3Accum = r;

            // twoS1J = 2*s1*j (this is s1's last read -- mutate in place).
            field.mul(s1, j);
            field.dbl(s1);
            field.sub(y3Accum, s1);

            CBigNum z1PlusZ2(p1.z);
            field.add(z1PlusZ2, p2.z);

            CBigNum z3(z1PlusZ2);
            field.mul(z3, z1PlusZ2);
            field.sub(z3, z1z1);
            field.sub(z3, z2z2);
            field.mul(z3, h);

            return ECPointJac{ std::move(x3), std::move(y3Accum), std::move(z3) };
        }

        void CEcCurve::condSwapJac(bool doSwap, ECPointJac& a, ECPointJac& b) {
            CBigNum::condSwap(doSwap, a.x, b.x);
            CBigNum::condSwap(doSwap, a.y, b.y);
            CBigNum::condSwap(doSwap, a.z, b.z);
        }

    /* Definition of the known curves array, in EEcKnownCurves order (ECURVE_P192, ECURVE_P224,
     * ECURVE_P256, ECURVE_P384, ECURVE_P521, ECURVE_SECP256K1, then the 14 Brainpool curves
     * (RFC 5639) in R1-then-T1 order -- ECURVE_UNKNOWN has no entry). Constants verified against
     * an independent source (FIPS 186-4 / SEC 2 recommended parameters for the NIST/secp256k1
     * curves; RFC 5639 itself, cross-checked against std.neuromancer.sk, for the Brainpool
     * curves) before hardcoding. */
    const CEcCurve CEcCurve::_knownCurves[ECURVE_MAX - 1] = {
        // ECURVE_P192: NIST P-192 / secp192r1
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
            "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"
        ),
        // ECURVE_P224: NIST P-224 / secp224r1
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
            "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
            "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
            "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"
        ),
        // ECURVE_P256: NIST P-256 / secp256r1
        CEcCurve(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
        ),
        // ECURVE_P384: NIST P-384 / secp384r1
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
        ),
        // ECURVE_P521: NIST P-521 / secp521r1
        CEcCurve(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
        ),
        // ECURVE_SECP256K1: secp256k1 (SEC 2)
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            "00",
            "07",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        ),
        // ECURVE_BPOOL160R1: brainpoolP160r1 (RFC 5639)
        CEcCurve(
            "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
            "340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
            "1E589A8595423412134FAA2DBDEC95C8D8675E58",
            "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3",
            "1667CB477A1A8EC338F94741669C976316DA6321",
            "E95E4A5F737059DC60DF5991D45029409E60FC09"
        ),
        // ECURVE_BPOOL192R1: brainpoolP192r1 (RFC 5639)
        CEcCurve(
            "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
            "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
            "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
            "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
            "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
            "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"
        ),
        // ECURVE_BPOOL224R1: brainpoolP224r1 (RFC 5639)
        CEcCurve(
            "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
            "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
            "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
            "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
            "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
            "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"
        ),
        // ECURVE_BPOOL256R1: brainpoolP256r1 (RFC 5639)
        CEcCurve(
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
            "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
            "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
            "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"
        ),
        // ECURVE_BPOOL320R1: brainpoolP320r1 (RFC 5639)
        CEcCurve(
            "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
            "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
            "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
            "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
            "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"
        ),
        // ECURVE_BPOOL384R1: brainpoolP384r1 (RFC 5639)
        CEcCurve(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
            "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
            "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"
        ),
        // ECURVE_BPOOL512R1: brainpoolP512r1 (RFC 5639)
        CEcCurve(
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
            "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
            "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
            "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"
        ),
        // ECURVE_BPOOL160T1: brainpoolP160t1 (RFC 5639)
        CEcCurve(
            "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
            "E95E4A5F737059DC60DFC7AD95B3D8139515620C",
            "7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380",
            "B199B13B9B34EFC1397E64BAEB05ACC265FF2378",
            "ADD6718B7C7C1961F0991B842443772152C9E0AD",
            "E95E4A5F737059DC60DF5991D45029409E60FC09"
        ),
        // ECURVE_BPOOL192T1: brainpoolP192t1 (RFC 5639)
        CEcCurve(
            "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
            "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86294",
            "13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79",
            "3AE9E58C82F63C30282E1FE7BBF43FA72C446AF6F4618129",
            "097E2C5667C2223A902AB5CA449D0084B7E5B3DE7CCC01C9",
            "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"
        ),
        // ECURVE_BPOOL224T1: brainpoolP224t1 (RFC 5639)
        CEcCurve(
            "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
            "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC",
            "4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D",
            "6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580",
            "0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C",
            "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"
        ),
        // ECURVE_BPOOL256T1: brainpoolP256t1 (RFC 5639)
        CEcCurve(
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374",
            "662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04",
            "A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4",
            "2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"
        ),
        // ECURVE_BPOOL320T1: brainpoolP320t1 (RFC 5639)
        CEcCurve(
            "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E24",
            "A7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CEB5B4FEF422340353",
            "925BE9FB01AFC6FB4D3E7D4990010F813408AB106C4F09CB7EE07868CC136FFF3357F624A21BED52",
            "63BA3A7A27483EBF6671DBEF7ABB30EBEE084E58A0B077AD42A5A0989D1EE71B1B9BC0455FB0D2C3",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"
        ),
        // ECURVE_BPOOL384T1: brainpoolP384t1 (RFC 5639)
        CEcCurve(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC50",
            "7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805CED70355A33B471EE",
            "18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946A5F54D8D0AA2F418808CC",
            "25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC2B2912675BF5B9E582928",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"
        ),
        // ECURVE_BPOOL512T1: brainpoolP512t1 (RFC 5639)
        CEcCurve(
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F0",
            "7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA2304976540F6450085F2DAE145C22553B465763689180EA2571867423E",
            "640ECE5C12788717B9C1BA06CBC2A6FEBA85842458C56DDE9DB1758D39C0313D82BA51735CDB3EA499AA77A7D6943A64F7A3F25FE26F06B51BAA2696FA9035DA",
            "5B534BD595F5AF0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEEF216BD71DF2DADF86A627306ECFF96DBB8BACE198B61E00F8B332",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"
        ),

        // --> GOST R 34.10-2012's own parameter sets. Every one of these was parsed out of
        // the RFC named beside it and then machine-checked (base point on the curve, q*P == O,
        // non-singular discriminant) before being emitted here -- see docs/HISTORY.md.

        // ECURVE_GOST256TEST: id-GostR3410-2001-TestParamSet -- RFC 7091 section 7.1 (same curve as RFC 4357's
        // own id-GostR3410-2001-TestParamSet). Testing only.
        CEcCurve(
            "8000000000000000000000000000000000000000000000000000000000000431",
            "07",
            "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
            "02",
            "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",
            "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"
        ),
        // ECURVE_GOST256A: id-tc26-gost-3410-2012-256-paramSetA -- RFC 7836 appendix A.2, in its equivalent
        // short-Weierstrass form (the RFC also gives the twisted-Edwards e/d/u/v, which
        // CEcCurve does not model). Cofactor 4.
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
            "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
            "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
            "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
            "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
            "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"
        ),
        // ECURVE_GOST256B: id-tc26-gost-3410-2012-256-paramSetB -- the same curve as RFC 4357's
        // id-GostR3410-2001-CryptoPro-A-ParamSet (RFC 9215 appendix C), whose parameters
        // these are (RFC 4357 section 11.4).
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
            "A6",
            "01",
            "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"
        ),
        // ECURVE_GOST256C: id-tc26-gost-3410-2012-256-paramSetC -- the same curve as RFC 4357's
        // id-GostR3410-2001-CryptoPro-B-ParamSet (RFC 9215 appendix C).
        CEcCurve(
            "8000000000000000000000000000000000000000000000000000000000000C99",
            "8000000000000000000000000000000000000000000000000000000000000C96",
            "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
            "01",
            "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC",
            "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F"
        ),
        // ECURVE_GOST256D: id-tc26-gost-3410-2012-256-paramSetD -- the same curve as RFC 4357's
        // id-GostR3410-2001-CryptoPro-C-ParamSet (RFC 9215 appendix C).
        CEcCurve(
            "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
            "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
            "805A",
            "00",
            "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67",
            "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9"
        ),
        // ECURVE_GOST512TEST: id-tc26-gost-3410-2012-512-paramSetTest -- RFC 9215 appendix E. Testing only.
        CEcCurve(
            "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373",
            "07",
            "1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC",
            "24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A",
            "2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E",
            "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF"
        ),
        // ECURVE_GOST512A: id-tc26-gost-3410-12-512-paramSetA -- RFC 7836 appendix A.1.
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
            "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
            "03",
            "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"
        ),
        // ECURVE_GOST512B: id-tc26-gost-3410-12-512-paramSetB -- RFC 7836 appendix A.1.
        CEcCurve(
            "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
            "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
            "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
            "02",
            "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD",
            "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD"
        ),
        // ECURVE_GOST512C: id-tc26-gost-3410-2012-512-paramSetC -- RFC 7836 appendix A.2, in its equivalent
        // short-Weierstrass form. Cofactor 4.
        CEcCurve(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
            "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
            "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",
            "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148",
            "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F",
            "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED"
        ),
    };

    CEcCurve::CEcCurve(
        const char* pHex, const char* aHex, const char* bHex,
        const char* gxHex, const char* gyHex, const char* nHex
    )
        : p(parseHex(pHex)), a(parseHex(aHex)), b(parseHex(bHex)), n(parseHex(nHex)),
          g(parseHex(gxHex), parseHex(gyHex))
    {
    }

    /* Maps a known curve identifier to the EAsymmetrics identifying it -- see this method's own
     * doc comment in eccurve.hpp. */
    EAsymmetrics CEcCurve::identify(EEcKnownCurves which) {
        switch (which) {
            case ECURVE_P192:        return EASYM_P192;
            case ECURVE_P224:        return EASYM_P224;
            case ECURVE_P256:        return EASYM_P256;
            case ECURVE_P384:        return EASYM_P384;
            case ECURVE_P521:        return EASYM_P521;
            case ECURVE_SECP256K1:   return EASYM_SECP256K1;
            case ECURVE_BPOOL160R1:  return EASYM_BPOOL160R1;
            case ECURVE_BPOOL192R1:  return EASYM_BPOOL192R1;
            case ECURVE_BPOOL224R1:  return EASYM_BPOOL224R1;
            case ECURVE_BPOOL256R1:  return EASYM_BPOOL256R1;
            case ECURVE_BPOOL320R1:  return EASYM_BPOOL320R1;
            case ECURVE_BPOOL384R1:  return EASYM_BPOOL384R1;
            case ECURVE_BPOOL512R1:  return EASYM_BPOOL512R1;
            case ECURVE_BPOOL160T1:  return EASYM_BPOOL160T1;
            case ECURVE_BPOOL192T1:  return EASYM_BPOOL192T1;
            case ECURVE_BPOOL224T1:  return EASYM_BPOOL224T1;
            case ECURVE_BPOOL256T1:  return EASYM_BPOOL256T1;
            case ECURVE_BPOOL320T1:  return EASYM_BPOOL320T1;
            case ECURVE_BPOOL384T1:  return EASYM_BPOOL384T1;
            case ECURVE_BPOOL512T1:  return EASYM_BPOOL512T1;
            case ECURVE_GOST256TEST: return EASYM_GOST256TEST;
            case ECURVE_GOST256A:    return EASYM_GOST256A;
            case ECURVE_GOST256B:    return EASYM_GOST256B;
            case ECURVE_GOST256C:    return EASYM_GOST256C;
            case ECURVE_GOST256D:    return EASYM_GOST256D;
            case ECURVE_GOST512TEST: return EASYM_GOST512TEST;
            case ECURVE_GOST512A:    return EASYM_GOST512A;
            case ECURVE_GOST512B:    return EASYM_GOST512B;
            case ECURVE_GOST512C:    return EASYM_GOST512C;
            default:                 return EASYM_P256; // unreachable for a validly-constructed CEcdsa
        }
    }

    size_t CEcCurve::fieldByteLen() const {
        return (p.bitLength() + 7) / 8;
    }

    bool CEcCurve::isOnCurve(const SEcPoint& pt) const {
        if (pt.infinity) {
            return true;
        }

        CBigNum lhs(pt.y);
        lhs.mulMod(pt.y, p);

        CBigNum rhs(pt.x);
        rhs.mulMod(pt.x, p);
        rhs.mulMod(pt.x, p);

        CBigNum ax(a);
        ax.mulMod(pt.x, p);

        rhs.add(ax);
        rhs.add(b);
        rhs.mod(p);

        return lhs == rhs;
    }

    SEcPoint CEcCurve::add(const SEcPoint& p1, const SEcPoint& p2) const {
        if (p1.infinity) {
            return p2;
        }

        if (p2.infinity) {
            return p1;
        }

        if (p1.x == p2.x) {
            CBigNum ySum(p1.y);
            ySum.add(p2.y);
            ySum.mod(p);
            if (ySum.isZero()) {
                return SEcPoint(); // p1 == -p2 -- result is the point at infinity
            }

            return doublePoint(p1);
        }

        CBigNum dx(p2.x);
        dx.modSub(p1.x, p);

        CBigNum dy(p2.y);
        dy.modSub(p1.y, p);

        CBigNum dxInv;
        if (!CBigNum::modInverse(dx, p, dxInv)) {
            return SEcPoint(); // unreachable: dx != 0 was just checked (p1.x != p2.x)
        }

        // dy's last read -- mutate in place instead of copying into a separate lambda.
        dy.mulMod(dxInv, p);
        CBigNum& lambda = dy;

        CBigNum x3(lambda);
        x3.mulMod(lambda, p);
        x3.modSub(p1.x, p);
        x3.modSub(p2.x, p);

        CBigNum y3(p1.x);
        y3.modSub(x3, p);
        y3.mulMod(lambda, p);
        y3.modSub(p1.y, p);

        return SEcPoint(std::move(x3), std::move(y3));
    }

    SEcPoint CEcCurve::doublePoint(const SEcPoint& pt) const {
        if (pt.infinity || pt.y.isZero()) {
            return SEcPoint();
        }

        CBigNum xx(pt.x);
        xx.mulMod(pt.x, p);

        CBigNum threeXX(xx);
        threeXX.add(xx);
        threeXX.add(xx);
        threeXX.mod(p);

        // threeXX's last read -- mutate in place instead of copying into a separate numerator.
        threeXX.add(a);
        threeXX.mod(p);

        CBigNum twoY(pt.y);
        twoY.add(pt.y);
        twoY.mod(p);

        CBigNum twoYInv;
        if (!CBigNum::modInverse(twoY, p, twoYInv)) {
            return SEcPoint(); // unreachable: y != 0 was just checked
        }

        // threeXX's (now "numerator"'s) last read -- mutate in place instead of copying into a
        // separate lambda.
        threeXX.mulMod(twoYInv, p);
        CBigNum& lambda = threeXX;

        CBigNum x3(lambda);
        x3.mulMod(lambda, p);
        x3.modSub(pt.x, p);
        x3.modSub(pt.x, p);

        CBigNum y3(pt.x);
        y3.modSub(x3, p);
        y3.mulMod(lambda, p);
        y3.modSub(pt.y, p);

        return SEcPoint(std::move(x3), std::move(y3));
    }

    /* Portable branch-free-shaped double-and-add fallback, entirely in Jacobian coordinates:
     * R0/R1 always satisfy the
     * invariant R1 == R0 + pt, and every iteration always computes both an addition and a
     * doubling -- only which register ends up holding which value depends on the scalar's bit,
     * via condSwapJac() rather than a branch choosing whether to run an addition at all (contrast
     * the old shape, which only ever added when the bit was set). Still not constant-time
     * overall (condSwapJac()/CBigNum's own arithmetic aren't), but removes the "the expensive
     * step only sometimes runs" pattern that was the most visible timing signal. Jacobian
     * coordinates additionally mean the loop itself never pays for a modular inversion --
     * toAffineFromJac() below pays for exactly one, at the very end, replacing the
     * one-inversion-per-step affine version this used to be (add()/doublePoint() above still
     * exist and still work in affine form, for callers that need a single group operation rather
     * than a full scalar multiplication).
     *
     * The loop runs in the Montgomery domain (see CMontgomery): the per-modulus constants are
     * built once here, up front, and every field multiplication inside then costs limb-wise
     * multiply-accumulate passes instead of the full Knuth-D long division CBigNum::mulMod() has
     * no choice but to perform. Building the context costs two divisions against the thousands it
     * saves, which is why it is built per call rather than cached on the curve -- a cached copy
     * would have to be invalidated whenever a caller wrote to the public p/a/b fields, and the
     * saving from caching it is unmeasurable next to the scalar multiplication it precedes. */
    SEcPoint CEcCurve::scalarMul(const SEcPoint& pt, const CBigNum& k) const {
        SEcPoint result; // infinity

        if (pt.infinity || k.isZero()) {
            return result;
        }

        // --> Every field prime this library ships is an odd prime, so this only fails on a
        // default-constructed (p == 0) curve, which has no group to multiply in anyway.
        const CMontgomery field(p);
        if (!field.isValid()) {
            return result;
        }

#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        const FastPrimeField fastField(p);
        CBigNum pMinusThree(p);
        pMinusThree.sub(CBigNum(uint64_t(3)));
        const bool fastAMinusThree = a == pMinusThree;
        FastPrimeField::Value fastOne;
        FastPrimeField::Value fastA;
        FastEcPoint fastInput;
        if (fastField.valid() &&
            fastField.load(field.one(), fastOne) &&
            fastField.load(field.toMont(a), fastA) &&
            fastField.load(field.toMont(pt.x), fastInput.x) &&
            fastField.load(field.toMont(pt.y), fastInput.y)) {
            fastInput.z = fastOne;
            const size_t scalarBits = k.bitLength();
            const size_t orderBits = n.bitLength();
            const size_t iterations = scalarBits > orderBits ? scalarBits : orderBits;
            const FastEcPoint product = fastWindowMultiply(
                fastInput, k, iterations, fastField, fastA, fastOne, fastAMinusThree);
            return fastToAffine(product, fastField, fastOne, field);
        }
#endif

        const CBigNum aMont = field.toMont(a);

        ECPointJac r0 = infinityJac(field);
        ECPointJac r1 = toJacobian(pt, field);

        const size_t scalarBits = k.bitLength();
        const size_t orderBits = n.bitLength();
        const size_t iterations = scalarBits > orderBits ? scalarBits : orderBits;

        for (size_t i = iterations; i-- > 0; ) {
            const bool bit = k.testBit(i);

            condSwapJac(bit, r0, r1);
            ECPointJac sum = addJac(r0, r1, field, aMont);
            ECPointJac doubled = doublePointJac(r0, field, aMont);
            r1 = std::move(sum);
            r0 = std::move(doubled);
            condSwapJac(bit, r0, r1);
        }

        return toAffineFromJac(r0, field);
    }

    /* Fixed-base multiplication with full-scan tables, so secret scalar bits never become memory
     * indexes. The native fixed-width path caches a compact 33-row signed radix-256 comb only after
     * every
     * standard P-256 parameter and the generator compare equal; mutable or other parameters build
     * a four-bit table per call. The portable CBigNum path always builds that per-call four-bit
     * table. */
    SEcPoint CEcCurve::scalarMulBase(const CBigNum& k) const {
        constexpr size_t WINDOW_BITS = 4;
        constexpr size_t TABLE_SIZE = size_t(1) << WINDOW_BITS;

        SEcPoint result;
        if (g.infinity || k.isZero()) {
            return result;
        }

        const CMontgomery field(p);
        if (!field.isValid()) {
            return result;
        }

#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        const FastPrimeField fastField(p);
        CBigNum pMinusThree(p);
        pMinusThree.sub(CBigNum(uint64_t(3)));
        const bool fastAMinusThree = a == pMinusThree;
        FastPrimeField::Value fastOne;
        FastPrimeField::Value fastA;
        FastEcPoint fastBase;
        if (fastField.valid() &&
            fastField.load(field.one(), fastOne) &&
            fastField.load(field.toMont(a), fastA) &&
            fastField.load(field.toMont(g.x), fastBase.x) &&
            fastField.load(field.toMont(g.y), fastBase.y)) {
            fastBase.z = fastOne;
            const size_t scalarBits = k.bitLength();
            const size_t orderBits = n.bitLength();
            const size_t iterations = scalarBits > orderBits ? scalarBits : orderBits;
            if (iterations <= 256) {
                const CEcCurve& standard = _knownCurves[ECURVE_P256 - 1];
                const bool standardP256 = p == standard.p && a == standard.a
                    && b == standard.b && n == standard.n && g.equals(standard.g);
                if (standardP256) {
                    static const FastP256CombTable comb = [&] {
                        FastP256CombTable built;
                        constexpr size_t POINTS =
                            FastP256CombTable::ROWS * FastP256CombTable::ENTRIES;
                        TArray<FastEcPoint> projective;
                        TArray<FastPrimeField::Value> prefixes;
                        if (!projective.resize(POINTS) || !prefixes.resize(POINTS)) {
                            return built;
                        }
                        FastEcPoint windowBase = fastBase;
                        for (size_t window = 0; window < FastP256CombTable::ROWS; ++window) {
                            FastEcPoint* row = projective.begin()
                                + window * FastP256CombTable::ENTRIES;
                            row[0] = fastInfinity(fastField, fastOne);
                            row[1] = windowBase;
                            for (size_t digit = 2; digit < FastP256CombTable::ENTRIES; ++digit) {
                                row[digit] = fastAdd(
                                    row[digit - 1], windowBase,
                                    fastField, fastA, fastOne, fastAMinusThree);
                            }
                            for (size_t bit = 0; bit < FastP256CombTable::WINDOW_BITS; ++bit) {
                                windowBase = fastDouble(
                                    windowBase, fastField, fastA, fastOne, fastAMinusThree);
                            }
                        }
                        fastBatchNormalize(
                            projective.begin(), POINTS,
                            fastField, fastOne, prefixes.begin());
                        for (size_t window = 0; window < FastP256CombTable::ROWS; ++window) {
                            for (size_t digit = 0; digit < FastP256CombTable::ENTRIES; ++digit) {
                                const FastEcPoint& source = projective[
                                    window * FastP256CombTable::ENTRIES + digit];
                                for (size_t limb = 0; limb < 4; ++limb) {
                                    built.points[window][digit].x[limb] = source.x.limbs[limb];
                                    built.points[window][digit].y[limb] = source.y.limbs[limb];
                                }
                            }
                        }
                        built.valid = true;
                        return built;
                    }();

                    if (comb.valid) {
#if defined(CERTPP_P256_COMB_AVX512)
                        const bool useAvx512Selection = hasP256CombAvx512();
#endif
                        FastEcPoint accumulator = fastInfinity(fastField, fastOne);
                        size_t carry = 0;
                        for (size_t window = 0; window < FastP256CombTable::ROWS; ++window) {
                            size_t byte = 0;
                            for (size_t bit = 0; bit < FastP256CombTable::WINDOW_BITS; ++bit) {
                                byte |= size_t(k.testBit(
                                    window * FastP256CombTable::WINDOW_BITS + bit)) << bit;
                            }
                            // Center each radix-256 digit in [-127, 128]. The fixed extra row
                            // consumes a final carry, and selection still scans every magnitude.
                            const size_t rawDigit = byte + carry;
                            carry = (rawDigit + 127) >> FastP256CombTable::WINDOW_BITS;
                            const size_t negativeMask = size_t(0) - carry;
                            const size_t digit = (rawDigit & ~negativeMask)
                                | (((size_t(1) << FastP256CombTable::WINDOW_BITS) - rawDigit)
                                    & negativeMask);
                            const size_t nonZero =
                                (digit | (size_t(0) - digit)) >> (sizeof(size_t) * 8 - 1);
                            const size_t tableDigit = digit | (nonZero ^ size_t(1));
                            FastEcPoint selected;
#if defined(CERTPP_P256_COMB_AVX512)
                            if (useAvx512Selection) {
                                FastP256CombTable::AffinePoint packed;
                                selectP256CombAvx512(
                                    comb.points[window], tableDigit, packed);
                                std::memcpy(selected.x.limbs, packed.x, sizeof(packed.x));
                                std::memcpy(selected.y.limbs, packed.y, sizeof(packed.y));
                            } else
#endif
                            {
                                for (size_t limb = 0; limb < 4; ++limb) {
                                    selected.x.limbs[limb] = comb.points[window][1].x[limb];
                                    selected.y.limbs[limb] = comb.points[window][1].y[limb];
                                }
                                for (size_t i = 2; i < FastP256CombTable::ENTRIES; ++i) {
                                    const uint64_t mask = uint64_t(0) - uint64_t(i == tableDigit);
                                    for (size_t limb = 0; limb < 4; ++limb) {
                                        selected.x.limbs[limb] ^=
                                            (selected.x.limbs[limb]
                                                ^ comb.points[window][i].x[limb]) & mask;
                                        selected.y.limbs[limb] ^=
                                            (selected.y.limbs[limb]
                                                ^ comb.points[window][i].y[limb]) & mask;
                                    }
                                }
                            }
                            selected.z = fastOne;
                            FastPrimeField::Value negatedY = fastField.sub(
                                FastPrimeField::Value(), selected.y);
                            fastField.conditionalAssign(
                                uint64_t(carry & nonZero), selected.y, negatedY);
                            FastEcPoint sum = fastAddMixed(
                                accumulator, selected,
                                fastField, fastA, fastOne, fastAMinusThree);
                            fastConditionalAssign(
                                fastField, uint64_t(nonZero ^ size_t(1)), sum, accumulator);
                            accumulator = sum;
                        }
                        return fastToAffine(accumulator, fastField, fastOne, field);
                    }
                }
            }
            const FastEcPoint product = fastWindowMultiply(
                fastBase, k, iterations, fastField, fastA, fastOne, fastAMinusThree);
            return fastToAffine(product, fastField, fastOne, field);
        }
#endif

        const CBigNum aMont = field.toMont(a);
        TArray<ECPointJac> table;
        if (!table.resize(TABLE_SIZE)) {
            return result;
        }

        table[0] = infinityJac(field);
        table[1] = toJacobian(g, field);
        for (size_t i = 2; i < TABLE_SIZE; ++i) {
            table[i] = addJac(table[i - 1], table[1], field, aMont);
        }

        ECPointJac accumulator = infinityJac(field);
        const size_t scalarBits = k.bitLength();
        const size_t orderBits = n.bitLength();
        const size_t iterations = scalarBits > orderBits ? scalarBits : orderBits;
        const size_t windows = (iterations + WINDOW_BITS - 1) / WINDOW_BITS;

        for (size_t window = windows; window-- > 0; ) {
            for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                accumulator = doublePointJac(accumulator, field, aMont);
            }

            const size_t base = window * WINDOW_BITS;
            size_t digit = 0;
            for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                digit |= size_t(k.testBit(base + bit)) << bit;
            }

            ECPointJac selected = infinityJac(field);
            for (size_t i = 0; i < TABLE_SIZE; ++i) {
                ECPointJac candidate = table[i];
                condSwapJac(i == digit, selected, candidate);
            }
            accumulator = addJac(accumulator, selected, field, aMont);
        }

        return toAffineFromJac(accumulator, field);
    }

    /* Joint multiplication for public verification scalars. Unlike scalarMul(), this routine is
     * deliberately variable-time: the bits of ECDSA/GOST verification scalars are already public,
     * and selecting among P1/P2/P1+P2 avoids duplicating a full fixed-shape ladder. */
    SEcPoint CEcCurve::linearCombination(
        const CBigNum& k1, const SEcPoint& p1,
        const CBigNum& k2, const SEcPoint& p2
    ) const {
        SEcPoint result;
        const size_t bits1 = k1.bitLength();
        const size_t bits2 = k2.bitLength();
        const size_t iterations = bits1 > bits2 ? bits1 : bits2;
        if (iterations == 0) {
            return result;
        }

        const CMontgomery field(p);
        if (!field.isValid()) {
            return result;
        }

#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        const FastPrimeField fastField(p);
        CBigNum pMinusThree(p);
        pMinusThree.sub(CBigNum(uint64_t(3)));
        const bool fastAMinusThree = a == pMinusThree;
        FastPrimeField::Value fastOne;
        FastPrimeField::Value fastA;
        FastEcPoint fastP1;
        FastEcPoint fastP2;
        if (fastField.valid() &&
            fastField.load(field.one(), fastOne) &&
            fastField.load(field.toMont(a), fastA) &&
            fastField.load(field.toMont(p1.x), fastP1.x) &&
            fastField.load(field.toMont(p1.y), fastP1.y) &&
            fastField.load(field.toMont(p2.x), fastP2.x) &&
            fastField.load(field.toMont(p2.y), fastP2.y)) {
            fastP1.z = p1.infinity ? FastPrimeField::Value() : fastOne;
            fastP2.z = p2.infinity ? FastPrimeField::Value() : fastOne;
            constexpr size_t WNAF_TABLE_SIZE = 8;
            FastEcPoint tables[2][WNAF_TABLE_SIZE];
            FastEcPoint* table1 = tables[0];
            FastEcPoint* table2 = tables[1];
            table1[0] = fastP1;
            table2[0] = fastP2;
            const FastEcPoint twiceP1 = fastDouble(
                fastP1, fastField, fastA, fastOne, fastAMinusThree);
            const FastEcPoint twiceP2 = fastDouble(
                fastP2, fastField, fastA, fastOne, fastAMinusThree);
            for (size_t i = 1; i < WNAF_TABLE_SIZE; ++i) {
                table1[i] = fastAdd(
                    table1[i - 1], twiceP1,
                    fastField, fastA, fastOne, fastAMinusThree);
                table2[i] = fastAdd(
                    table2[i - 1], twiceP2,
                    fastField, fastA, fastOne, fastAMinusThree);
            }
            FastPrimeField::Value prefixes[2 * WNAF_TABLE_SIZE];
            fastBatchNormalize(
                &tables[0][0], 2 * WNAF_TABLE_SIZE, fastField, fastOne, prefixes);

            const TArray<int8_t> digits1 = computeWnaf(k1, 5);
            const TArray<int8_t> digits2 = computeWnaf(k2, 5);
            const size_t wnafIterations =
                digits1.size() > digits2.size() ? digits1.size() : digits2.size();
            FastEcPoint accumulator = fastInfinity(fastField, fastOne);

            for (size_t i = wnafIterations; i-- > 0; ) {
                accumulator = fastDouble(
                    accumulator, fastField, fastA, fastOne, fastAMinusThree);
                const int digit1 = i < digits1.size() ? digits1[i] : 0;
                const int digit2 = i < digits2.size() ? digits2[i] : 0;
                if (digit1 != 0) {
                    FastEcPoint addend = table1[(digit1 < 0 ? -digit1 : digit1) / 2];
                    if (digit1 < 0) {
                        addend = fastNegate(addend, fastField);
                    }
                    accumulator = fastAddMixed(
                        accumulator, addend,
                        fastField, fastA, fastOne, fastAMinusThree);
                }
                if (digit2 != 0) {
                    FastEcPoint addend = table2[(digit2 < 0 ? -digit2 : digit2) / 2];
                    if (digit2 < 0) {
                        addend = fastNegate(addend, fastField);
                    }
                    accumulator = fastAddMixed(
                        accumulator, addend,
                        fastField, fastA, fastOne, fastAMinusThree);
                }
            }

            return fastToAffine(accumulator, fastField, fastOne, field);
        }
#endif

        const CBigNum aMont = field.toMont(a);
        const ECPointJac j1 = toJacobian(p1, field);
        const ECPointJac j2 = toJacobian(p2, field);
        const ECPointJac j12 = addJac(j1, j2, field, aMont);
        ECPointJac accumulator = infinityJac(field);

        for (size_t i = iterations; i-- > 0; ) {
            accumulator = doublePointJac(accumulator, field, aMont);
            const bool bit1 = k1.testBit(i);
            const bool bit2 = k2.testBit(i);
            if (bit1 && bit2) {
                accumulator = addJac(accumulator, j12, field, aMont);
            } else if (bit1) {
                accumulator = addJac(accumulator, j1, field, aMont);
            } else if (bit2) {
                accumulator = addJac(accumulator, j2, field, aMont);
            }
        }

        return toAffineFromJac(accumulator, field);
    }

    bool CEcCurve::encodePoint(const SEcPoint& pt, TArray<uint8_t>& out) const {
        if (pt.infinity) {
            out.resize(1);
            out[0] = 0x00;
            return true;
        }

        size_t flen = fieldByteLen();
        out.resize(1 + 2 * flen);
        out[0] = 0x04;

        if (!pt.x.toBigEndian(SByteSpan(out.begin() + 1, flen))) {
            return false;
        }

        if (!pt.y.toBigEndian(SByteSpan(out.begin() + 1 + flen, flen))) {
            return false;
        }

        return true;
    }

    bool CEcCurve::decodePoint(SReadOnlyByteSpan data, SEcPoint& out) const {
        // --> The point at infinity is a valid SEC1 *encoding*, but never a valid *public key* --
        // every caller (createPublicKey()/createPrivateKey() in ecdsa.cpp) immediately rejected it
        // on top of this call anyway, so it's rejected once here instead, for every caller.
        if (data.size == 1 && data.data[0] == 0x00) {
            return false;
        }

        size_t flen = fieldByteLen();
        if (data.size != 1 + 2 * flen || data.data[0] != 0x04) {
            return false;
        }

        CBigNum x = CBigNum::fromBigEndian(data.slice(1, flen));
        CBigNum y = CBigNum::fromBigEndian(data.slice(1 + flen, flen));

        // --> Field range: a flen-byte big-endian value can represent anything up to 2^(8*flen)-1,
        // which is larger than p for every curve this library ships (p is never of the form
        // 2^n-1) -- without this, isOnCurve()'s mod-p arithmetic would accept a non-canonical
        // x/y >= p as "on curve" (it's equal mod p to some legitimate point), letting the same
        // point be smuggled in under more than one byte encoding.
        if (x >= p || y >= p) {
            return false;
        }

        SEcPoint candidate(x, y);
        if (!isOnCurve(candidate)) {
            return false;
        }

        // --> Correct (order-n) subgroup: n*candidate must be the point at infinity. This is
        // mathematically guaranteed already for this library's cofactor-1 curves (the only
        // possible point orders are 1 and n, and order 1 is the already-rejected infinity), but
        // checking it unconditionally here keeps every decodePoint() caller uniformly protected
        // without relying on each one separately re-deriving why it's safe to skip -- see
        // CEc2Curve::decodePoint(), where the equivalent check is NOT redundant. It is not
        // redundant for ECURVE_GOST256A/ECURVE_GOST512C either, whose cofactor is 4.
        if (!scalarMul(candidate, n).infinity) {
            return false;
        }

        out = candidate;
        return true;
    }

} // namespace crypto
} // namespace certpp
