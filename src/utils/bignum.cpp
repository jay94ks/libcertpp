#include <certpp/utils/bignum.hpp>
#include <certpp/utils/hex.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/io/buffer.hpp>
#include <cstring>
#include <utility>

/* Hardware-accelerated multiply (MULX/BMI2 + ADCX/ADX, over pairs of the existing 32-bit limbs
 * reinterpreted as 64-bit digits) for mul()'s inner loop, gated by both the
 * CERTPP_DISABLE_HWACCEL_SIMD build option and the target architecture. ADX/BMI2 (unlike GF(2^m)'s
 * PCLMULQDQ) only exist in 64-bit mode, so this is x86-64-only -- compiled out entirely on
 * 32-bit x86 and non-x86 targets, where mul() falls back to the portable loop unconditionally. */
#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && (defined(_M_X64) || defined(__x86_64__))
#define CERTPP_BIGNUM_HWACCEL_AVAILABLE 1
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {

#if defined(CERTPP_BIGNUM_HWACCEL_AVAILABLE)
        /* Whether this CPU actually has BMI2 (MULX) and ADX (ADCX/ADOX) -- both are optional
         * x86-64 features, not guaranteed just because the binary was built for the
         * architecture, so this must be checked at runtime before ever emitting either
         * instruction. Computed once (CPUID leaf 7, sub-leaf 0: EBX bit 8 = BMI2, bit 19 = ADX). */
        bool CBigNum::hasAdxBmi2() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };

                // --> Leaf 7 must be gated on leaf 0's reported maximum: CPUID answers an
                // out-of-range leaf with the highest supported leaf's data, not zeroes, so
                // without this a CPU whose maximum is below 7 can appear to advertise BMI2/ADX.
                // The __get_cpuid_count() path below makes the same check internally.
                __cpuid(info, 0);
                if (info[0] < 7) {
                    return false;
                }

                __cpuidex(info, 7, 0);
                return ((info[1] & (1 << 8)) != 0) && ((info[1] & (1 << 19)) != 0);
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return ((ebx & (1u << 8)) != 0) && ((ebx & (1u << 19)) != 0);
#endif
            }();

            return supported;
        }

        /* Reinterprets a little-endian 32-bit limb buffer as len64 64-bit digits, zero-padded
         * past src's actual length (and past len32 if len32 is odd). */
        void CBigNum::packInto64(const uint32_t* src, size_t len32, uint64_t* dst64, size_t len64) {
            for (size_t i = 0; i < len64; ++i) {
                size_t lo = i * 2, hi = lo + 1;
                uint64_t v = (lo < len32) ? uint64_t(src[lo]) : 0;
                if (hi < len32) {
                    v |= (uint64_t(src[hi]) << 32);
                }
                dst64[i] = v;
            }
        }

        /* Schoolbook multiply over 64-bit digits (each covering 2 of CBigNum's native 32-bit
         * limbs), using MULX for the digit multiply and ADCX for carry-propagating accumulation
         * -- the same algorithm as CBigNum::mul()'s portable loop below, just processing twice
         * the bits per hardware multiply instruction, and producing an identical result. Given
         * how much of this library depends on CBigNum::mul() being correct, this is additionally
         * verified by a dedicated cross-check against the portable loop (tests/utils/bignum.cpp)
         * across many random operand pairs, not just this library's ordinary test suite.
         *
         * __attribute__((target(...))) lets GCC/Clang emit these instructions in just this one
         * function regardless of the translation unit's default -march (MSVC needs no
         * equivalent -- it allows using intrinsics for any instruction set unconditionally, and
         * relies on the runtime hasAdxBmi2() check above to avoid actually executing them on a
         * CPU that lacks the feature). */
#if defined(__GNUC__) && !defined(_MSC_VER)
        __attribute__((target("bmi2,adx")))
#endif
        void CBigNum::mulAccelerated(
            const uint32_t* a, size_t aLen, const uint32_t* b, size_t bLen,
            uint32_t* result, size_t resultLen
        ) {
            size_t aLen64 = (aLen + 1) / 2;
            size_t bLen64 = (bLen + 1) / 2;
            size_t resultLen64 = aLen64 + bLen64 + 1;

            TArray<uint64_t> a64, b64, r64, row;
            a64.resize(aLen64);
            b64.resize(bLen64);
            r64.resize(resultLen64);
            row.resize(bLen64 + 1);

            packInto64(a, aLen, a64.begin(), aLen64);
            packInto64(b, bLen, b64.begin(), bLen64);
            for (size_t i = 0; i < resultLen64; ++i) {
                r64[i] = 0;
            }

            for (size_t i = 0; i < aLen64; ++i) {
                uint64_t ai = a64[i];
                if (ai == 0) {
                    continue;
                }

                // Step A: row[] = ai * b64[] (single-digit-times-multiword multiply). Each step
                // here only ever adds two full-range 64-bit values (lo, carry) plus an implicit
                // zero carry-in -- the provably-safe case for _addcarry_u64 (its carry-out can
                // only ever be 0 or 1 when summing two 64-bit operands, unlike summing three at
                // once, which needs 2 bits of carry-out and is NOT representable by a single
                // _addcarry_u64 call chained the "obvious" way -- the bug an earlier version of
                // this function had, caught by the cross-check test this function's own doc
                // comment mentions).
                uint64_t carry = 0;
                for (size_t j = 0; j < bLen64; ++j) {
                    uint64_t hi;
                    uint64_t lo = _mulx_u64(ai, b64[j], &hi);

                    unsigned char c = _addcarry_u64(0, lo, carry, &row[j]);
                    carry = hi + c; // hi <= 2^64-2, so +1 (c is 0 or 1) never overflows
                }
                row[bLen64] = carry;

                // Step B: r64[i .. i+bLen64] += row[] -- an ordinary multi-precision add (two
                // same-length arrays, single-bit carry propagation throughout), the same
                // structure as CBigNum::sub()'s/add()'s own limb loops, just at 64-bit
                // granularity: also provably safe, for the same two-operand-plus-carry-in reason.
                unsigned char carry2 = 0;
                for (size_t j = 0; j <= bLen64; ++j) {
                    carry2 = _addcarry_u64(carry2, r64[i + j], row[j], &r64[i + j]);
                }

                size_t k = i + bLen64 + 1;
                while (carry2 != 0 && k < resultLen64) {
                    carry2 = _addcarry_u64(carry2, r64[k], 0, &r64[k]);
                    ++k;
                }
            }

            for (size_t i = 0; i < resultLen; ++i) {
                size_t digit = i / 2;
                uint64_t v = (digit < resultLen64) ? r64[digit] : 0;
                result[i] = (i % 2 == 0) ? uint32_t(v) : uint32_t(v >> 32);
            }
        }
#endif

        /* Reverses a byte span in place -- bridges this class's big-endian convention to
         * RFC 7748/RFC 8032's little-endian wire format. */
        void CBigNum::reverseBytesInPlace(const SByteSpan& bytes) {
            for (size_t i = 0, j = bytes.size; i < j; ++i, --j) {
                uint8_t t = bytes.data[i];
                bytes.data[i] = bytes.data[j - 1];
                bytes.data[j - 1] = t;
            }
        }

        /* Shifts a raw little-endian limb buffer left by exactly 1 bit in place, discarding any
         * overflow beyond count limbs (callers size the buffer with enough headroom). */
        void CBigNum::shiftLeft1(uint32_t* limbs, size_t count) {
            uint32_t carry = 0;

            for (size_t i = 0; i < count; ++i) {
                uint32_t next = limbs[i] >> 31;
                limbs[i] = (limbs[i] << 1) | carry;
                carry = next;
            }
        }

        /* Compares two same-length raw little-endian limb buffers. */
        int CBigNum::compareLimbs(const uint32_t* a, const uint32_t* b, size_t count) {
            for (size_t i = count; i-- > 0; ) {
                if (a[i] != b[i]) {
                    return a[i] < b[i] ? -1 : 1;
                }
            }

            return 0;
        }

        /* Subtracts b from a in place, assuming a >= b (same-length raw little-endian buffers). */
        void CBigNum::subtractLimbs(uint32_t* a, const uint32_t* b, size_t count) {
            int64_t borrow = 0;

            for (size_t i = 0; i < count; ++i) {
                int64_t t = int64_t(a[i]) - int64_t(b[i]) - borrow;

                if (t < 0) {
                    t += (int64_t(1) << 32);
                    borrow = 1;
                } else {
                    borrow = 0;
                }

                a[i] = uint32_t(t);
            }
        }

    /* A signed magnitude used only by modInverse()'s extended-Euclidean bookkeeping (the Bezout
     * coefficients can go negative, even though CBigNum itself never does). */
    SignedBig CBigNum::signedAdd(const SignedBig& x, const SignedBig& y) {
        if (x.neg == y.neg) {
            CBigNum m(x.mag);
            m.add(y.mag);
            return SignedBig{ std::move(m), x.neg };
        }

        if (x.mag.compare(y.mag) >= 0) {
            CBigNum m(x.mag);
            m.sub(y.mag);
            bool mz = m.isZero();
            return SignedBig{ std::move(m), mz ? false : x.neg };
        }

        CBigNum m(y.mag);
        m.sub(x.mag);
        bool mz = m.isZero();
        return SignedBig{ std::move(m), mz ? false : y.neg };
    }

    SignedBig CBigNum::signedSub(const SignedBig& x, const SignedBig& y) {
        return signedAdd(x, SignedBig{ y.mag, !y.neg });
    }

    SignedBig CBigNum::signedMul(const CBigNum& q, const SignedBig& s) {
        CBigNum m(q);
        m.mul(s.mag);
        bool mz = m.isZero();
        return SignedBig{ std::move(m), mz ? false : s.neg };
    }

    CBigNum CBigNum::fromLimbsTrimmed(TArray<uint32_t>&& limbs) {
        size_t n = limbs.size();
        while (n > 0 && limbs[n - 1] == 0) {
            --n;
        }

        limbs.resize(n);

        CBigNum result;
        result._limbs = std::move(limbs);
        return result;
    }

    CBigNum::CBigNum() {
    }

    CBigNum::CBigNum(uint64_t value) {
        if (value == 0) {
            return;
        }

        uint32_t low = uint32_t(value);
        uint32_t high = uint32_t(value >> 32);

        if (high) {
            _limbs.resize(2);
            _limbs[0] = low;
            _limbs[1] = high;
        } else {
            _limbs.resize(1);
            _limbs[0] = low;
        }
    }

    CBigNum CBigNum::fromBigEndian(SReadOnlyByteSpan bytes) {
        CBigNum result;
        if (bytes.empty()) {
            return result;
        }

        size_t n = bytes.size;
        size_t limbCount = (n + 3) / 4;
        result._limbs.resize(limbCount);

        size_t bytePos = n;
        for (size_t li = 0; li < limbCount; ++li) {
            uint32_t limb = 0;

            for (size_t b = 0; b < 4 && bytePos > 0; ++b) {
                --bytePos;
                limb |= uint32_t(bytes.data[bytePos]) << (8 * b);
            }

            result._limbs[li] = limb;
        }

        return fromLimbsTrimmed(std::move(result._limbs));
    }

    CBigNum CBigNum::fromLittleEndian(SReadOnlyByteSpan bytes) {
        CBuffer reversed(bytes.data, bytes.size);
        reverseBytesInPlace(reversed.toSpan());
        return fromBigEndian(reversed.toSpan());
    }

    CBigNum CBigNum::fromBigEndianTruncated(SReadOnlyByteSpan bytes, size_t bitsN) {
        size_t outlenBits = bytes.size * 8;
        if (outlenBits <= bitsN) {
            // FIPS 186-4 keeps min(N, outlen) bits, so a digest no longer than N is used whole.
            return fromBigEndian(bytes);
        }

        size_t bytesN = (bitsN + 7) / 8;
        SReadOnlyByteSpan truncated = bytes.size > bytesN ? bytes.slice(0, bytesN) : bytes;

        CBigNum value = fromBigEndian(truncated);

        // --> A whole-byte slice keeps 8*size bits, but FIPS 186-4 4.6/6.4 asks for exactly the
        // leftmost bitsN, so for a subgroup order that isn't byte-aligned the surplus low bits
        // have to be shifted out. That is every binary curve except K-233 and B-571 (e.g. N=163
        // for B-163/K-163 keeps 168 bits, 5 too many). Omitting the shift is self-consistent --
        // this library's own sign() and verify() still agree with each other -- but agrees with
        // no conforming implementation, so it silently breaks interoperability both ways.
        size_t keptBits = truncated.size * 8;
        if (keptBits > bitsN) {
            value.shr(keptBits - bitsN);
        }

        return value;
    }

    bool CBigNum::fromHex(const char* hex, CBigNum& out) {
        TArray<uint8_t> bytes;
        if (!CHex::decode(hex, bytes)) {
            return false;
        }

        out = fromBigEndian(SReadOnlyByteSpan(bytes.begin(), bytes.size()));
        return true;
    }

    void CBigNum::toBigEndian(TArray<uint8_t>& out) const {
        if (_limbs.empty()) {
            out.resize(1);
            out[0] = 0;
            return;
        }

        size_t limbCount = _limbs.size();
        size_t totalBytes = limbCount * 4;

        CBuffer tmp(totalBytes);
        uint8_t* tmpPtr = tmp.toPtr();

        for (size_t li = 0; li < limbCount; ++li) {
            uint32_t limb = _limbs[li];
            size_t base = totalBytes - (li + 1) * 4;

            tmpPtr[base + 0] = uint8_t(limb >> 24);
            tmpPtr[base + 1] = uint8_t(limb >> 16);
            tmpPtr[base + 2] = uint8_t(limb >> 8);
            tmpPtr[base + 3] = uint8_t(limb);
        }

        size_t start = 0;
        while (start + 1 < totalBytes && tmpPtr[start] == 0) {
            ++start;
        }

        size_t n = totalBytes - start;
        out.resize(n);
        std::memcpy(out.begin(), tmpPtr + start, n);
    }

    bool CBigNum::toBigEndian(const SByteSpan& out) const {
        TArray<uint8_t> minimal;
        toBigEndian(minimal);

        if (minimal.size() > out.size) {
            return false;
        }

        size_t pad = out.size - minimal.size();
        std::memset(out.data, 0, pad);
        std::memcpy(out.data + pad, minimal.begin(), minimal.size());

        return true;
    }

    bool CBigNum::toLittleEndian(const SByteSpan& out) const {
        if (!toBigEndian(out)) {
            return false;
        }

        reverseBytesInPlace(out);
        return true;
    }

    bool CBigNum::isZero() const {
        return _limbs.empty();
    }

    bool CBigNum::isEven() const {
        return _limbs.empty() || (_limbs[0] & 1u) == 0;
    }

    bool CBigNum::testBit(size_t index) const {
        size_t limbIdx = index / 32;
        if (limbIdx >= _limbs.size()) {
            return false;
        }

        return (_limbs[limbIdx] >> (index % 32)) & 1u;
    }

    void CBigNum::setBit(size_t index) {
        size_t limbIdx = index / 32;
        if (limbIdx >= _limbs.size()) {
            _limbs.resize(limbIdx + 1);
        }

        _limbs[limbIdx] |= (1u << (index % 32));
    }

    size_t CBigNum::bitLength() const {
        if (_limbs.empty()) {
            return 0;
        }

        size_t top = _limbs.size() - 1;
        uint32_t v = _limbs[top];

        size_t bits = top * 32;
        while (v) {
            ++bits;
            v >>= 1;
        }

        return bits;
    }

    int32_t CBigNum::compare(const CBigNum& other) const {
        if (_limbs.size() != other._limbs.size()) {
            return _limbs.size() < other._limbs.size() ? -1 : 1;
        }

        for (size_t i = _limbs.size(); i-- > 0; ) {
            if (_limbs[i] != other._limbs[i]) {
                return _limbs[i] < other._limbs[i] ? -1 : 1;
            }
        }

        return 0;
    }

    CBigNum& CBigNum::add(const CBigNum& other) {
        size_t n = _limbs.size() > other._limbs.size() ? _limbs.size() : other._limbs.size();

        TArray<uint32_t> result;
        result.resize(n + 1);

        uint64_t carry = 0;
        for (size_t i = 0; i < n; ++i) {
            uint64_t av = i < _limbs.size() ? _limbs[i] : 0;
            uint64_t bv = i < other._limbs.size() ? other._limbs[i] : 0;
            uint64_t t = av + bv + carry;

            result[i] = uint32_t(t);
            carry = t >> 32;
        }

        result[n] = uint32_t(carry);

        *this = fromLimbsTrimmed(std::move(result));
        return *this;
    }

    CBigNum& CBigNum::sub(const CBigNum& other) {
        TArray<uint32_t> result;
        result.resize(_limbs.size());

        int64_t borrow = 0;
        for (size_t i = 0; i < _limbs.size(); ++i) {
            int64_t av = _limbs[i];
            int64_t bv = i < other._limbs.size() ? other._limbs[i] : 0;
            int64_t t = av - bv - borrow;

            if (t < 0) {
                t += (int64_t(1) << 32);
                borrow = 1;
            } else {
                borrow = 0;
            }

            result[i] = uint32_t(t);
        }

        *this = fromLimbsTrimmed(std::move(result));
        return *this;
    }

    CBigNum& CBigNum::mul(const CBigNum& other) {
        if (_limbs.empty() || other._limbs.empty()) {
            *this = CBigNum();
            return *this;
        }

        TArray<uint32_t> result;
        result.resize(_limbs.size() + other._limbs.size());

#if defined(CERTPP_BIGNUM_HWACCEL_AVAILABLE)
        if (hasAdxBmi2()) {
            mulAccelerated(_limbs.begin(), _limbs.size(), other._limbs.begin(), other._limbs.size(),
                result.begin(), result.size());
        } else
#endif
        {
            for (size_t i = 0; i < _limbs.size(); ++i) {
                uint64_t carry = 0;
                uint64_t ai = _limbs[i];

                for (size_t j = 0; j < other._limbs.size(); ++j) {
                    uint64_t t = ai * uint64_t(other._limbs[j]) + result[i + j] + carry;
                    result[i + j] = uint32_t(t);
                    carry = t >> 32;
                }

                result[i + other._limbs.size()] += uint32_t(carry);
            }
        }

        *this = fromLimbsTrimmed(std::move(result));
        return *this;
    }

    void CBigNum::divMod(const CBigNum& divisor, CBigNum& outQuotient, CBigNum& outRemainder) const {
        if (divisor.isZero()) {
            outQuotient = CBigNum();
            outRemainder = CBigNum();
            return;
        }

        size_t dividendBits = bitLength();
        size_t divisorLimbCount = divisor._limbs.size();
        size_t bufLen = divisorLimbCount + 1;

        TArray<uint32_t> rem;
        rem.resize(bufLen);

        TArray<uint32_t> divBuf;
        divBuf.resize(bufLen);
        std::memcpy(divBuf.begin(), divisor._limbs.begin(), divisorLimbCount * sizeof(uint32_t));

        size_t quotLimbCount = dividendBits ? (dividendBits + 31) / 32 : 1;
        TArray<uint32_t> quot;
        quot.resize(quotLimbCount);

        for (size_t i = dividendBits; i-- > 0; ) {
            shiftLeft1(rem.begin(), bufLen);
            if (testBit(i)) {
                rem[0] |= 1u;
            }

            if (compareLimbs(rem.begin(), divBuf.begin(), bufLen) >= 0) {
                subtractLimbs(rem.begin(), divBuf.begin(), bufLen);
                quot[i / 32] |= (1u << (i % 32));
            }
        }

        outQuotient = fromLimbsTrimmed(std::move(quot));
        outRemainder = fromLimbsTrimmed(std::move(rem));
    }

    CBigNum& CBigNum::mod(const CBigNum& modulus) {
        CBigNum q, r;
        divMod(modulus, q, r);
        *this = std::move(r);
        return *this;
    }

    CBigNum& CBigNum::mulMod(const CBigNum& other, const CBigNum& modulus) {
        mul(other);
        mod(modulus);
        return *this;
    }

    CBigNum& CBigNum::modSub(const CBigNum& other, const CBigNum& modulus) {
        CBigNum aa(*this);
        aa.mod(modulus);

        CBigNum bb(other);
        bb.mod(modulus);

        if (aa >= bb) {
            aa.sub(bb);
        } else {
            CBigNum diff(bb);
            diff.sub(aa);
            aa = modulus;
            aa.sub(diff);
        }

        *this = std::move(aa);
        return *this;
    }

    CBigNum& CBigNum::modNeg(const CBigNum& modulus) {
        CBigNum aa(*this);
        aa.mod(modulus);

        if (!aa.isZero()) {
            CBigNum m(modulus);
            m.sub(aa);
            aa = std::move(m);
        }

        *this = std::move(aa);
        return *this;
    }

    CBigNum& CBigNum::shl(size_t bits) {
        if (_limbs.empty() || bits == 0) {
            return *this;
        }

        size_t limbShift = bits / 32;
        size_t bitShift = bits % 32;

        TArray<uint32_t> result;
        result.resize(_limbs.size() + limbShift + 1);

        for (size_t i = 0; i < _limbs.size(); ++i) {
            uint64_t v = uint64_t(_limbs[i]) << bitShift;
            result[i + limbShift] |= uint32_t(v);
            result[i + limbShift + 1] |= uint32_t(v >> 32);
        }

        *this = fromLimbsTrimmed(std::move(result));
        return *this;
    }

    CBigNum& CBigNum::shr(size_t bits) {
        if (_limbs.empty()) {
            return *this;
        }

        size_t limbShift = bits / 32;
        size_t bitShift = bits % 32;

        if (limbShift >= _limbs.size()) {
            *this = CBigNum();
            return *this;
        }

        size_t n = _limbs.size() - limbShift;
        TArray<uint32_t> result;
        result.resize(n);

        for (size_t i = 0; i < n; ++i) {
            uint64_t v = uint64_t(_limbs[i + limbShift]);
            if (i + limbShift + 1 < _limbs.size()) {
                v |= uint64_t(_limbs[i + limbShift + 1]) << 32;
            }

            result[i] = uint32_t(v >> bitShift);
        }

        *this = fromLimbsTrimmed(std::move(result));
        return *this;
    }

    CBigNum CBigNum::gcd(CBigNum a, CBigNum b) {
        while (!b.isZero()) {
            CBigNum q, r;
            a.divMod(b, q, r);

            a = std::move(b);
            b = std::move(r);
        }

        return a;
    }

    bool CBigNum::modInverse(const CBigNum& value, const CBigNum& modulus, CBigNum& out) {
        if (modulus.isZero()) {
            return false;
        }

        CBigNum a(value);
        a.mod(modulus);
        if (a.isZero()) {
            return false;
        }

        CBigNum oldR = a;
        CBigNum r = modulus;
        SignedBig oldS{ CBigNum(uint64_t(1)), false };
        SignedBig s{ CBigNum(uint64_t(0)), false };

        while (!r.isZero()) {
            CBigNum q, rem;
            oldR.divMod(r, q, rem);

            CBigNum newR = std::move(rem);
            oldR = std::move(r);
            r = std::move(newR);

            SignedBig newS = signedSub(oldS, signedMul(q, s));
            oldS = s;
            s = std::move(newS);
        }

        if (oldR != CBigNum(uint64_t(1))) {
            return false;
        }

        CBigNum mag(oldS.mag);
        mag.mod(modulus);

        if (oldS.neg && !mag.isZero()) {
            CBigNum negated(modulus);
            negated.sub(mag);
            out = std::move(negated);
        } else {
            out = std::move(mag);
        }

        return true;
    }

    CBigNum CBigNum::modExp(const CBigNum& base, const CBigNum& exponent, const CBigNum& modulus) {
        if (modulus.isZero()) {
            return CBigNum();
        }

        CBigNum result(uint64_t(1));
        result.mod(modulus);

        CBigNum b(base);
        b.mod(modulus);

        size_t bits = exponent.bitLength();
        for (size_t i = 0; i < bits; ++i) {
            if (exponent.testBit(i)) {
                result.mulMod(b, modulus);
            }

            b.mulMod(b, modulus);
        }

        return result;
    }

    void CBigNum::condSwap(bool swap, CBigNum& a, CBigNum& b) {
        if (swap) {
            std::swap(a, b);
        }
    }

    bool CBigNum::random(size_t bits, CBigNum& out) {
        if (bits == 0) {
            out = CBigNum();
            return true;
        }

        size_t bytes = (bits + 7) / 8;
        CBuffer buf(bytes);

        if (crypto::CRng::fill(buf.toSpan()) != ERET_OK) {
            return false;
        }

        size_t extraBits = bytes * 8 - bits;
        if (extraBits) {
            uint8_t* p = buf.toPtr();
            p[0] = uint8_t(p[0] & (0xFFu >> extraBits));
        }

        out = CBigNum::fromBigEndian(buf.toSpan());
        return true;
    }

    bool CBigNum::randomBelow(const CBigNum& bound, CBigNum& out) {
        if (bound.isZero()) {
            return false;
        }

        size_t bits = bound.bitLength();
        for (size_t attempt = 0; attempt < 1000; ++attempt) {
            CBigNum candidate;
            if (!random(bits, candidate)) {
                return false;
            }

            if (candidate < bound) {
                out = candidate;
                return true;
            }
        }

        return false;
    }

    bool CBigNum::isProbablePrime(size_t rounds) const {
        /* Small primes below 1000, used to reject obvious composites without paying for a full
         * Miller-Rabin round. */
        static constexpr uint32_t SMALL_PRIMES[] = {
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277,
            281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
            397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
            503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
            619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
            743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
            863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991,
            997
        };

        if (compare(CBigNum(uint64_t(2))) < 0) {
            return false;
        }

        for (uint32_t p : SMALL_PRIMES) {
            CBigNum sp{ uint64_t(p) };

            if (*this == sp) {
                return true;
            }

            CBigNum r0(*this);
            r0.mod(sp);
            if (r0.isZero()) {
                return false;
            }
        }

        CBigNum nMinus1(*this);
        nMinus1.sub(CBigNum(uint64_t(1)));

        CBigNum d(nMinus1);
        size_t r = 0;

        while (d.isEven()) {
            d.shr(1);
            ++r;
        }

        CBigNum nMinus3(nMinus1);
        nMinus3.sub(CBigNum(uint64_t(2)));

        for (size_t i = 0; i < rounds; ++i) {
            CBigNum witness;
            if (!randomBelow(nMinus3, witness)) {
                return false;
            }

            witness.add(CBigNum(uint64_t(2)));

            CBigNum x = modExp(witness, d, *this);
            if (x == CBigNum(uint64_t(1)) || x == nMinus1) {
                continue;
            }

            bool composite = true;
            for (size_t j = 1; j < r; ++j) {
                x.mulMod(x, *this);
                if (x == nMinus1) {
                    composite = false;
                    break;
                }
            }

            if (composite) {
                return false;
            }
        }

        return true;
    }

    bool CBigNum::generatePrime(size_t bits, CBigNum& out) {
        if (bits < 2) {
            return false;
        }

        constexpr size_t MAX_ATTEMPTS = 100000;
        for (size_t attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
            CBigNum candidate;
            if (!random(bits, candidate)) {
                return false;
            }

            candidate.setBit(bits - 1);
            candidate.setBit(bits - 2);
            candidate.setBit(0);

            if (candidate.isProbablePrime()) {
                out = candidate;
                return true;
            }
        }

        return false;
    }

} // namespace certpp
