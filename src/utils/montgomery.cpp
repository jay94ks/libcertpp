#include <certpp/utils/montgomery.hpp>
#include <cstring>
#include <utility>

#if defined(__clang__) && (defined(__x86_64__) || defined(_M_X64))
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {

#if defined(__clang__) && defined(__SIZEOF_INT128__) && \
    (defined(__x86_64__) || defined(_M_X64))
    namespace {

        /* Fixed-width 64-bit integrated CIOS multiplication for an already-packed Montgomery
         * chain. Product and reduction carries advance together, so each accumulator digit is read
         * once instead of being written by a product pass and read again by a reduction pass.
         * Keeping operands packed across repeated squares also avoids converting every intermediate
         * through CBigNum's 32-bit storage. out may alias either input; scratch holds count+2 digits. */
        template<bool Accelerated, size_t FixedCount = 0>
#if defined(__clang__)
        __attribute__((always_inline))
#endif
        inline void mulWideChainBody(
            const uint64_t* a, const uint64_t* b, const uint64_t* modulus,
            size_t count, uint64_t n0inv, uint64_t* out, uint64_t* scratch
        ) {
            (void)Accelerated;
            using Wide = unsigned __int128;
            const size_t digitCount = FixedCount == 0 ? count : FixedCount;
            std::memset(scratch, 0, (digitCount + 2) * sizeof(uint64_t));

            for (size_t i = 0; i < digitCount; ++i) {
                const uint64_t bi = b[i];
                Wide product = Wide(scratch[0]) + Wide(a[0]) * bi;
                uint64_t productDigit = uint64_t(product);
                Wide productCarry = product >> 64;

                const uint64_t multiplier = productDigit * n0inv;
                Wide reduction = Wide(productDigit) + Wide(multiplier) * modulus[0];
                Wide reductionCarry = reduction >> 64;

#if defined(__clang__)
#pragma clang loop unroll_count(32)
#endif
                for (size_t j = 1; j < digitCount; ++j) {
                    product = Wide(scratch[j]) + Wide(a[j]) * bi + productCarry;
                    productDigit = uint64_t(product);
                    productCarry = product >> 64;

                    reduction = Wide(productDigit)
                        + Wide(multiplier) * modulus[j] + reductionCarry;
                    scratch[j - 1] = uint64_t(reduction);
                    reductionCarry = reduction >> 64;
                }

                const Wide productTop = Wide(scratch[digitCount]) + productCarry;
                const Wide reductionTop = Wide(uint64_t(productTop)) + reductionCarry;
                scratch[digitCount - 1] = uint64_t(reductionTop);
                scratch[digitCount] = uint64_t(productTop >> 64)
                    + uint64_t(reductionTop >> 64);
            }

            auto compare = [digitCount](const uint64_t* lhs, const uint64_t* rhs) {
                for (size_t i = digitCount; i-- > 0; ) {
                    if (lhs[i] != rhs[i]) {
                        return lhs[i] < rhs[i] ? -1 : 1;
                    }
                }
                return 0;
            };

            while (scratch[digitCount] != 0 || compare(scratch, modulus) >= 0) {
                uint64_t borrow = 0;
                for (size_t i = 0; i < digitCount; ++i) {
                    const uint64_t first = scratch[i] - modulus[i];
                    const uint64_t borrow1 = scratch[i] < modulus[i];
                    const uint64_t second = first - borrow;
                    const uint64_t borrow2 = first < borrow;
                    scratch[i] = second;
                    borrow = borrow1 | borrow2;
                }
                scratch[digitCount] -= borrow;
            }

            std::memcpy(out, scratch, digitCount * sizeof(uint64_t));
        }

        using MulWideChain = void(*)(
            const uint64_t*, const uint64_t*, const uint64_t*, size_t,
            uint64_t, uint64_t*, uint64_t*);

        void mulWideChainPortable(
            const uint64_t* a, const uint64_t* b, const uint64_t* modulus,
            size_t count, uint64_t n0inv, uint64_t* out, uint64_t* scratch
        ) {
            mulWideChainBody<false>(a, b, modulus, count, n0inv, out, scratch);
        }

        template<size_t Count>
        void mulWideChainPortableFixed(
            const uint64_t* a, const uint64_t* b, const uint64_t* modulus,
            size_t count, uint64_t n0inv, uint64_t* out, uint64_t* scratch
        ) {
            mulWideChainBody<false, Count>(
                a, b, modulus, count, n0inv, out, scratch);
        }

#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && defined(__clang__)
        bool hasAdxBmi2Montgomery() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuid(info, 0);
                if (info[0] < 7) {
                    return false;
                }
                __cpuidex(info, 7, 0);
                return ((info[1] & (1 << 8)) != 0)
                    && ((info[1] & (1 << 19)) != 0);
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return ((ebx & (1u << 8)) != 0)
                    && ((ebx & (1u << 19)) != 0);
#endif
            }();
            return supported;
        }

        __attribute__((target("bmi2,adx")))
        void mulWideChainAccelerated(
            const uint64_t* a, const uint64_t* b, const uint64_t* modulus,
            size_t count, uint64_t n0inv, uint64_t* out, uint64_t* scratch
        ) {
            mulWideChainBody<true>(a, b, modulus, count, n0inv, out, scratch);
        }

        template<size_t Count>
        __attribute__((target("bmi2,adx")))
        void mulWideChainAcceleratedFixed(
            const uint64_t* a, const uint64_t* b, const uint64_t* modulus,
            size_t count, uint64_t n0inv, uint64_t* out, uint64_t* scratch
        ) {
            mulWideChainBody<true, Count>(
                a, b, modulus, count, n0inv, out, scratch);
        }

#if !defined(CERTPP_DISABLE_HWACCEL_AVX512)
        bool hasTigerLakeMontgomery() {
            static const bool supported = [] {
                __builtin_cpu_init();
                return __builtin_cpu_is("tigerlake") != 0;
            }();
            return supported;
        }

        __attribute__((target("arch=tigerlake")))
        void mulWideChainTigerLake(
            const uint64_t* a, const uint64_t* b, const uint64_t* modulus,
            size_t count, uint64_t n0inv, uint64_t* out, uint64_t* scratch
        ) {
            mulWideChainBody<true>(a, b, modulus, count, n0inv, out, scratch);
        }

        template<size_t Count>
        __attribute__((target("arch=tigerlake")))
        void mulWideChainTigerLakeFixed(
            const uint64_t* a, const uint64_t* b, const uint64_t* modulus,
            size_t count, uint64_t n0inv, uint64_t* out, uint64_t* scratch
        ) {
            mulWideChainBody<true, Count>(
                a, b, modulus, count, n0inv, out, scratch);
        }

#endif
#endif

        MulWideChain selectMulWideChain(size_t count) {
            MulWideChain multiply = mulWideChainPortable;
            if (count == 16) {
                multiply = mulWideChainPortableFixed<16>;
            } else if (count == 32) {
                multiply = mulWideChainPortableFixed<32>;
            }
#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && defined(__clang__)
            if (hasAdxBmi2Montgomery()) {
                multiply = mulWideChainAccelerated;
                if (count == 16) {
                    multiply = mulWideChainAcceleratedFixed<16>;
                } else if (count == 32) {
                    multiply = mulWideChainAcceleratedFixed<32>;
                }
            }
#if !defined(CERTPP_DISABLE_HWACCEL_AVX512)
            if (hasTigerLakeMontgomery()) {
                multiply = mulWideChainTigerLake;
                if (count == 16) {
                    multiply = mulWideChainTigerLakeFixed<16>;
                } else if (count == 32) {
                    multiply = mulWideChainTigerLakeFixed<32>;
                }
            }
#endif
#endif
            return multiply;
        }

    } // namespace
#endif

    /* Computes -value^-1 mod 2^32 by Newton's iteration. */
    uint32_t CMontgomery::negInverse32(uint32_t value) {
        // --> x_{k+1} = x_k * (2 - value*x_k) doubles the number of correct low bits each step.
        // Seeding with x_0 = value is already correct to 3 bits (value*value == 1 mod 8 holds for
        // every odd value), so 3 -> 6 -> 12 -> 24 -> 48 bits: four steps cover all 32, and the
        // fifth is pure insurance. All arithmetic is deliberately mod 2^32 (uint32_t wraparound).
        uint32_t x = value;

        for (size_t i = 0; i < 5; ++i) {
            x = uint32_t(x * uint32_t(2u - value * x));
        }

        return uint32_t(0u - x);
    }

    /* Copies value's limbs into a count-limb buffer, zero-extending past its length. */
    void CMontgomery::load(uint32_t* dst, size_t count, const CBigNum& value) {
        const size_t have = value._limbs.size() < count ? value._limbs.size() : count;

        if (have) {
            std::memcpy(dst, value._limbs.begin(), have * sizeof(uint32_t));
        }

        if (have < count) {
            std::memset(dst + have, 0, (count - have) * sizeof(uint32_t));
        }
    }

    /* Writes a raw little-endian limb buffer back into a CBigNum, trimming leading zeroes. */
    void CMontgomery::store(CBigNum& out, const uint32_t* src, size_t count) {
        size_t n = count;
        while (n > 0 && src[n - 1] == 0) {
            --n;
        }

        // --> TArray::resize() never shrinks the allocation, so a CBigNum that has already held a
        // field element keeps its buffer and this is allocation-free from the second use onward.
        if (!out._limbs.resize(n)) {
            out = CBigNum();
            return;
        }

        if (n) {
            std::memcpy(out._limbs.begin(), src, n * sizeof(uint32_t));
        }
    }

    /* Whether value needs reducing before it can be fed to mulInternal(). */
    bool CMontgomery::needsReduce(const CBigNum& value) const {
        return value._limbs.size() > _count || value.compare(_m) >= 0;
    }

    /* CIOS Montgomery multiplication: out = a*b*R^-1 mod m. */
    void CMontgomery::mulInternal(
        const uint32_t* a, size_t aLen, const uint32_t* b, size_t bLen, CBigNum& out
    ) const {
#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        mulInternal64(a, aLen, b, bLen, out);
        return;
#endif
        const size_t s = _count;
        const uint32_t* n = _m._limbs.begin();

        // --> The accumulator needs s+2 limbs: s for the running product, one for the carry out of
        // the multiply pass, and one more for the carry out of that (t[s+1], always 0 or 1).
        uint32_t stackBuf[STACK_LIMBS + 2];
        TArray<uint32_t> heapBuf;
        uint32_t* t = stackBuf;

        if (s + 2 > STACK_LIMBS + 2) {
            if (!heapBuf.resize(s + 2)) {
                out = CBigNum();
                return;
            }

            t = heapBuf.begin();
        }

        std::memset(t, 0, (s + 2) * sizeof(uint32_t));

        for (size_t i = 0; i < s; ++i) {
            const uint64_t bi = i < bLen ? uint64_t(b[i]) : 0;

            // --> Multiply pass: t += a * b[i]. Every term fits a uint64_t exactly --
            // (2^32-1) + (2^32-1)^2 + (2^32-1) == 2^64-1 -- so no intermediate can overflow.
            uint64_t carry = 0;
            for (size_t j = 0; j < s; ++j) {
                const uint64_t aj = j < aLen ? uint64_t(a[j]) : 0;
                const uint64_t acc = uint64_t(t[j]) + aj * bi + carry;

                t[j] = uint32_t(acc);
                carry = acc >> 32;
            }

            uint64_t acc = uint64_t(t[s]) + carry;
            t[s] = uint32_t(acc);
            t[s + 1] = uint32_t(acc >> 32);

            // --> Reduction pass: add the unique multiple of m that clears t[0], then shift down by
            // one limb (which is what dividing by 2^32 amounts to, and why the result comes out
            // multiplied by R^-1 rather than needing a division to get there).
            const uint32_t mi = uint32_t(uint64_t(t[0]) * uint64_t(_n0inv));

            carry = (uint64_t(t[0]) + uint64_t(mi) * uint64_t(n[0])) >> 32;

            for (size_t j = 1; j < s; ++j) {
                const uint64_t red = uint64_t(t[j]) + uint64_t(mi) * uint64_t(n[j]) + carry;

                t[j - 1] = uint32_t(red);
                carry = red >> 32;
            }

            acc = uint64_t(t[s]) + carry;
            t[s - 1] = uint32_t(acc);
            t[s] = uint32_t(uint64_t(t[s + 1]) + (acc >> 32));
        }

        // --> Both operands were below m, so the accumulator is now below 2m and exactly one
        // subtraction can be needed. Writing it as a loop (rather than a single `if`) makes that a
        // property of the arithmetic instead of an assumption about it: it is correct for any
        // accumulator, and simply never runs more than once for the inputs this can be given.
        // compareLimbs() has to be consulted *before* each subtraction, not after: it is also what
        // says whether that subtraction borrows out of t[s], which subtractLimbs() (working over s
        // limbs only) does not report.
        for (;;) {
            const int cmp = CBigNum::compareLimbs(t, n, s);
            if (t[s] == 0 && cmp < 0) {
                break;
            }

            CBigNum::subtractLimbs(t, n, s);

            if (cmp < 0) {
                --t[s];
            }
        }

        store(out, t, s);
    }

#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
    /* The same integrated CIOS recurrence over 64-bit digits. A 128-bit temporary holds one full
     * product plus the accumulator digit and carry exactly, cutting an n-limb multiplication from
     * n^2 32-bit products to ceil(n/2)^2 native products. Product and reduction carries advance in
     * the same digit loop to avoid a second pass over the accumulator. */
    void CMontgomery::mulInternal64(
        const uint32_t* a, size_t aLen, const uint32_t* b, size_t bLen, CBigNum& out
    ) const {
        using Wide = unsigned __int128;
        const size_t s = _wideCount;
        constexpr size_t STACK_DIGITS = (STACK_LIMBS + 1) / 2;
        uint64_t aStack[STACK_DIGITS], bStack[STACK_DIGITS];
        uint64_t tStack[STACK_DIGITS + 2];
        TArray<uint64_t> heap;
        uint64_t* a64 = aStack;
        uint64_t* b64 = bStack;
        uint64_t* t = tStack;
        if (s > STACK_DIGITS) {
            if (!heap.resize(3 * s + 2)) {
                out = CBigNum();
                return;
            }
            a64 = heap.begin();
            b64 = a64 + s;
            t = b64 + s;
        }

        auto pack = [](const uint32_t* src, size_t len, uint64_t* dst, size_t count) {
            for (size_t i = 0; i < count; ++i) {
                const size_t lo = 2 * i;
                uint64_t value = lo < len ? uint64_t(src[lo]) : 0;
                if (lo + 1 < len) {
                    value |= uint64_t(src[lo + 1]) << 32;
                }
                dst[i] = value;
            }
        };
        pack(a, aLen, a64, s);
        pack(b, bLen, b64, s);
        std::memset(t, 0, (s + 2) * sizeof(uint64_t));
        const uint64_t* n64 = _modulus64.begin();

        for (size_t i = 0; i < s; ++i) {
            const uint64_t bi = b64[i];
            Wide product = Wide(t[0]) + Wide(a64[0]) * bi;
            uint64_t productDigit = uint64_t(product);
            Wide productCarry = product >> 64;

            const uint64_t multiplier = productDigit * _n0inv64;
            Wide reduction = Wide(productDigit) + Wide(multiplier) * n64[0];
            Wide reductionCarry = reduction >> 64;

            for (size_t j = 1; j < s; ++j) {
                product = Wide(t[j]) + Wide(a64[j]) * bi + productCarry;
                productDigit = uint64_t(product);
                productCarry = product >> 64;

                reduction = Wide(productDigit)
                    + Wide(multiplier) * n64[j] + reductionCarry;
                t[j - 1] = uint64_t(reduction);
                reductionCarry = reduction >> 64;
            }

            const Wide productTop = Wide(t[s]) + productCarry;
            const Wide reductionTop = Wide(uint64_t(productTop)) + reductionCarry;
            t[s - 1] = uint64_t(reductionTop);
            t[s] = uint64_t(productTop >> 64) + uint64_t(reductionTop >> 64);
        }

        auto compare = [s](const uint64_t* lhs, const uint64_t* rhs) {
            for (size_t i = s; i-- > 0; ) {
                if (lhs[i] != rhs[i]) {
                    return lhs[i] < rhs[i] ? -1 : 1;
                }
            }
            return 0;
        };
        while (t[s] != 0 || compare(t, n64) >= 0) {
            uint64_t borrow = 0;
            for (size_t i = 0; i < s; ++i) {
                const uint64_t first = t[i] - n64[i];
                const uint64_t borrow1 = t[i] < n64[i];
                const uint64_t second = first - borrow;
                const uint64_t borrow2 = first < borrow;
                t[i] = second;
                borrow = borrow1 | borrow2;
            }
            t[s] -= borrow;
        }

        uint32_t limbs[STACK_LIMBS + 2];
        TArray<uint32_t> heapLimbs;
        uint32_t* result = limbs;
        if (2 * s > STACK_LIMBS + 2) {
            if (!heapLimbs.resize(2 * s)) {
                out = CBigNum();
                return;
            }
            result = heapLimbs.begin();
        }
        for (size_t i = 0; i < s; ++i) {
            result[2 * i] = uint32_t(t[i]);
            result[2 * i + 1] = uint32_t(t[i] >> 32);
        }
        store(out, result, 2 * s);
    }
#endif

    CMontgomery::CMontgomery()
        : _count(0), _n0inv(0), _wideCount(0), _n0inv64(0), _valid(false)
    {
    }

    CMontgomery::CMontgomery(const CBigNum& modulus)
        : _count(0), _n0inv(0), _wideCount(0), _n0inv64(0), _valid(false)
    {
        // --> Montgomery reduction needs R == 2^(32*limbs) to be coprime to m, which for a power of
        // two means exactly "m is odd". An even (or zero) modulus has no n' at all, so there is
        // nothing to fall back to here -- the instance stays invalid and every operation becomes a
        // no-op, leaving the caller to use CBigNum::mod()/mulMod() instead.
        if (modulus.isZero() || modulus.isEven()) {
            return;
        }

        _m = modulus;
        _count = _m._limbs.size();
        _n0inv = negInverse32(_m._limbs[0]);
        _wideCount = (_count + 1) / 2;
        if (!_modulus64.resize(_wideCount)) {
            _m = CBigNum();
            _count = 0;
            _wideCount = 0;
            return;
        }
        for (size_t i = 0; i < _wideCount; ++i) {
            const size_t lo = 2 * i;
            _modulus64[i] = uint64_t(_m._limbs[lo]);
            if (lo + 1 < _count) {
                _modulus64[i] |= uint64_t(_m._limbs[lo + 1]) << 32;
            }
        }
        uint64_t inverse64 = _modulus64[0];
        for (size_t i = 0; i < 6; ++i) {
            inverse64 *= uint64_t(2) - _modulus64[0] * inverse64;
        }
        _n0inv64 = uint64_t(0) - inverse64;

        // --> Sanity check on the Newton iteration rather than trusting it: n' * m[0] must be -1
        // mod 2^32. Cheap, and it runs once per context instead of once per multiply.
        if (uint32_t(_n0inv * _m._limbs[0]) != uint32_t(0u - 1u)) {
            _m = CBigNum();
            _count = 0;
            _n0inv = 0;
            _modulus64.clear();
            _wideCount = 0;
            _n0inv64 = 0;
            return;
        }

        // --> R^2 mod m and R mod m are the only two places a long division happens, and they
        // happen once, here -- which is the whole trade this class makes.
        _rr = CBigNum(uint64_t(1));
#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        const size_t wideCount = (_count + 1) / 2;
        _rr.shl(128 * wideCount);
#else
        _rr.shl(64 * _count);
#endif
        _rr.mod(_m);

        _one = CBigNum(uint64_t(1));
#if defined(__SIZEOF_INT128__) && (defined(__x86_64__) || defined(_M_X64))
        _one.shl(64 * wideCount);
#else
        _one.shl(32 * _count);
#endif
        _one.mod(_m);

        _valid = true;
    }

    /* Whether this context was built from a non-zero, odd modulus. */
    bool CMontgomery::isValid() const {
        return _valid;
    }

    /* The modulus this context was built from. */
    const CBigNum& CMontgomery::modulus() const {
        return _m;
    }

    /* The Montgomery form of 1 (R mod m). */
    const CBigNum& CMontgomery::one() const {
        return _one;
    }

    /* Converts an ordinary residue into Montgomery form (value*R mod m). */
    CBigNum CMontgomery::toMont(const CBigNum& value) const {
        if (!_valid) {
            return value;
        }

        // --> value*R mod m is mulInternal(value, R^2) == value*R^2*R^-1: the one multiplication
        // the precomputed _rr exists for.
        CBigNum result(value);
        if (needsReduce(result)) {
            result.mod(_m);
        }

        mulInternal(
            result._limbs.begin(), result._limbs.size(),
            _rr._limbs.begin(), _rr._limbs.size(), result
        );

        return result;
    }

    /* Converts a Montgomery-form value back to an ordinary residue. */
    CBigNum CMontgomery::fromMont(const CBigNum& value) const {
        if (!_valid) {
            return value;
        }

        CBigNum result(value);
        if (needsReduce(result)) {
            result.mod(_m);
        }

        // --> mulInternal(value, 1) == value*R^-1, i.e. a bare reduction pass.
        const uint32_t oneLimb = 1u;
        mulInternal(result._limbs.begin(), result._limbs.size(), &oneLimb, 1, result);

        return result;
    }

    /* Multiplies two Montgomery-form values, yielding a Montgomery-form product. */
    CBigNum& CMontgomery::mul(CBigNum& acc, const CBigNum& other) const {
        if (!_valid) {
            return acc;
        }

        if (needsReduce(acc)) {
            acc.mod(_m);
        }

        // --> mulInternal() reads only the low _count limbs of each operand, so an out-of-domain
        // `other` has to be reduced into a temporary first. In the Montgomery domain this never
        // fires; it is here so the class is still correct when handed an arbitrary value.
        if (needsReduce(other)) {
            CBigNum reduced(other);
            reduced.mod(_m);

            mulInternal(
                acc._limbs.begin(), acc._limbs.size(),
                reduced._limbs.begin(), reduced._limbs.size(), acc
            );

            return acc;
        }

        // --> acc and other may be the same object (squaring): mulInternal() finishes reading both
        // operands before it writes anything into out, so the aliasing is safe.
        mulInternal(
            acc._limbs.begin(), acc._limbs.size(),
            other._limbs.begin(), other._limbs.size(), acc
        );

        return acc;
    }

    /* Multiplies two ordinary-form values modulo the modulus. */
    CBigNum& CMontgomery::mulMod(CBigNum& acc, const CBigNum& other) const {
        if (!_valid) {
            return acc;
        }

        // --> mulInternal(a*R, b) == a*b: converting just one of the two operands in is enough to
        // land back in ordinary form, so this costs one extra pass over mul(), not two.
        acc = toMont(acc);
        return mul(acc, other);
    }

    /* Adds modulo the modulus. */
    CBigNum& CMontgomery::add(CBigNum& acc, const CBigNum& other) const {
        if (!_valid) {
            return acc;
        }

        if (needsReduce(acc)) {
            acc.mod(_m);
        }

        const size_t s = _count;
        const uint32_t* n = _m._limbs.begin();

        uint32_t stackBuf[STACK_LIMBS + 1];
        TArray<uint32_t> heapBuf;
        uint32_t* t = stackBuf;

        if (s + 1 > STACK_LIMBS + 1) {
            if (!heapBuf.resize(s + 1)) {
                return acc;
            }

            t = heapBuf.begin();
        }

        load(t, s, acc);

        // --> `other` is read through a reduced copy only when it needs one; otherwise its own
        // limbs are read directly, zero-extended past its length. Note that acc's limbs were
        // already copied into t above, so passing acc itself as `other` (see dbl()) is safe.
        CBigNum reduced;
        const CBigNum* rhs = &other;
        if (needsReduce(other)) {
            reduced = other;
            reduced.mod(_m);
            rhs = &reduced;
        }

        const uint32_t* b = rhs->_limbs.begin();
        const size_t bLen = rhs->_limbs.size();

        uint64_t carry = 0;
        for (size_t i = 0; i < s; ++i) {
            const uint64_t sum = uint64_t(t[i]) + (i < bLen ? uint64_t(b[i]) : 0) + carry;

            t[i] = uint32_t(sum);
            carry = sum >> 32;
        }

        t[s] = uint32_t(carry);

        // --> Both addends were below m, so the sum is below 2m: at most one subtraction, and the
        // top limb is implicitly zero afterwards (store() only reads the low s limbs anyway).
        if (t[s] != 0 || CBigNum::compareLimbs(t, n, s) >= 0) {
            CBigNum::subtractLimbs(t, n, s);
        }

        store(acc, t, s);
        return acc;
    }

    /* Subtracts modulo the modulus. */
    CBigNum& CMontgomery::sub(CBigNum& acc, const CBigNum& other) const {
        if (!_valid) {
            return acc;
        }

        if (needsReduce(acc)) {
            acc.mod(_m);
        }

        const size_t s = _count;
        const uint32_t* n = _m._limbs.begin();

        uint32_t stackBuf[STACK_LIMBS];
        TArray<uint32_t> heapBuf;
        uint32_t* t = stackBuf;

        if (s > STACK_LIMBS) {
            if (!heapBuf.resize(s)) {
                return acc;
            }

            t = heapBuf.begin();
        }

        load(t, s, acc);

        CBigNum reduced;
        const CBigNum* rhs = &other;
        if (needsReduce(other)) {
            reduced = other;
            reduced.mod(_m);
            rhs = &reduced;
        }

        const uint32_t* b = rhs->_limbs.begin();
        const size_t bLen = rhs->_limbs.size();

        int64_t borrow = 0;
        for (size_t i = 0; i < s; ++i) {
            int64_t diff = int64_t(t[i]) - int64_t(i < bLen ? b[i] : 0) - borrow;

            if (diff < 0) {
                diff += (int64_t(1) << 32);
                borrow = 1;
            } else {
                borrow = 0;
            }

            t[i] = uint32_t(diff);
        }

        // --> A borrow out of the top limb means the true difference was negative; adding m back
        // once lands it in [0, m), since both operands were already below m.
        if (borrow) {
            uint64_t carry = 0;
            for (size_t i = 0; i < s; ++i) {
                const uint64_t sum = uint64_t(t[i]) + uint64_t(n[i]) + carry;

                t[i] = uint32_t(sum);
                carry = sum >> 32;
            }
        }

        store(acc, t, s);
        return acc;
    }

    /* Doubles modulo the modulus. */
    CBigNum& CMontgomery::dbl(CBigNum& acc) const {
        // --> add() loads acc into its own scratch buffer before it reads the right-hand operand,
        // so passing acc as both arguments is safe.
        return add(acc, acc);
    }

    /* Negates modulo the modulus. */
    CBigNum& CMontgomery::neg(CBigNum& acc) const {
        if (!_valid) {
            return acc;
        }

        if (needsReduce(acc)) {
            acc.mod(_m);
        }

        if (acc.isZero()) {
            return acc;
        }

        CBigNum result(_m);
        result.sub(acc);

        acc = std::move(result);
        return acc;
    }

    /* Modular exponentiation via binary or adaptive sliding-window chains. */
    CBigNum CMontgomery::modExp(const CBigNum& base, const CBigNum& exponent) const {
        if (!_valid) {
            return CBigNum();
        }

        // --> One is the right answer for a zero exponent even when the base is zero, matching
        // CBigNum::modExp(); for m == 1 it then has to be reduced back down to zero.
        if (exponent.isZero()) {
            CBigNum result(uint64_t(1));
            result.mod(_m);
            return result;
        }

        const size_t exponentBits = exponent.bitLength();
        if (exponentBits <= 64) {
            // Tiny public exponents such as RSA's 65537 have only two set bits. Building a window
            // table costs more multiplications than it can save, so keep the direct binary path.
            const CBigNum baseMont = toMont(base);
#if defined(__clang__) && defined(__SIZEOF_INT128__) && \
    (defined(__x86_64__) || defined(_M_X64))
            constexpr size_t STACK_DIGITS = (STACK_LIMBS + 1) / 2;
            uint64_t stack[3 * STACK_DIGITS + STACK_DIGITS + 2];
            TArray<uint64_t> heap;
            uint64_t* packed = stack;
            if (_wideCount > STACK_DIGITS) {
                if (!heap.resize(4 * _wideCount + 2)) {
                    return CBigNum();
                }
                packed = heap.begin();
            }

            uint64_t* baseWide = packed;
            uint64_t* resultWide = baseWide + _wideCount;
            uint64_t* ordinaryOne = resultWide + _wideCount;
            uint64_t* scratch = ordinaryOne + _wideCount;

            auto pack = [this](const CBigNum& value, uint64_t* out) {
                for (size_t i = 0; i < _wideCount; ++i) {
                    const size_t lo = 2 * i;
                    uint64_t digit = lo < value._limbs.size() ? uint64_t(value._limbs[lo]) : 0;
                    if (lo + 1 < value._limbs.size()) {
                        digit |= uint64_t(value._limbs[lo + 1]) << 32;
                    }
                    out[i] = digit;
                }
            };

            pack(baseMont, baseWide);
            std::memcpy(resultWide, baseWide, _wideCount * sizeof(uint64_t));
            std::memset(ordinaryOne, 0, _wideCount * sizeof(uint64_t));
            ordinaryOne[0] = 1;

            const MulWideChain multiply = selectMulWideChain(_wideCount);

            // bitLength() guarantees the top exponent bit is one. Seeding with base consumes that
            // bit directly instead of squaring Montgomery one and multiplying by base first.
            for (size_t i = exponentBits - 1; i-- > 0; ) {
                multiply(resultWide, resultWide, _modulus64.begin(), _wideCount,
                    _n0inv64, resultWide, scratch);
                if (exponent.testBit(i)) {
                    multiply(resultWide, baseWide, _modulus64.begin(), _wideCount,
                        _n0inv64, resultWide, scratch);
                }
            }

            // One final Montgomery reduction returns to the ordinary domain.
            multiply(resultWide, ordinaryOne, _modulus64.begin(), _wideCount,
                _n0inv64, resultWide, scratch);

            CBigNum result;
            if (!result._limbs.resize(2 * _wideCount)) {
                return CBigNum();
            }
            for (size_t i = 0; i < _wideCount; ++i) {
                result._limbs[2 * i] = uint32_t(resultWide[i]);
                result._limbs[2 * i + 1] = uint32_t(resultWide[i] >> 32);
            }
            size_t used = result._limbs.size();
            while (used != 0 && result._limbs[used - 1] == 0) {
                --used;
            }
            result._limbs.resize(used);
            return result;
#else
            CBigNum result(baseMont);
            for (size_t i = exponentBits - 1; i-- > 0; ) {
                mul(result, result);
                if (exponent.testBit(i)) {
                    mul(result, baseMont);
                }
            }
            return fromMont(result);
#endif
        }

        const CBigNum baseMont = toMont(base);

        constexpr size_t MAX_WINDOW = 5;
        constexpr size_t MAX_ODD_POWERS = size_t(1) << (MAX_WINDOW - 1);
        const size_t window = exponentBits > 512 ? size_t(5) : size_t(4);
        const size_t oddPowers = size_t(1) << (window - 1);

#if defined(__clang__) && defined(__SIZEOF_INT128__) && \
    (defined(__x86_64__) || defined(_M_X64))
        // Keep every long-exponent intermediate in the 64-bit format consumed by the CIOS
        // recurrence. Converting each square through CBigNum's 32-bit storage otherwise costs two
        // complete limb walks per multiplication, more than a thousand times for RSA-2048 CRT.
        constexpr size_t STACK_DIGITS = (STACK_LIMBS + 1) / 2;
        uint64_t stack[(MAX_ODD_POWERS + 4) * STACK_DIGITS + 2];
        TArray<uint64_t> heap;
        uint64_t* packed = stack;
        if (_wideCount > STACK_DIGITS) {
            if (!heap.resize((MAX_ODD_POWERS + 4) * _wideCount + 2)) {
                return CBigNum();
            }
            packed = heap.begin();
        }

        uint64_t* table = packed;
        uint64_t* baseSquared = table + MAX_ODD_POWERS * _wideCount;
        uint64_t* resultWide = baseSquared + _wideCount;
        uint64_t* ordinaryOne = resultWide + _wideCount;
        uint64_t* scratch = ordinaryOne + _wideCount;

        auto pack = [this](const CBigNum& value, uint64_t* out) {
            for (size_t i = 0; i < _wideCount; ++i) {
                const size_t lo = 2 * i;
                uint64_t digit = lo < value._limbs.size() ? uint64_t(value._limbs[lo]) : 0;
                if (lo + 1 < value._limbs.size()) {
                    digit |= uint64_t(value._limbs[lo + 1]) << 32;
                }
                out[i] = digit;
            }
        };

        const MulWideChain multiply = selectMulWideChain(_wideCount);

        pack(baseMont, table);
        multiply(table, table, _modulus64.begin(), _wideCount,
            _n0inv64, baseSquared, scratch);
        for (size_t i = 1; i < oddPowers; ++i) {
            multiply(table + (i - 1) * _wideCount, baseSquared,
                _modulus64.begin(), _wideCount, _n0inv64,
                table + i * _wideCount, scratch);
        }

        pack(_one, resultWide);
        size_t cursor = exponentBits;
        while (cursor > 0) {
            const size_t top = cursor - 1;
            if (!exponent.testBit(top)) {
                multiply(resultWide, resultWide, _modulus64.begin(), _wideCount,
                    _n0inv64, resultWide, scratch);
                --cursor;
                continue;
            }

            size_t bottom = cursor > window ? cursor - window : 0;
            while (!exponent.testBit(bottom)) {
                ++bottom;
            }

            size_t value = 0;
            for (size_t bit = cursor; bit-- > bottom; ) {
                value = (value << 1) | size_t(exponent.testBit(bit));
                multiply(resultWide, resultWide, _modulus64.begin(), _wideCount,
                    _n0inv64, resultWide, scratch);
            }
            multiply(resultWide, table + (value >> 1) * _wideCount,
                _modulus64.begin(), _wideCount, _n0inv64, resultWide, scratch);
            cursor = bottom;
        }

        std::memset(ordinaryOne, 0, _wideCount * sizeof(uint64_t));
        ordinaryOne[0] = 1;
        multiply(resultWide, ordinaryOne, _modulus64.begin(), _wideCount,
            _n0inv64, resultWide, scratch);

        CBigNum result;
        if (!result._limbs.resize(2 * _wideCount)) {
            return CBigNum();
        }
        for (size_t i = 0; i < _wideCount; ++i) {
            result._limbs[2 * i] = uint32_t(resultWide[i]);
            result._limbs[2 * i + 1] = uint32_t(resultWide[i] >> 32);
        }
        size_t used = result._limbs.size();
        while (used != 0 && result._limbs[used - 1] == 0) {
            --used;
        }
        result._limbs.resize(used);
        return result;
#else

        // table[i] = base^(2*i+1). Sliding windows only end at a set bit, so even powers are
        // never selected. Long RSA exponents use a five-bit window, while DSA's shorter 160/256-
        // bit exponents retain the smaller four-bit table.
        CBigNum table[MAX_ODD_POWERS];
        table[0] = baseMont;
        CBigNum baseSquared(table[0]);
        mul(baseSquared, baseSquared);
        for (size_t i = 1; i < oddPowers; ++i) {
            table[i] = table[i - 1];
            mul(table[i], baseSquared);
        }

        CBigNum result(_one);

        size_t cursor = exponentBits;
        while (cursor > 0) {
            const size_t top = cursor - 1;
            if (!exponent.testBit(top)) {
                mul(result, result);
                --cursor;
                continue;
            }

            size_t bottom = cursor > window ? cursor - window : 0;
            while (!exponent.testBit(bottom)) {
                ++bottom;
            }

            size_t value = 0;
            for (size_t bit = cursor; bit-- > bottom; ) {
                value = (value << 1) | size_t(exponent.testBit(bit));
                mul(result, result);
            }
            mul(result, table[value >> 1]);
            cursor = bottom;
        }

        return fromMont(result);
#endif
    }

    /* Product of two modular exponentiations via one two-bit simultaneous window. */
    CBigNum CMontgomery::modExpProduct(
        const CBigNum& firstBase, const CBigNum& firstExponent,
        const CBigNum& secondBase, const CBigNum& secondExponent
    ) const {
        if (!_valid) {
            return CBigNum();
        }

        const CBigNum firstMont = toMont(firstBase);
        const CBigNum secondMont = toMont(secondBase);

#if defined(__clang__) && defined(__SIZEOF_INT128__) && \
    (defined(__x86_64__) || defined(_M_X64))
        constexpr size_t WINDOW = 2;
        constexpr size_t WINDOW_VALUES = size_t(1) << WINDOW;
        constexpr size_t PRODUCT_COUNT = WINDOW_VALUES * WINDOW_VALUES;
        constexpr size_t STACK_DIGITS = (STACK_LIMBS + 1) / 2;
        constexpr size_t BUFFER_COUNT = PRODUCT_COUNT + 2 * WINDOW_VALUES + 3;
        uint64_t stack[BUFFER_COUNT * STACK_DIGITS + 2];
        TArray<uint64_t> heap;
        uint64_t* packed = stack;
        if (_wideCount > STACK_DIGITS) {
            if (!heap.resize(BUFFER_COUNT * _wideCount + 2)) {
                return CBigNum();
            }
            packed = heap.begin();
        }

        uint64_t* table = packed;
        uint64_t* firstPowers = table + PRODUCT_COUNT * _wideCount;
        uint64_t* secondPowers = firstPowers + WINDOW_VALUES * _wideCount;
        uint64_t* resultWide = secondPowers + WINDOW_VALUES * _wideCount;
        uint64_t* ordinaryOne = resultWide + _wideCount;
        uint64_t* scratch = ordinaryOne + _wideCount;

        auto pack = [this](const CBigNum& value, uint64_t* out) {
            for (size_t i = 0; i < _wideCount; ++i) {
                const size_t lo = 2 * i;
                uint64_t digit = lo < value._limbs.size() ? uint64_t(value._limbs[lo]) : 0;
                if (lo + 1 < value._limbs.size()) {
                    digit |= uint64_t(value._limbs[lo + 1]) << 32;
                }
                out[i] = digit;
            }
        };

        const MulWideChain multiply = selectMulWideChain(_wideCount);

        pack(_one, firstPowers);
        std::memcpy(secondPowers, firstPowers, _wideCount * sizeof(uint64_t));
        pack(firstMont, firstPowers + _wideCount);
        pack(secondMont, secondPowers + _wideCount);
        for (size_t i = 2; i < WINDOW_VALUES; ++i) {
            multiply(firstPowers + (i - 1) * _wideCount, firstPowers + _wideCount,
                _modulus64.begin(), _wideCount, _n0inv64,
                firstPowers + i * _wideCount, scratch);
            multiply(secondPowers + (i - 1) * _wideCount, secondPowers + _wideCount,
                _modulus64.begin(), _wideCount, _n0inv64,
                secondPowers + i * _wideCount, scratch);
        }
        for (size_t first = 0; first < WINDOW_VALUES; ++first) {
            for (size_t second = 0; second < WINDOW_VALUES; ++second) {
                uint64_t* entry = table
                    + (first * WINDOW_VALUES + second) * _wideCount;
                if (first == 0) {
                    std::memcpy(entry, secondPowers + second * _wideCount,
                        _wideCount * sizeof(uint64_t));
                } else if (second == 0) {
                    std::memcpy(entry, firstPowers + first * _wideCount,
                        _wideCount * sizeof(uint64_t));
                } else {
                    multiply(firstPowers + first * _wideCount,
                        secondPowers + second * _wideCount,
                        _modulus64.begin(), _wideCount, _n0inv64, entry, scratch);
                }
            }
        }
        std::memcpy(resultWide, table, _wideCount * sizeof(uint64_t));

        const size_t firstBits = firstExponent.bitLength();
        const size_t secondBits = secondExponent.bitLength();
        const size_t bits = firstBits > secondBits ? firstBits : secondBits;
        size_t cursor = bits;
        while (cursor != 0) {
            const size_t width = cursor < WINDOW ? cursor : WINDOW;
            const size_t bottom = cursor - width;
            size_t firstValue = 0;
            size_t secondValue = 0;
            for (size_t bit = cursor; bit-- > bottom; ) {
                multiply(resultWide, resultWide, _modulus64.begin(), _wideCount,
                    _n0inv64, resultWide, scratch);
                firstValue = (firstValue << 1) | size_t(firstExponent.testBit(bit));
                secondValue = (secondValue << 1) | size_t(secondExponent.testBit(bit));
            }
            const size_t index = firstValue * WINDOW_VALUES + secondValue;
            if (index != 0) {
                multiply(resultWide, table + index * _wideCount,
                    _modulus64.begin(), _wideCount, _n0inv64, resultWide, scratch);
            }
            cursor = bottom;
        }

        std::memset(ordinaryOne, 0, _wideCount * sizeof(uint64_t));
        ordinaryOne[0] = 1;
        multiply(resultWide, ordinaryOne, _modulus64.begin(), _wideCount,
            _n0inv64, resultWide, scratch);

        CBigNum result;
        if (!result._limbs.resize(2 * _wideCount)) {
            return CBigNum();
        }
        for (size_t i = 0; i < _wideCount; ++i) {
            result._limbs[2 * i] = uint32_t(resultWide[i]);
            result._limbs[2 * i + 1] = uint32_t(resultWide[i] >> 32);
        }
        size_t used = result._limbs.size();
        while (used != 0 && result._limbs[used - 1] == 0) {
            --used;
        }
        result._limbs.resize(used);
        return result;
#else
        constexpr size_t WINDOW = 2;
        constexpr size_t WINDOW_VALUES = size_t(1) << WINDOW;
        CBigNum firstPowers[WINDOW_VALUES];
        CBigNum secondPowers[WINDOW_VALUES];
        CBigNum table[WINDOW_VALUES * WINDOW_VALUES];
        firstPowers[0] = _one;
        secondPowers[0] = _one;
        firstPowers[1] = firstMont;
        secondPowers[1] = secondMont;
        for (size_t i = 2; i < WINDOW_VALUES; ++i) {
            firstPowers[i] = firstPowers[i - 1];
            mul(firstPowers[i], firstPowers[1]);
            secondPowers[i] = secondPowers[i - 1];
            mul(secondPowers[i], secondPowers[1]);
        }
        for (size_t first = 0; first < WINDOW_VALUES; ++first) {
            for (size_t second = 0; second < WINDOW_VALUES; ++second) {
                CBigNum& entry = table[first * WINDOW_VALUES + second];
                if (first == 0) {
                    entry = secondPowers[second];
                } else if (second == 0) {
                    entry = firstPowers[first];
                } else {
                    entry = firstPowers[first];
                    mul(entry, secondPowers[second]);
                }
            }
        }
        CBigNum result(_one);
        const size_t firstBits = firstExponent.bitLength();
        const size_t secondBits = secondExponent.bitLength();
        const size_t bits = firstBits > secondBits ? firstBits : secondBits;
        size_t cursor = bits;
        while (cursor != 0) {
            const size_t width = cursor < WINDOW ? cursor : WINDOW;
            const size_t bottom = cursor - width;
            size_t firstValue = 0;
            size_t secondValue = 0;
            for (size_t bit = cursor; bit-- > bottom; ) {
                mul(result, result);
                firstValue = (firstValue << 1) | size_t(firstExponent.testBit(bit));
                secondValue = (secondValue << 1) | size_t(secondExponent.testBit(bit));
            }
            const size_t index = firstValue * WINDOW_VALUES + secondValue;
            if (index != 0) {
                mul(result, table[index]);
            }
            cursor = bottom;
        }
        return fromMont(result);
#endif
    }

} // namespace certpp
