#include <certpp/utils/montgomery.hpp>
#include <cstring>
#include <utility>

namespace certpp {

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

    CMontgomery::CMontgomery()
        : _count(0), _n0inv(0), _valid(false)
    {
    }

    CMontgomery::CMontgomery(const CBigNum& modulus)
        : _count(0), _n0inv(0), _valid(false)
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

        // --> Sanity check on the Newton iteration rather than trusting it: n' * m[0] must be -1
        // mod 2^32. Cheap, and it runs once per context instead of once per multiply.
        if (uint32_t(_n0inv * _m._limbs[0]) != uint32_t(0u - 1u)) {
            _m = CBigNum();
            _count = 0;
            _n0inv = 0;
            return;
        }

        // --> R^2 mod m and R mod m are the only two places a long division happens, and they
        // happen once, here -- which is the whole trade this class makes.
        _rr = CBigNum(uint64_t(1));
        _rr.shl(64 * _count);
        _rr.mod(_m);

        _one = CBigNum(uint64_t(1));
        _one.shl(32 * _count);
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

    /* Modular exponentiation via square-and-multiply in the Montgomery domain. */
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

        const CBigNum baseMont = toMont(base);
        CBigNum result(_one);

        for (size_t i = exponent.bitLength(); i-- > 0; ) {
            mul(result, result);

            if (exponent.testBit(i)) {
                mul(result, baseMont);
            }
        }

        return fromMont(result);
    }

} // namespace certpp
