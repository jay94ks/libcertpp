#ifndef __SRC_CRYPTO_ASYMS_FE448_HPP__
#define __SRC_CRYPTO_ASYMS_FE448_HPP__

#include <certpp/arch.hpp>
#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * An element of GF(2^448 - 2^224 - 1) in a fixed-width representation.
     *
     * Targets with a native 64x64-to-128 multiply use eight radix-2^56 limbs. Other targets use
     * sixteen radix-2^28 limbs so every product and accumulator remains within uint64_t. The limb
     * count and operation schedule are independent of the represented value.
     */
    class Fe448 {
    public:
        static constexpr size_t BYTES = 56;
#if defined(CERTPP_ARCH_NATIVE_64x64_TO_128)
        static constexpr size_t LIMBS = 8;
        static constexpr unsigned WIDTH = 56;
#else
        static constexpr size_t LIMBS = 16;
        static constexpr unsigned WIDTH = 28;
#endif

        uint64_t limbs[LIMBS];

        void setZero();
        void setOne();

        /** Decodes a canonical little-endian field element. */
        bool fromBytes(const uint8_t in[BYTES]);

        /** Encodes the canonical little-endian representative. */
        void toBytes(uint8_t out[BYTES]) const;

        static void add(Fe448& out, const Fe448& a, const Fe448& b);
        static void sub(Fe448& out, const Fe448& a, const Fe448& b);
        static void mul(Fe448& out, const Fe448& a, const Fe448& b);
        static void square(Fe448& out, const Fe448& a);
        static void mulSmall(Fe448& out, const Fe448& a, uint32_t b);
        static void neg(Fe448& out, const Fe448& a);
        static void conditionalSwap(bool swap, Fe448& a, Fe448& b);
        static void invert(Fe448& out, const Fe448& a);

        /** Computes sqrt(u / v), returning false when the ratio is not a square or v is zero. */
        static bool squareRootRatio(Fe448& out, const Fe448& u, const Fe448& v);

        bool isZero() const;
        bool isEqual(const Fe448& other) const;
        bool isOdd() const;
    };

} // namespace crypto
} // namespace certpp

#endif // __SRC_CRYPTO_ASYMS_FE448_HPP__
