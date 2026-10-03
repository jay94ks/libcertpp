#include "mldsascheme.hpp"
#include "mldsacodec.hpp"
#include "mldsarounding.hpp"
#include "mldsasampler.hpp"
#include <certpp/crypto/hashers/shake256.hpp>
#include <certpp/utils/secure.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/buffer.hpp>
#include <initializer_list>
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        using Poly = MlDsaRing::Poly;

        /* H (FIPS 204 4.1): SHAKE256 over the concatenation of the parts, squeezed to out.size.
         * squeeze() rather than finish(), so the length is the caller's span rather than the
         * instance's byteWidth(); the two must not be mixed on one instance. */
        bool hashH(std::initializer_list<SReadOnlyByteSpan> parts, const SByteSpan& out) {
            if (!out.data || out.size == 0) {
                return false;
            }

            SHAKE256 xof(out.size);

            for (const SReadOnlyByteSpan& part : parts) {
                if (part.size == 0) {
                    continue; // --> An empty context string is legal, and has nothing to absorb.
                }

                if (xof.push(part) != part.size) {
                    return false;
                }
            }

            return xof.squeeze(out);
        }

        /* Copies a vector and transforms every element into the NTT domain. */
        void toNttDomain(const Poly* in, size_t count, Poly* out) {
            for (size_t i = 0; i < count; ++i) {
                std::memcpy(out[i].coeffs, in[i].coeffs, sizeof(out[i].coeffs));
                MlDsaRing::ntt(out[i]);
            }
        }

        /* out[i] = sum_j aHat[i*l + j] * vecHat[j], left in the NTT domain -- verify() has one
         * more NTT-domain term to subtract before it inverts, so the inverse is the caller's. */
        void matrixVectorNtt(
            const Poly* aHat, const Poly* vecHat, size_t k, size_t l, Poly* out
        ) {
            for (size_t i = 0; i < k; ++i) {
                MlDsaRing::setZero(out[i]);

                for (size_t j = 0; j < l; ++j) {
                    Poly product;
                    MlDsaRing::multiplyNtt(product, aHat[i * l + j], vecHat[j]);
                    MlDsaRing::add(out[i], out[i], product);
                }
            }
        }

        /* The largest absolute coefficient over a vector, taking each coefficient at face value
         * rather than reducing it -- for LowBits/BitUnpack output, which is already centered and
         * whose magnitude would be destroyed by a mod-q reduction. */
        int32_t absMax(const Poly* vec, size_t count) {
            int32_t largest = 0;

            for (size_t i = 0; i < count; ++i) {
                for (size_t j = 0; j < MlDsaRing::N; ++j) {
                    const int32_t value = vec[i].coeffs[j] < 0
                        ? -vec[i].coeffs[j] : vec[i].coeffs[j];

                    if (value > largest) {
                        largest = value;
                    }
                }
            }

            return largest;
        }

        /* Zeroizes a polynomial vector when it leaves scope (FIPS 204 3.6.3: sensitive
         * intermediates are destroyed as soon as they are no longer needed).
         *
         * RAII rather than a call at the end, because signing's rejection loop has four
         * `continue` paths and a dozen early returns -- a scrub written at the bottom would be
         * skipped by every one of them, which is the failure mode this library already hit once
         * (see decapsulate()'s single exit in CMlKem, added for the same reason). Destruction
         * order is the reverse of declaration, and every use is inside the scope, so nothing is
         * cleared while still live. */
        struct PolyScrubber {
            TArray<Poly>& target;

            ~PolyScrubber() {
                if (target.size() != 0) {
                    CSecure::zero(SByteSpan(
                        reinterpret_cast<uint8_t*>(target.begin()),
                        target.size() * sizeof(Poly)));
                }
            }
        };

        /* The same, for a fixed-size byte array holding a seed or a hash. */
        struct ByteScrubber {
            uint8_t* data;
            size_t size;

            ~ByteScrubber() {
                CSecure::zero(SByteSpan(data, size));
            }
        };

        /* ||vec||_inf over coefficients held in [0, q), via their centered representatives. */
        int32_t vectorInfinityNorm(const Poly* vec, size_t count) {
            int32_t largest = 0;

            for (size_t i = 0; i < count; ++i) {
                const int32_t norm = MlDsaRing::infinityNorm(vec[i]);

                if (norm > largest) {
                    largest = norm;
                }
            }

            return largest;
        }

    } // namespace

    /* pkEncode (FIPS 204 Algorithm 22). */
    bool MlDsaScheme::pkEncode(
        const MlDsaParams& params, const SReadOnlyByteSpan& rho, const Poly* t1,
        const SByteSpan& out
    ) {
        if (!params.isValid() || !t1) {
            return false;
        }
        if (rho.size != RHO_BYTES || !rho.data) {
            return false;
        }
        if (out.size != params.publicKeyBytes() || !out.data) {
            return false;
        }

        std::memcpy(out.data, rho.data, RHO_BYTES);

        const size_t width = 32 * MlDsaParams::t1BitWidth();
        const uint32_t bound = (uint32_t(1) << MlDsaParams::t1BitWidth()) - 1u;

        for (size_t i = 0; i < params.k; ++i) {
            if (!MlDsaCodec::simpleBitPack(
                    t1[i], bound, out.slice(RHO_BYTES + i * width, width)))
            {
                return false;
            }
        }

        return true;
    }

    /* pkDecode (FIPS 204 Algorithm 23). */
    bool MlDsaScheme::pkDecode(
        const MlDsaParams& params, const SReadOnlyByteSpan& pk, const SByteSpan& rho, Poly* t1
    ) {
        if (!params.isValid() || !t1) {
            return false;
        }
        if (rho.size != RHO_BYTES || !rho.data) {
            return false;
        }
        if (pk.size != params.publicKeyBytes() || !pk.data) {
            return false;
        }

        std::memcpy(rho.data, pk.data, RHO_BYTES);

        const size_t width = 32 * MlDsaParams::t1BitWidth();
        const uint32_t bound = (uint32_t(1) << MlDsaParams::t1BitWidth()) - 1u;

        for (size_t i = 0; i < params.k; ++i) {
            if (!MlDsaCodec::simpleBitUnpack(
                    pk.slice(RHO_BYTES + i * width, width), bound, t1[i]))
            {
                return false;
            }
        }

        return true;
    }

    /* skEncode (FIPS 204 Algorithm 24). */
    bool MlDsaScheme::skEncode(
        const MlDsaParams& params, const SReadOnlyByteSpan& rho, const SReadOnlyByteSpan& k,
        const SReadOnlyByteSpan& tr, const Poly* s1, const Poly* s2, const Poly* t0,
        const SByteSpan& out
    ) {
        if (!params.isValid() || !s1 || !s2 || !t0) {
            return false;
        }
        if (rho.size != RHO_BYTES || k.size != RHO_BYTES || tr.size != MU_BYTES) {
            return false;
        }
        if (!rho.data || !k.data || !tr.data) {
            return false;
        }
        if (out.size != params.privateKeyBytes() || !out.data) {
            return false;
        }

        std::memcpy(out.data, rho.data, RHO_BYTES);
        std::memcpy(out.data + RHO_BYTES, k.data, RHO_BYTES);
        std::memcpy(out.data + 2 * RHO_BYTES, tr.data, MU_BYTES);

        const uint32_t eta = uint32_t(params.eta);
        const size_t etaWidth = 32 * params.etaBitWidth();
        const size_t t0Width = 32 * size_t(MlDsaRounding::D);
        const uint32_t t0Bound = uint32_t(1) << (MlDsaRounding::D - 1);

        size_t offset = 2 * RHO_BYTES + MU_BYTES;

        for (size_t i = 0; i < params.l; ++i, offset += etaWidth) {
            if (!MlDsaCodec::bitPack(s1[i], eta, eta, out.slice(offset, etaWidth))) {
                return false;
            }
        }

        for (size_t i = 0; i < params.k; ++i, offset += etaWidth) {
            if (!MlDsaCodec::bitPack(s2[i], eta, eta, out.slice(offset, etaWidth))) {
                return false;
            }
        }

        for (size_t i = 0; i < params.k; ++i, offset += t0Width) {
            if (!MlDsaCodec::bitPack(
                    t0[i], t0Bound - 1u, t0Bound, out.slice(offset, t0Width)))
            {
                return false;
            }
        }

        return true;
    }

    /* skDecode (FIPS 204 Algorithm 25), including the s1/s2 range check. */
    bool MlDsaScheme::skDecode(
        const MlDsaParams& params, const SReadOnlyByteSpan& sk, const SByteSpan& rho,
        const SByteSpan& k, const SByteSpan& tr, Poly* s1, Poly* s2, Poly* t0
    ) {
        if (!params.isValid() || !s1 || !s2 || !t0) {
            return false;
        }
        if (rho.size != RHO_BYTES || k.size != RHO_BYTES || tr.size != MU_BYTES) {
            return false;
        }
        if (!rho.data || !k.data || !tr.data) {
            return false;
        }
        if (sk.size != params.privateKeyBytes() || !sk.data) {
            return false;
        }

        std::memcpy(rho.data, sk.data, RHO_BYTES);
        std::memcpy(k.data, sk.data + RHO_BYTES, RHO_BYTES);
        std::memcpy(tr.data, sk.data + 2 * RHO_BYTES, MU_BYTES);

        const uint32_t eta = uint32_t(params.eta);
        const size_t etaWidth = 32 * params.etaBitWidth();
        const size_t t0Width = 32 * size_t(MlDsaRounding::D);
        const uint32_t t0Bound = uint32_t(1) << (MlDsaRounding::D - 1);

        size_t offset = 2 * RHO_BYTES + MU_BYTES;

        for (size_t i = 0; i < params.l; ++i, offset += etaWidth) {
            if (!MlDsaCodec::bitUnpack(sk.slice(offset, etaWidth), eta, eta, s1[i])) {
                return false;
            }
        }

        for (size_t i = 0; i < params.k; ++i, offset += etaWidth) {
            if (!MlDsaCodec::bitUnpack(sk.slice(offset, etaWidth), eta, eta, s2[i])) {
                return false;
            }
        }

        for (size_t i = 0; i < params.k; ++i, offset += t0Width) {
            if (!MlDsaCodec::bitUnpack(
                    sk.slice(offset, t0Width), t0Bound - 1u, t0Bound, t0[i]))
            {
                return false;
            }
        }

        // --> FIPS 204 Algorithm 25 lines 9-10. 2*eta + 1 is 5 or 9, so the field is wider than
        // the range and a byte string can decode to -5 (eta = 2) or -11 (eta = 4). t0's field is
        // exactly 13 bits wide for a 13-bit range, so it needs no equivalent check.
        for (size_t i = 0; i < params.l; ++i) {
            if (!MlDsaCodec::inRange(s1[i], -int32_t(eta), int32_t(eta))) {
                return false;
            }
        }

        for (size_t i = 0; i < params.k; ++i) {
            if (!MlDsaCodec::inRange(s2[i], -int32_t(eta), int32_t(eta))) {
                return false;
            }
        }

        return true;
    }

    /* sigEncode (FIPS 204 Algorithm 26). */
    bool MlDsaScheme::sigEncode(
        const MlDsaParams& params, const SReadOnlyByteSpan& commitment, const Poly* z,
        const Poly* hints, const SByteSpan& out
    ) {
        if (!params.isValid() || !z || !hints) {
            return false;
        }
        if (commitment.size != params.commitmentBytes() || !commitment.data) {
            return false;
        }
        if (out.size != params.signatureBytes() || !out.data) {
            return false;
        }

        std::memcpy(out.data, commitment.data, commitment.size);

        const size_t zWidth = 32 * (1 + params.gamma1BitWidth());
        size_t offset = commitment.size;

        for (size_t i = 0; i < params.l; ++i, offset += zWidth) {
            if (!MlDsaCodec::bitPack(
                    z[i], params.gamma1 - 1u, params.gamma1, out.slice(offset, zWidth)))
            {
                return false;
            }
        }

        return MlDsaCodec::hintBitPack(
            hints, params.k, params.omega, out.slice(offset, params.omega + params.k));
    }

    /* sigDecode (FIPS 204 Algorithm 27). */
    bool MlDsaScheme::sigDecode(
        const MlDsaParams& params, const SReadOnlyByteSpan& signature,
        const SByteSpan& commitment, Poly* z, Poly* hints
    ) {
        if (!params.isValid() || !z || !hints) {
            return false;
        }
        if (commitment.size != params.commitmentBytes() || !commitment.data) {
            return false;
        }
        if (signature.size != params.signatureBytes() || !signature.data) {
            return false;
        }

        std::memcpy(commitment.data, signature.data, commitment.size);

        const size_t zWidth = 32 * (1 + params.gamma1BitWidth());
        size_t offset = commitment.size;

        for (size_t i = 0; i < params.l; ++i, offset += zWidth) {
            if (!MlDsaCodec::bitUnpack(
                    signature.slice(offset, zWidth), params.gamma1 - 1u, params.gamma1, z[i]))
            {
                return false;
            }
        }

        return MlDsaCodec::hintBitUnpack(
            signature.slice(offset, params.omega + params.k), params.k, params.omega, hints);
    }

    /* The length w1Encode() writes. */
    size_t MlDsaScheme::w1EncodedBytes(const MlDsaParams& params) {
        return 32 * params.k * MlDsaCodec::bitLength(uint32_t(params.highBitsRange()) - 1u);
    }

    /* w1Encode (FIPS 204 Algorithm 28). */
    bool MlDsaScheme::w1Encode(const MlDsaParams& params, const Poly* w1, const SByteSpan& out) {
        if (!params.isValid() || !w1) {
            return false;
        }
        if (out.size != w1EncodedBytes(params) || !out.data) {
            return false;
        }

        const uint32_t bound = uint32_t(params.highBitsRange()) - 1u;
        const size_t width = 32 * MlDsaCodec::bitLength(bound);

        for (size_t i = 0; i < params.k; ++i) {
            if (!MlDsaCodec::simpleBitPack(w1[i], bound, out.slice(i * width, width))) {
                return false;
            }
        }

        return true;
    }

    /* ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6). */
    bool MlDsaScheme::keyGenInternal(
        const MlDsaParams& params, const SReadOnlyByteSpan& seed, const SByteSpan& pk,
        const SByteSpan& sk
    ) {
        if (!params.isValid()) {
            return false;
        }
        if (seed.size != SEED_BYTES || !seed.data) {
            return false;
        }
        if (pk.size != params.publicKeyBytes() || !pk.data) {
            return false;
        }
        if (sk.size != params.privateKeyBytes() || !sk.data) {
            return false;
        }

        // --> The (k, l) bytes appended to xi are domain separation between the parameter sets,
        // added in FIPS 204's final text. Omitting them -- as round-3 Dilithium does -- gives
        // three schemes that all work with themselves and none of which match the standard. This
        // is the same trap FIPS 203's G(d || k) has.
        const uint8_t domain[2] = { uint8_t(params.k), uint8_t(params.l) };

        // xi expands into rho, rho' and K -- the whole private key is a function of these
        // 128 bytes, so they are as sensitive as it is.
        uint8_t expanded[128];
        ByteScrubber expandedScrub{ expanded, sizeof(expanded) };

        if (!hashH({ seed, SReadOnlyByteSpan(domain, sizeof(domain)) },
                   SByteSpan(expanded, sizeof(expanded))))
        {
            return false;
        }

        const SReadOnlyByteSpan rho(expanded, RHO_BYTES);
        const SReadOnlyByteSpan rhoPrime(expanded + RHO_BYTES, MU_BYTES);
        const SReadOnlyByteSpan keySeed(expanded + RHO_BYTES + MU_BYTES, RHO_BYTES);

        TArray<Poly> aHat;
        TArray<Poly> s1;
        TArray<Poly> s2;
        TArray<Poly> s1Hat;
        TArray<Poly> t;

        // A-hat is public (it is a function of rho alone, which travels in the public key), so
        // it is left alone; everything else here is secret or derived from secrets.
        PolyScrubber s1Scrub{ s1 };
        PolyScrubber s2Scrub{ s2 };
        PolyScrubber s1HatScrub{ s1Hat };
        PolyScrubber tScrub{ t };

        if (!aHat.resize(params.k * params.l) || !s1.resize(params.l)
            || !s2.resize(params.k) || !s1Hat.resize(params.l)
            || !t.resize(params.k))
        {
            return false;
        }

        if (!MlDsaSampler::expandA(rho, params.k, params.l, aHat.begin())) {
            return false;
        }
        if (!MlDsaSampler::expandS(
                rhoPrime, params.k, params.l, params.eta, s1.begin(), s2.begin()))
        {
            return false;
        }

        toNttDomain(s1.begin(), params.l, s1Hat.begin());
        matrixVectorNtt(aHat.begin(), s1Hat.begin(), params.k, params.l, t.begin());

        TArray<Poly> t1;
        TArray<Poly> t0;
        PolyScrubber t0Scrub{ t0 };   // --> t1 is published; t0 is not.

        if (!t1.resize(params.k) || !t0.resize(params.k)) {
            return false;
        }

        for (size_t i = 0; i < params.k; ++i) {
            MlDsaRing::inverseNtt(t.begin()[i]);
            MlDsaRing::add(t.begin()[i], t.begin()[i], s2.begin()[i]);
            MlDsaRounding::power2Round(t.begin()[i], t1.begin()[i], t0.begin()[i]);
        }

        if (!pkEncode(params, rho, t1.begin(), pk)) {
            return false;
        }

        uint8_t tr[MU_BYTES];
        if (!hashH({ SReadOnlyByteSpan(pk) }, SByteSpan(tr, sizeof(tr)))) {
            return false;
        }

        return skEncode(
            params, rho, keySeed, SReadOnlyByteSpan(tr, sizeof(tr)),
            s1.begin(), s2.begin(), t0.begin(), sk);
    }

    /* ML-DSA.Sign_internal (FIPS 204 Algorithm 7). */
    bool MlDsaScheme::signInternal(
        const MlDsaParams& params, const SReadOnlyByteSpan& sk, const SReadOnlyByteSpan& message,
        const SReadOnlyByteSpan& externalMu, const SReadOnlyByteSpan& rnd, const SByteSpan& out
    ) {
        if (!params.isValid()) {
            return false;
        }
        if (sk.size != params.privateKeyBytes() || !sk.data) {
            return false;
        }
        if (rnd.size != RND_BYTES || !rnd.data) {
            return false;
        }
        if (out.size != params.signatureBytes() || !out.data) {
            return false;
        }
        if (externalMu.size != 0 && (externalMu.size != MU_BYTES || !externalMu.data)) {
            return false;
        }

        const size_t k = params.k;
        const size_t l = params.l;
        const int32_t gamma2 = params.gamma2;

        uint8_t rho[RHO_BYTES];
        uint8_t keySeed[RHO_BYTES];
        uint8_t tr[MU_BYTES];

        // K is what makes rho'' -- and rho'' is what makes y, so leaking it leaks the nonce and
        // therefore s1, exactly as EdDSA's signing prefix does.
        ByteScrubber keySeedScrub{ keySeed, sizeof(keySeed) };

        TArray<Poly> s1;
        TArray<Poly> s2;
        TArray<Poly> t0;
        PolyScrubber s1Scrub{ s1 };
        PolyScrubber s2Scrub{ s2 };
        PolyScrubber t0Scrub{ t0 };

        if (!s1.resize(l) || !s2.resize(k) || !t0.resize(k)) {
            return false;
        }

        if (!skDecode(
                params, sk, SByteSpan(rho, sizeof(rho)), SByteSpan(keySeed, sizeof(keySeed)),
                SByteSpan(tr, sizeof(tr)), s1.begin(), s2.begin(), t0.begin()))
        {
            return false;
        }

        TArray<Poly> aHat;
        TArray<Poly> s1Hat;
        TArray<Poly> s2Hat;
        TArray<Poly> t0Hat;
        PolyScrubber s1HatScrub{ s1Hat };
        PolyScrubber s2HatScrub{ s2Hat };
        PolyScrubber t0HatScrub{ t0Hat };

        if (!aHat.resize(k * l) || !s1Hat.resize(l) || !s2Hat.resize(k)
            || !t0Hat.resize(k))
        {
            return false;
        }

        if (!MlDsaSampler::expandA(SReadOnlyByteSpan(rho, sizeof(rho)), k, l, aHat.begin())) {
            return false;
        }

        toNttDomain(s1.begin(), l, s1Hat.begin());
        toNttDomain(s2.begin(), k, s2Hat.begin());
        toNttDomain(t0.begin(), k, t0Hat.begin());

        uint8_t mu[MU_BYTES];
        ByteScrubber muScrub{ mu, sizeof(mu) };

        if (externalMu.size == MU_BYTES) {
            std::memcpy(mu, externalMu.data, MU_BYTES);
        }
        else if (!hashH({ SReadOnlyByteSpan(tr, sizeof(tr)), message },
                        SByteSpan(mu, sizeof(mu))))
        {
            return false;
        }

        // --> rho'' binds the signing seed K, the per-signature randomness and the message
        // together. rnd being all zero is exactly what makes signing deterministic; it is not a
        // degenerate case, it is FIPS 204's own deterministic variant and what every ACVP
        // `deterministic: true` group uses.
        uint8_t rhoPrime2[MU_BYTES];
        ByteScrubber rhoPrime2Scrub{ rhoPrime2, sizeof(rhoPrime2) };

        if (!hashH({ SReadOnlyByteSpan(keySeed, sizeof(keySeed)), rnd,
                     SReadOnlyByteSpan(mu, sizeof(mu)) },
                   SByteSpan(rhoPrime2, sizeof(rhoPrime2))))
        {
            return false;
        }

        TArray<Poly> y;
        TArray<Poly> yHat;
        TArray<Poly> w;
        TArray<Poly> w1;
        TArray<Poly> z;
        TArray<Poly> lowParts;
        TArray<Poly> wMinusCs2;
        TArray<Poly> ct0;
        TArray<Poly> hints;
        CBuffer w1Encoded;

        // y is the masking vector: publishing it alongside z would hand over s1 directly, so it
        // and its NTT form are secret, and so is z until the bounds pass and it is encoded.
        PolyScrubber yScrub{ y };
        PolyScrubber yHatScrub{ yHat };
        PolyScrubber zScrub{ z };
        PolyScrubber ct0Scrub{ ct0 };

        if (!y.resize(l) || !yHat.resize(l) || !w.resize(k) || !w1.resize(k)
            || !z.resize(l) || !lowParts.resize(k) || !wMinusCs2.resize(k)
            || !ct0.resize(k) || !hints.resize(k)
            || !w1Encoded.resize(w1EncodedBytes(params)))
        {
            return false;
        }

        uint8_t commitment[MlDsaParams::mlDsa87().commitmentBytes()];
        const size_t commitmentBytes = params.commitmentBytes();

        Poly challenge;
        Poly challengeHat;
        Poly product;

        // `product` carries c*s1 and c*s2 in turn, both secret-derived; `challenge` and its NTT
        // form are public (c is SampleInBall(c-tilde), and c-tilde goes in the signature).
        ByteScrubber productScrub{
            reinterpret_cast<uint8_t*>(product.coeffs), sizeof(product.coeffs) };

        // --> Rejection sampling with aborts. Every iteration draws a fresh y and throws the
        // whole attempt away if any of the four bounds below fails; the expected count is a
        // handful, and FIPS 204 sets no upper limit, so neither does this.
        for (uint32_t kappa = 0; ; kappa += uint32_t(l)) {
            if (!MlDsaSampler::expandMask(
                    SReadOnlyByteSpan(rhoPrime2, sizeof(rhoPrime2)), kappa, l, params.gamma1,
                    y.begin()))
            {
                return false;
            }

            toNttDomain(y.begin(), l, yHat.begin());
            matrixVectorNtt(aHat.begin(), yHat.begin(), k, l, w.begin());

            for (size_t i = 0; i < k; ++i) {
                MlDsaRing::inverseNtt(w.begin()[i]);

                for (size_t j = 0; j < MlDsaRing::N; ++j) {
                    w1.begin()[i].coeffs[j] =
                        MlDsaRounding::highBits(w.begin()[i].coeffs[j], gamma2);
                }
            }

            if (!w1Encode(params, w1.begin(), SByteSpan(w1Encoded.toPtr(), w1Encoded.size()))) {
                return false;
            }

            if (!hashH({ SReadOnlyByteSpan(mu, sizeof(mu)), w1Encoded.toSpan() },
                       SByteSpan(commitment, commitmentBytes)))
            {
                return false;
            }

            if (!MlDsaSampler::sampleInBall(
                    SReadOnlyByteSpan(commitment, commitmentBytes), params.tau, challenge))
            {
                return false;
            }

            std::memcpy(challengeHat.coeffs, challenge.coeffs, sizeof(challengeHat.coeffs));
            MlDsaRing::ntt(challengeHat);

            for (size_t j = 0; j < l; ++j) {
                MlDsaRing::multiplyNtt(product, challengeHat, s1Hat.begin()[j]);
                MlDsaRing::inverseNtt(product);
                MlDsaRing::add(z.begin()[j], y.begin()[j], product);
            }

            for (size_t i = 0; i < k; ++i) {
                MlDsaRing::multiplyNtt(product, challengeHat, s2Hat.begin()[i]);
                MlDsaRing::inverseNtt(product);
                MlDsaRing::sub(wMinusCs2.begin()[i], w.begin()[i], product);

                for (size_t j = 0; j < MlDsaRing::N; ++j) {
                    lowParts.begin()[i].coeffs[j] =
                        MlDsaRounding::lowBits(wMinusCs2.begin()[i].coeffs[j], gamma2);
                }
            }

            // z holds reduced coefficients, so its norm goes through centered(); the low parts
            // are already centered and must not be reduced again.
            if (vectorInfinityNorm(z.begin(), l) >= int32_t(params.gamma1) - int32_t(params.beta)) {
                continue;
            }
            if (absMax(lowParts.begin(), k) >= gamma2 - int32_t(params.beta)) {
                continue;
            }

            for (size_t i = 0; i < k; ++i) {
                MlDsaRing::multiplyNtt(ct0.begin()[i], challengeHat, t0Hat.begin()[i]);
                MlDsaRing::inverseNtt(ct0.begin()[i]);
            }

            // --> This bound is what lets useHint() invert makeHint() at all: the perturbation
            // has to stay strictly inside gamma2. Dropping it produces signatures that the
            // signer believes in and no verifier accepts.
            if (vectorInfinityNorm(ct0.begin(), k) >= gamma2) {
                continue;
            }

            size_t hintWeight = 0;
            for (size_t i = 0; i < k; ++i) {
                for (size_t j = 0; j < MlDsaRing::N; ++j) {
                    const int32_t negated =
                        MlDsaRing::reduce(-int64_t(ct0.begin()[i].coeffs[j]));
                    const int32_t shifted = MlDsaRing::reduce(
                        int64_t(wMinusCs2.begin()[i].coeffs[j])
                        + int64_t(ct0.begin()[i].coeffs[j]));

                    const uint8_t bit = MlDsaRounding::makeHint(negated, shifted, gamma2);
                    hints.begin()[i].coeffs[j] = int32_t(bit);
                    hintWeight += bit;
                }
            }

            if (hintWeight > params.omega) {
                continue;
            }

            for (size_t j = 0; j < l; ++j) {
                for (size_t i = 0; i < MlDsaRing::N; ++i) {
                    z.begin()[j].coeffs[i] = MlDsaRing::centered(z.begin()[j].coeffs[i]);
                }
            }

            return sigEncode(
                params, SReadOnlyByteSpan(commitment, commitmentBytes), z.begin(),
                hints.begin(), out);
        }
    }

    /* ML-DSA.Verify_internal (FIPS 204 Algorithm 8). */
    bool MlDsaScheme::verifyInternal(
        const MlDsaParams& params, const SReadOnlyByteSpan& pk, const SReadOnlyByteSpan& message,
        const SReadOnlyByteSpan& externalMu, const SReadOnlyByteSpan& signature
    ) {
        if (!params.isValid()) {
            return false;
        }
        if (pk.size != params.publicKeyBytes() || !pk.data) {
            return false;
        }
        if (signature.size != params.signatureBytes() || !signature.data) {
            return false;
        }
        if (externalMu.size != 0 && (externalMu.size != MU_BYTES || !externalMu.data)) {
            return false;
        }

        const size_t k = params.k;
        const size_t l = params.l;
        const int32_t gamma2 = params.gamma2;
        const size_t commitmentBytes = params.commitmentBytes();

        uint8_t rho[RHO_BYTES];

        TArray<Poly> t1;
        TArray<Poly> z;
        TArray<Poly> hints;
        if (!t1.resize(k) || !z.resize(l) || !hints.resize(k)) {
            return false;
        }

        if (!pkDecode(params, pk, SByteSpan(rho, sizeof(rho)), t1.begin())) {
            return false;
        }

        uint8_t commitment[MlDsaParams::mlDsa87().commitmentBytes()];
        if (!sigDecode(
                params, signature, SByteSpan(commitment, commitmentBytes), z.begin(),
                hints.begin()))
        {
            return false; // --> A malformed hint lands here; see MlDsaCodec::hintBitUnpack().
        }

        // The decoded z is centered, so its magnitude is read directly. This check is not
        // redundant with the signer's: it is what stops an attacker handing over an oversized z.
        if (absMax(z.begin(), l) >= int32_t(params.gamma1) - int32_t(params.beta)) {
            return false;
        }

        uint8_t mu[MU_BYTES];
        if (externalMu.size == MU_BYTES) {
            std::memcpy(mu, externalMu.data, MU_BYTES);
        }
        else {
            uint8_t tr[MU_BYTES];
            if (!hashH({ pk }, SByteSpan(tr, sizeof(tr)))) {
                return false;
            }
            if (!hashH({ SReadOnlyByteSpan(tr, sizeof(tr)), message },
                       SByteSpan(mu, sizeof(mu))))
            {
                return false;
            }
        }

        TArray<Poly> aHat;
        TArray<Poly> zHat;
        TArray<Poly> wApprox;
        CBuffer w1Encoded;
        if (!aHat.resize(k * l) || !zHat.resize(l) || !wApprox.resize(k)
            || !w1Encoded.resize(w1EncodedBytes(params)))
        {
            return false;
        }

        if (!MlDsaSampler::expandA(SReadOnlyByteSpan(rho, sizeof(rho)), k, l, aHat.begin())) {
            return false;
        }

        Poly challenge;
        if (!MlDsaSampler::sampleInBall(
                SReadOnlyByteSpan(commitment, commitmentBytes), params.tau, challenge))
        {
            return false;
        }

        Poly challengeHat;
        std::memcpy(challengeHat.coeffs, challenge.coeffs, sizeof(challengeHat.coeffs));
        MlDsaRing::ntt(challengeHat);

        toNttDomain(z.begin(), l, zHat.begin());
        matrixVectorNtt(aHat.begin(), zHat.begin(), k, l, wApprox.begin());

        for (size_t i = 0; i < k; ++i) {
            // t1 * 2^d reaches 2^23, which is above q, so the shift is reduced rather than
            // written straight into a coefficient.
            Poly scaled;
            for (size_t j = 0; j < MlDsaRing::N; ++j) {
                scaled.coeffs[j] =
                    MlDsaRing::reduce(int64_t(t1.begin()[i].coeffs[j]) << MlDsaRounding::D);
            }

            MlDsaRing::ntt(scaled);

            Poly product;
            MlDsaRing::multiplyNtt(product, challengeHat, scaled);
            MlDsaRing::sub(wApprox.begin()[i], wApprox.begin()[i], product);
            MlDsaRing::inverseNtt(wApprox.begin()[i]);

            for (size_t j = 0; j < MlDsaRing::N; ++j) {
                wApprox.begin()[i].coeffs[j] = MlDsaRounding::useHint(
                    uint8_t(hints.begin()[i].coeffs[j]), wApprox.begin()[i].coeffs[j], gamma2);
            }
        }

        if (!w1Encode(params, wApprox.begin(), SByteSpan(w1Encoded.toPtr(), w1Encoded.size()))) {
            return false;
        }

        uint8_t recomputed[MlDsaParams::mlDsa87().commitmentBytes()];
        if (!hashH({ SReadOnlyByteSpan(mu, sizeof(mu)), w1Encoded.toSpan() },
                   SByteSpan(recomputed, commitmentBytes)))
        {
            return false;
        }

        return std::memcmp(commitment, recomputed, commitmentBytes) == 0;
    }

    /* ML-DSA.Sign (FIPS 204 Algorithm 2), the pure external interface. */
    bool MlDsaScheme::sign(
        const MlDsaParams& params, const SReadOnlyByteSpan& sk, const SReadOnlyByteSpan& message,
        const SReadOnlyByteSpan& context, const SReadOnlyByteSpan& rnd, const SByteSpan& out
    ) {
        if (!params.isValid()) {
            return false;
        }
        if (sk.size != params.privateKeyBytes() || !sk.data) {
            return false;
        }
        if (context.size > MAX_CONTEXT_BYTES) {
            return false;
        }

        // --> mu is computed here and handed to signInternal() as its externalMu, instead of
        // building M' = 0x00 || |ctx| || ctx || M into one buffer and passing that. Both give
        // bit-identical results, because mu is H(tr || M') and H absorbs the parts in order --
        // but this way the message is never copied, which matters when it is a multi-megabyte
        // document rather than a 3 KiB TBSCertificate. tr lives at a fixed offset in the private
        // key (FIPS 204 Algorithm 24: rho || K || tr), so reading it costs nothing either.
        const uint8_t prefix[2] = { 0x00, uint8_t(context.size) };

        uint8_t mu[MU_BYTES];
        if (!hashH({ sk.slice(2 * RHO_BYTES, MU_BYTES),
                     SReadOnlyByteSpan(prefix, sizeof(prefix)), context, message },
                   SByteSpan(mu, sizeof(mu))))
        {
            return false;
        }

        return signInternal(
            params, sk, SReadOnlyByteSpan(nullptr, 0), SReadOnlyByteSpan(mu, sizeof(mu)), rnd,
            out);
    }

    /* ML-DSA.Verify (FIPS 204 Algorithm 3), the pure external interface. */
    bool MlDsaScheme::verify(
        const MlDsaParams& params, const SReadOnlyByteSpan& pk, const SReadOnlyByteSpan& message,
        const SReadOnlyByteSpan& context, const SReadOnlyByteSpan& signature
    ) {
        if (!params.isValid()) {
            return false;
        }
        if (pk.size != params.publicKeyBytes() || !pk.data) {
            return false;
        }
        if (context.size > MAX_CONTEXT_BYTES) {
            return false;
        }

        uint8_t tr[MU_BYTES];
        if (!hashH({ pk }, SByteSpan(tr, sizeof(tr)))) {
            return false;
        }

        const uint8_t prefix[2] = { 0x00, uint8_t(context.size) };

        uint8_t mu[MU_BYTES];
        if (!hashH({ SReadOnlyByteSpan(tr, sizeof(tr)),
                     SReadOnlyByteSpan(prefix, sizeof(prefix)), context, message },
                   SByteSpan(mu, sizeof(mu))))
        {
            return false;
        }

        return verifyInternal(
            params, pk, SReadOnlyByteSpan(nullptr, 0), SReadOnlyByteSpan(mu, sizeof(mu)),
            signature);
    }

    /* Length check; pkDecode() cannot fail on a correctly sized input. */
    bool MlDsaScheme::checkPublicKey(const MlDsaParams& params, const SReadOnlyByteSpan& pk) {
        return params.isValid() && pk.data && pk.size == params.publicKeyBytes();
    }

    /* Length check plus skDecode()'s s1/s2 range check. */
    bool MlDsaScheme::checkPrivateKey(const MlDsaParams& params, const SReadOnlyByteSpan& sk) {
        if (!params.isValid() || !sk.data || sk.size != params.privateKeyBytes()) {
            return false;
        }

        uint8_t rho[RHO_BYTES];
        uint8_t keySeed[RHO_BYTES];
        uint8_t tr[MU_BYTES];

        TArray<Poly> s1;
        TArray<Poly> s2;
        TArray<Poly> t0;
        PolyScrubber s1Scrub{ s1 };
        PolyScrubber s2Scrub{ s2 };
        PolyScrubber t0Scrub{ t0 };
        ByteScrubber keySeedScrub{ keySeed, sizeof(keySeed) };

        if (!s1.resize(params.l) || !s2.resize(params.k) || !t0.resize(params.k)) {
            return false;
        }

        return skDecode(
            params, sk, SByteSpan(rho, sizeof(rho)), SByteSpan(keySeed, sizeof(keySeed)),
            SByteSpan(tr, sizeof(tr)), s1.begin(), s2.begin(), t0.begin());
    }

    /* Re-derives the public key from a private key's own rho/s1/s2. */
    bool MlDsaScheme::publicKeyOf(
        const MlDsaParams& params, const SReadOnlyByteSpan& sk, const SByteSpan& pk,
        bool& consistent
    ) {
        consistent = false;

        if (!params.isValid()) {
            return false;
        }
        if (sk.size != params.privateKeyBytes() || !sk.data) {
            return false;
        }
        if (pk.size != params.publicKeyBytes() || !pk.data) {
            return false;
        }

        uint8_t rho[RHO_BYTES];
        uint8_t keySeed[RHO_BYTES];
        uint8_t tr[MU_BYTES];

        TArray<Poly> s1;
        TArray<Poly> s2;
        TArray<Poly> t0;
        PolyScrubber s1Scrub{ s1 };
        PolyScrubber s2Scrub{ s2 };
        PolyScrubber t0Scrub{ t0 };
        ByteScrubber keySeedScrub{ keySeed, sizeof(keySeed) };

        if (!s1.resize(params.l) || !s2.resize(params.k) || !t0.resize(params.k)) {
            return false;
        }

        if (!skDecode(
                params, sk, SByteSpan(rho, sizeof(rho)), SByteSpan(keySeed, sizeof(keySeed)),
                SByteSpan(tr, sizeof(tr)), s1.begin(), s2.begin(), t0.begin()))
        {
            return false;
        }

        TArray<Poly> aHat;
        TArray<Poly> s1Hat;
        TArray<Poly> t;
        TArray<Poly> t1;
        TArray<Poly> low;
        PolyScrubber s1HatScrub{ s1Hat };
        PolyScrubber tScrub{ t };
        PolyScrubber lowScrub{ low };

        if (!aHat.resize(params.k * params.l) || !s1Hat.resize(params.l)
            || !t.resize(params.k) || !t1.resize(params.k) || !low.resize(params.k))
        {
            return false;
        }

        if (!MlDsaSampler::expandA(
                SReadOnlyByteSpan(rho, sizeof(rho)), params.k, params.l, aHat.begin()))
        {
            return false;
        }

        toNttDomain(s1.begin(), params.l, s1Hat.begin());
        matrixVectorNtt(aHat.begin(), s1Hat.begin(), params.k, params.l, t.begin());

        for (size_t i = 0; i < params.k; ++i) {
            MlDsaRing::inverseNtt(t.begin()[i]);
            MlDsaRing::add(t.begin()[i], t.begin()[i], s2.begin()[i]);
            MlDsaRounding::power2Round(t.begin()[i], t1.begin()[i], low.begin()[i]);
        }

        if (!pkEncode(params, SReadOnlyByteSpan(rho, sizeof(rho)), t1.begin(), pk)) {
            return false;
        }

        uint8_t derivedTr[MU_BYTES];
        if (!hashH({ SReadOnlyByteSpan(pk) }, SByteSpan(derivedTr, sizeof(derivedTr)))) {
            return false;
        }

        if (std::memcmp(derivedTr, tr, sizeof(tr)) != 0) {
            return true;    // --> consistent stays false; the caller decides what to do.
        }

        // --> tr == H(pk) alone does not cover t0: the same rho/s1/s2 produce the same pk and
        // therefore the same tr whatever t0 says, and a wrong t0 only shows up later as hints
        // that no verifier accepts. Power2Round's low part is the t0 this key should carry, so
        // comparing them is the remaining half of the check.
        for (size_t i = 0; i < params.k; ++i) {
            for (size_t j = 0; j < MlDsaRing::N; ++j) {
                if (low.begin()[i].coeffs[j] != t0.begin()[i].coeffs[j]) {
                    return true;
                }
            }
        }

        consistent = true;
        return true;
    }

} // namespace crypto
} // namespace certpp
