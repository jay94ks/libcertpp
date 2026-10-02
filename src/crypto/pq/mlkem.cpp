#include <certpp/crypto/pq/mlkem.hpp>
#include "mlkemring.hpp"
#include "mlkemcodec.hpp"
#include <certpp/crypto/hashers/sha3_256.hpp>
#include <certpp/crypto/hashers/sha3_512.hpp>
#include <certpp/crypto/hashers/shake256.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    /* H(x) = SHA3-256(x). */
    bool CMlKem::hashH(const SReadOnlyByteSpan& input, const SByteSpan& out) {
        if (out.size != 32 || !out.data) {
            return false;
        }

        SHA3_256 hasher;
        if (!input.empty() && hasher.push(input) != input.size) {
            return false;
        }

        SByteSpan span(out.data, out.size);
        return hasher.finish(span);
    }

    /* G(x) = SHA3-512(x), split in half. */
    bool CMlKem::hashG(
        const SReadOnlyByteSpan& input, const SByteSpan& firstHalf, const SByteSpan& secondHalf
    ) {
        if (firstHalf.size != 32 || secondHalf.size != 32 || !firstHalf.data || !secondHalf.data) {
            return false;
        }

        SHA3_512 hasher;
        if (!input.empty() && hasher.push(input) != input.size) {
            return false;
        }

        uint8_t full[64];
        SByteSpan span(full, sizeof(full));
        if (!hasher.finish(span)) {
            return false;
        }

        std::memcpy(firstHalf.data, full, 32);
        std::memcpy(secondHalf.data, full + 32, 32);
        return true;
    }

    /* J(x) = SHAKE256(x, 32). */
    bool CMlKem::hashJ(const SReadOnlyByteSpan& input, const SByteSpan& out) {
        if (out.size != 32 || !out.data) {
            return false;
        }

        SHAKE256 xof;
        if (!input.empty() && xof.push(input) != input.size) {
            return false;
        }

        return xof.squeeze(out);
    }

    /* PRF_eta(s, b) = SHAKE256(s || b, 64*eta). */
    bool CMlKem::prf(
        size_t eta, const SReadOnlyByteSpan& seed, uint8_t counter, const SByteSpan& out
    ) {
        if (seed.size != 32 || !seed.data || out.size != 64 * eta) {
            return false;
        }

        // --> eta is only an output *length* here, not domain separation: FIPS 203 says so
        // explicitly, which means PRF_2 and PRF_3 on the same (s, b) share a prefix. Nothing in
        // ML-KEM ever calls both with the same input, but it is worth not mistaking the length for
        // a tag.
        uint8_t input[33];
        std::memcpy(input, seed.data, 32);
        input[32] = counter;

        SHAKE256 xof;
        if (xof.push(SReadOnlyByteSpan(input, sizeof(input))) != sizeof(input)) {
            return false;
        }

        return xof.squeeze(out);
    }

    /* K-PKE.KeyGen (FIPS 203 Algorithm 13). */
    bool CMlKem::kpkeKeyGen(
        const SMlKemParams& params, const SReadOnlyByteSpan& d,
        const SByteSpan& ekPke, const SByteSpan& dkPke
    ) {
        const size_t k = params.k;

        // params is caller-supplied, and every fixed-capacity buffer below is sized from MAX_K or
        // maxCiphertextBytes() -- so a set outside FIPS 203's three would overflow them. Rejecting
        // it is what makes those sizes sound; see SMlKemParams::isValid(). Every entry point in
        // this file does the same, first, before deriving anything from params.
        if (!params.isValid()) {
            return false;
        }
        if (d.size != 32 || !d.data) {
            return false;
        }
        if (ekPke.size != params.ekBytes() || dkPke.size != params.dkPkeBytes()) {
            return false;
        }

        // --> (rho, sigma) = G(d || k). That trailing parameter byte is the domain separator added
        // after FIPS 203's initial public draft; omitting it -- as round-3 Kyber code does -- still
        // produces a working, self-consistent scheme that interoperates with nothing.
        uint8_t seeded[33];
        std::memcpy(seeded, d.data, 32);
        seeded[32] = uint8_t(k);

        uint8_t rho[32];
        uint8_t sigma[32];
        if (!hashG(SReadOnlyByteSpan(seeded, sizeof(seeded)),
                   SByteSpan(rho, sizeof(rho)), SByteSpan(sigma, sizeof(sigma))))
        {
            return false;
        }

        const SReadOnlyByteSpan rhoSpan(rho, sizeof(rho));
        const SReadOnlyByteSpan sigmaSpan(sigma, sizeof(sigma));

        // --> A-hat[i][j] = SampleNTT(rho || j || i). The index bytes are transposed relative to
        // the loop order, which the standard's own margin note calls out; getting this backwards
        // transposes the matrix and changes every key byte.
        SMlKemPoly aHat[SMlKemParams::MAX_K][SMlKemParams::MAX_K];
        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < k; ++j) {
                if (!CMlKemSampler::sampleNtt(rhoSpan, uint8_t(j), uint8_t(i), aHat[i][j])) {
                    return false;
                }
            }
        }

        uint8_t prfOut[64 * 3];
        uint8_t counter = 0;

        SMlKemPoly sHat[SMlKemParams::MAX_K];
        for (size_t i = 0; i < k; ++i) {
            const SByteSpan outSpan(prfOut, 64 * params.eta1);
            if (!prf(params.eta1, sigmaSpan, counter, outSpan)) {
                return false;
            }
            ++counter;

            if (!CMlKemSampler::samplePolyCbd(params.eta1, outSpan, sHat[i])) {
                return false;
            }

            MlKemRing::ntt(sHat[i]);
        }

        SMlKemPoly eHat[SMlKemParams::MAX_K];
        for (size_t i = 0; i < k; ++i) {
            const SByteSpan outSpan(prfOut, 64 * params.eta1);
            if (!prf(params.eta1, sigmaSpan, counter, outSpan)) {
                return false;
            }
            ++counter;

            if (!CMlKemSampler::samplePolyCbd(params.eta1, outSpan, eHat[i])) {
                return false;
            }

            MlKemRing::ntt(eHat[i]);
        }

        // t-hat = A-hat * s-hat + e-hat, all in the NTT domain.
        for (size_t i = 0; i < k; ++i) {
            SMlKemPoly accumulator;
            MlKemRing::setZero(accumulator);

            for (size_t j = 0; j < k; ++j) {
                SMlKemPoly product;
                MlKemRing::multiplyNtt(product, aHat[i][j], sHat[j]);
                MlKemRing::add(accumulator, accumulator, product);
            }

            MlKemRing::add(accumulator, accumulator, eHat[i]);

            if (!MlKemCodec::byteEncode(12, accumulator, SByteSpan(ekPke.data + 384 * i, 384))) {
                return false;
            }
        }

        std::memcpy(ekPke.data + 384 * k, rho, 32);

        for (size_t i = 0; i < k; ++i) {
            if (!MlKemCodec::byteEncode(12, sHat[i], SByteSpan(dkPke.data + 384 * i, 384))) {
                return false;
            }
        }

        // --> sigma and everything sampled from it reconstruct the secret key, so they are cleared
        // before this frame is reused. rho isn't: it goes into ekPke and is public. Unlike
        // decapsulate(), this clears only on the success path -- the early returns above all mean a
        // hasher or sampler failed at a fixed, correct size, so none is reachable, and threading a
        // status through the loops to cover them would cost more clarity than it buys. decapsulate()
        // is restructured for it because clearing there is a normative FIPS 203 requirement about
        // the reject flag rather than defence in depth.
        CSecure::zero(SByteSpan(seeded, sizeof(seeded)));
        CSecure::zero(SByteSpan(sigma, sizeof(sigma)));
        CSecure::zero(SByteSpan(prfOut, sizeof(prfOut)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(sHat), sizeof(sHat)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(eHat), sizeof(eHat)));

        return true;
    }

    /* K-PKE.Encrypt (FIPS 203 Algorithm 14). */
    bool CMlKem::kpkeEncrypt(
        const SMlKemParams& params, const SReadOnlyByteSpan& ekPke,
        const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& randomness,
        const SByteSpan& ciphertext
    ) {
        const size_t k = params.k;

        if (!params.isValid()) {
            return false;
        }
        if (ekPke.size != params.ekBytes() || !ekPke.data) {
            return false;
        }
        if (message.size != 32 || !message.data) {
            return false;
        }
        if (randomness.size != 32 || !randomness.data) {
            return false;
        }
        if (ciphertext.size != params.ciphertextBytes() || !ciphertext.data) {
            return false;
        }

        SMlKemPoly tHat[SMlKemParams::MAX_K];
        for (size_t i = 0; i < k; ++i) {
            if (!MlKemCodec::byteDecode(12, SReadOnlyByteSpan(ekPke.data + 384 * i, 384), tHat[i])) {
                return false;
            }
        }

        const SReadOnlyByteSpan rhoSpan(ekPke.data + 384 * k, 32);

        // Same sampling byte order as KeyGen; the transpose is applied when multiplying, below.
        SMlKemPoly aHat[SMlKemParams::MAX_K][SMlKemParams::MAX_K];
        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < k; ++j) {
                if (!CMlKemSampler::sampleNtt(rhoSpan, uint8_t(j), uint8_t(i), aHat[i][j])) {
                    return false;
                }
            }
        }

        uint8_t prfOut[64 * 3];
        uint8_t counter = 0;

        SMlKemPoly yHat[SMlKemParams::MAX_K];
        for (size_t i = 0; i < k; ++i) {
            const SByteSpan outSpan(prfOut, 64 * params.eta1);
            if (!prf(params.eta1, randomness, counter, outSpan)) {
                return false;
            }
            ++counter;

            if (!CMlKemSampler::samplePolyCbd(params.eta1, outSpan, yHat[i])) {
                return false;
            }

            MlKemRing::ntt(yHat[i]);
        }

        SMlKemPoly e1[SMlKemParams::MAX_K];
        for (size_t i = 0; i < k; ++i) {
            const SByteSpan outSpan(prfOut, 64 * params.eta2);
            if (!prf(params.eta2, randomness, counter, outSpan)) {
                return false;
            }
            ++counter;

            if (!CMlKemSampler::samplePolyCbd(params.eta2, outSpan, e1[i])) {
                return false;
            }
        }

        SMlKemPoly e2;
        {
            const SByteSpan outSpan(prfOut, 64 * params.eta2);
            if (!prf(params.eta2, randomness, counter, outSpan)) {
                return false;
            }
            if (!CMlKemSampler::samplePolyCbd(params.eta2, outSpan, e2)) {
                return false;
            }
        }

        // u = NTT^-1(A-hat^T * y-hat) + e1. The transpose is the aHat[j][i] indexing here.
        const size_t c1Stride = 32 * params.du;
        for (size_t i = 0; i < k; ++i) {
            SMlKemPoly accumulator;
            MlKemRing::setZero(accumulator);

            for (size_t j = 0; j < k; ++j) {
                SMlKemPoly product;
                MlKemRing::multiplyNtt(product, aHat[j][i], yHat[j]);
                MlKemRing::add(accumulator, accumulator, product);
            }

            MlKemRing::inverseNtt(accumulator);
            MlKemRing::add(accumulator, accumulator, e1[i]);

            if (!MlKemCodec::compress(params.du, accumulator)) {
                return false;
            }
            if (!MlKemCodec::byteEncode(
                    params.du, accumulator, SByteSpan(ciphertext.data + c1Stride * i, c1Stride)))
            {
                return false;
            }
        }

        // v = NTT^-1(t-hat^T * y-hat) + e2 + Decompress_1(ByteDecode_1(message))
        SMlKemPoly v;
        MlKemRing::setZero(v);
        for (size_t i = 0; i < k; ++i) {
            SMlKemPoly product;
            MlKemRing::multiplyNtt(product, tHat[i], yHat[i]);
            MlKemRing::add(v, v, product);
        }
        MlKemRing::inverseNtt(v);
        MlKemRing::add(v, v, e2);

        SMlKemPoly mu;
        if (!MlKemCodec::byteDecode(1, message, mu) || !MlKemCodec::decompress(1, mu)) {
            return false;
        }
        MlKemRing::add(v, v, mu);

        if (!MlKemCodec::compress(params.dv, v)) {
            return false;
        }

        return MlKemCodec::byteEncode(
            params.dv, v, SByteSpan(ciphertext.data + c1Stride * k, 32 * params.dv)
        );
    }

    /* K-PKE.Decrypt (FIPS 203 Algorithm 15). */
    bool CMlKem::kpkeDecrypt(
        const SMlKemParams& params, const SReadOnlyByteSpan& dkPke,
        const SReadOnlyByteSpan& ciphertext, const SByteSpan& message
    ) {
        const size_t k = params.k;

        if (!params.isValid()) {
            return false;
        }
        if (dkPke.size != params.dkPkeBytes() || !dkPke.data) {
            return false;
        }
        if (ciphertext.size != params.ciphertextBytes() || !ciphertext.data) {
            return false;
        }
        if (message.size != 32 || !message.data) {
            return false;
        }

        const size_t c1Stride = 32 * params.du;

        SMlKemPoly u[SMlKemParams::MAX_K];
        for (size_t i = 0; i < k; ++i) {
            if (!MlKemCodec::byteDecode(
                    params.du, SReadOnlyByteSpan(ciphertext.data + c1Stride * i, c1Stride), u[i]))
            {
                return false;
            }
            if (!MlKemCodec::decompress(params.du, u[i])) {
                return false;
            }

            MlKemRing::ntt(u[i]);
        }

        SMlKemPoly v;
        if (!MlKemCodec::byteDecode(
                params.dv, SReadOnlyByteSpan(ciphertext.data + c1Stride * k, 32 * params.dv), v))
        {
            return false;
        }
        if (!MlKemCodec::decompress(params.dv, v)) {
            return false;
        }

        // w = v - NTT^-1(s-hat^T * NTT(u))
        SMlKemPoly accumulator;
        MlKemRing::setZero(accumulator);

        for (size_t i = 0; i < k; ++i) {
            SMlKemPoly sHat;
            if (!MlKemCodec::byteDecode(12, SReadOnlyByteSpan(dkPke.data + 384 * i, 384), sHat)) {
                return false;
            }

            SMlKemPoly product;
            MlKemRing::multiplyNtt(product, sHat, u[i]);
            MlKemRing::add(accumulator, accumulator, product);
        }

        MlKemRing::inverseNtt(accumulator);
        MlKemRing::sub(v, v, accumulator);

        if (!MlKemCodec::compress(1, v)) {
            return false;
        }

        const bool encoded = MlKemCodec::byteEncode(1, v, message);

        // accumulator held s-hat^T * NTT(u), which is derived from the decapsulation key; v held
        // the recovered message before it was encoded out. The loop's own sHat copies go out of
        // scope each iteration and are not reachable from here.
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(&accumulator), sizeof(accumulator)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(&v), sizeof(v)));

        return encoded;
    }

    /* ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16). */
    bool CMlKem::generateKeyPair(
        const SMlKemParams& params, const SReadOnlyByteSpan& d, const SReadOnlyByteSpan& z,
        const SByteSpan& ek, const SByteSpan& dk
    ) {
        const size_t k = params.k;

        if (!params.isValid()) {
            return false;
        }
        if (z.size != 32 || !z.data) {
            return false;
        }
        if (ek.size != params.ekBytes() || !ek.data) {
            return false;
        }
        if (dk.size != params.dkBytes() || !dk.data) {
            return false;
        }

        // dk = dk_PKE || ek || H(ek) || z -- the decapsulation key carries everything decaps needs
        // for its re-encryption check, which is why it is more than twice the size of ek.
        if (!kpkeKeyGen(params, d, ek, SByteSpan(dk.data, params.dkPkeBytes()))) {
            return false;
        }

        std::memcpy(dk.data + 384 * k, ek.data, ek.size);

        if (!hashH(SReadOnlyByteSpan(ek.data, ek.size), SByteSpan(dk.data + 768 * k + 32, 32))) {
            return false;
        }

        std::memcpy(dk.data + 768 * k + 64, z.data, 32);
        return true;
    }

    /* ML-KEM.Encaps_internal (FIPS 203 Algorithm 17). */
    bool CMlKem::encapsulate(
        const SMlKemParams& params, const SReadOnlyByteSpan& ek, const SReadOnlyByteSpan& message,
        const SByteSpan& ciphertext, const SByteSpan& sharedSecret
    ) {
        if (!params.isValid()) {
            return false;
        }
        if (ek.size != params.ekBytes() || !ek.data) {
            return false;
        }
        if (message.size != 32 || !message.data) {
            return false;
        }
        if (sharedSecret.size != 32 || !sharedSecret.data) {
            return false;
        }
        if (ciphertext.size != params.ciphertextBytes() || !ciphertext.data) {
            return false;
        }

        // (K, r) = G(message || H(ek)). Binding the encapsulation key into the derivation is what
        // stops a ciphertext being replayed under a different key.
        uint8_t combined[64];
        std::memcpy(combined, message.data, 32);
        if (!hashH(ek, SByteSpan(combined + 32, 32))) {
            return false;
        }

        uint8_t randomness[32];
        if (!hashG(SReadOnlyByteSpan(combined, sizeof(combined)),
                   sharedSecret, SByteSpan(randomness, sizeof(randomness))))
        {
            return false;
        }

        const bool encrypted = kpkeEncrypt(
            params, ek, message, SReadOnlyByteSpan(randomness, sizeof(randomness)), ciphertext
        );

        // combined's first half is the message, which determines the shared secret; randomness
        // reproduces the ciphertext from it. H(ek) in the second half is public, but clearing the
        // whole buffer is simpler than clearing half of it and no less correct.
        CSecure::zero(SByteSpan(combined, sizeof(combined)));
        CSecure::zero(SByteSpan(randomness, sizeof(randomness)));

        return encrypted;
    }

    /* ML-KEM.Decaps_internal (FIPS 203 Algorithm 18). */
    bool CMlKem::decapsulate(
        const SMlKemParams& params, const SReadOnlyByteSpan& dk,
        const SReadOnlyByteSpan& ciphertext, const SByteSpan& sharedSecret
    ) {
        const size_t k = params.k;

        if (!params.isValid()) {
            return false;
        }
        if (dk.size != params.dkBytes() || !dk.data) {
            return false;
        }
        if (ciphertext.size != params.ciphertextBytes() || !ciphertext.data) {
            return false;
        }
        if (sharedSecret.size != 32 || !sharedSecret.data) {
            return false;
        }

        const SReadOnlyByteSpan dkPke(dk.data, params.dkPkeBytes());
        const SReadOnlyByteSpan ek(dk.data + 384 * k, params.ekBytes());
        const SReadOnlyByteSpan h(dk.data + 768 * k + 32, 32);
        const SReadOnlyByteSpan z(dk.data + 768 * k + 64, 32);

        // --> Single exit from here on, with every secret cleared at the bottom. FIPS 203 requires
        // the implicit-reject flag and the values it chose between to be destroyed before this
        // returns, and an early `return false` in the middle would skip that -- so the steps chain
        // through `ok` instead. Each of those failures needs a hasher to fail at a fixed, correct
        // output size, i.e. never; the structure is for the guarantee, not the likelihood.
        //
        // ciphertext.size is params.ciphertextBytes() and params is one of the three valid sets, so
        // it is at most maxCiphertextBytes() -- rejectionInput and reencrypted both fit.
        uint8_t recovered[32];
        uint8_t combined[64];
        uint8_t candidateSecret[32];
        uint8_t randomness[32];
        uint8_t rejectionInput[32 + SMlKemParams::maxCiphertextBytes()];
        uint8_t rejectionSecret[32];
        uint8_t reencrypted[SMlKemParams::maxCiphertextBytes()];
        uint8_t matches = 0;

        bool ok = kpkeDecrypt(params, dkPke, ciphertext, SByteSpan(recovered, sizeof(recovered)));

        if (ok) {
            std::memcpy(combined, recovered, 32);
            std::memcpy(combined + 32, h.data, 32);

            ok = hashG(SReadOnlyByteSpan(combined, sizeof(combined)),
                       SByteSpan(candidateSecret, sizeof(candidateSecret)),
                       SByteSpan(randomness, sizeof(randomness)));
        }

        if (ok) {
            // The implicit-rejection secret, derived from the private key's own z and the
            // ciphertext -- J(z || c), the value a tampered ciphertext resolves to.
            std::memcpy(rejectionInput, z.data, 32);
            std::memcpy(rejectionInput + 32, ciphertext.data, ciphertext.size);

            ok = hashJ(SReadOnlyByteSpan(rejectionInput, 32 + ciphertext.size),
                       SByteSpan(rejectionSecret, sizeof(rejectionSecret)));
        }

        if (ok) {
            // Re-encrypt and compare. A ciphertext that does not reproduce itself yields the
            // rejection secret rather than an error: the caller must not be able to tell the two
            // cases apart, which is what makes the FO transform chosen-ciphertext secure.
            // Reporting failure here would hand an attacker the decryption oracle the transform
            // exists to deny.
            ok = kpkeEncrypt(
                params, ek, SReadOnlyByteSpan(recovered, sizeof(recovered)),
                SReadOnlyByteSpan(randomness, sizeof(randomness)),
                SByteSpan(reencrypted, ciphertext.size));
        }

        if (ok) {
            // Both halves of this are constant-time on purpose, and neither can be written the
            // obvious way. memcmp() stops at the first mismatch, so its running time would reveal
            // how long a prefix of the re-encryption matched -- far more than the one bit the
            // transform is hiding. And `matches ? a : b` branches on the verdict, which *is* that
            // one bit. So the comparison yields a mask, and the mask drives a byte-wise select.
            matches = CSecure::equalsMask(
                SReadOnlyByteSpan(reencrypted, ciphertext.size), ciphertext);

            ok = CSecure::select(
                matches,
                SReadOnlyByteSpan(candidateSecret, sizeof(candidateSecret)),
                SReadOnlyByteSpan(rejectionSecret, sizeof(rejectionSecret)),
                sharedSecret);
        }

        // The decrypted message and the re-derived randomness matter most of these: either one
        // reconstructs the shared secret for a *valid* ciphertext, so leaving them in a stack frame
        // the next call reuses would undo the point of deriving them freshly each time. Only z is
        // cleared out of rejectionInput -- the ciphertext following it is public.
        CSecure::zero(SByteSpan(&matches, sizeof(matches)));
        CSecure::zero(SByteSpan(recovered, sizeof(recovered)));
        CSecure::zero(SByteSpan(combined, sizeof(combined)));
        CSecure::zero(SByteSpan(candidateSecret, sizeof(candidateSecret)));
        CSecure::zero(SByteSpan(randomness, sizeof(randomness)));
        CSecure::zero(SByteSpan(rejectionSecret, sizeof(rejectionSecret)));
        CSecure::zero(SByteSpan(rejectionInput, 32));

        return ok;
    }

    /* True iff ek is the right length and its encoded t-hat is canonical. */
    bool CMlKem::checkEncapsulationKey(const SMlKemParams& params, const SReadOnlyByteSpan& ek) {
        if (!params.isValid()) {
            return false;
        }
        if (ek.size != params.ekBytes() || !ek.data) {
            return false;
        }

        for (size_t i = 0; i < params.k; ++i) {
            if (!MlKemCodec::isCanonical12(SReadOnlyByteSpan(ek.data + 384 * i, 384))) {
                return false;
            }
        }

        return true;
    }

    /* True iff dk is the right length and its embedded H(ek) matches the ek it carries. */
    bool CMlKem::checkDecapsulationKey(const SMlKemParams& params, const SReadOnlyByteSpan& dk) {
        if (!params.isValid()) {
            return false;
        }
        if (dk.size != params.dkBytes() || !dk.data) {
            return false;
        }

        const size_t k = params.k;
        const SReadOnlyByteSpan ek(dk.data + 384 * k, params.ekBytes());

        uint8_t expected[32];
        if (!hashH(ek, SByteSpan(expected, sizeof(expected)))) {
            return false;
        }

        return std::memcmp(expected, dk.data + 768 * k + 32, 32) == 0;
    }

} // namespace crypto
} // namespace certpp
