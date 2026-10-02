#ifndef __INCLUDE_CERTPP_CRYPTO_KEMS_MLKEM_HPP__
#define __INCLUDE_CERTPP_CRYPTO_KEMS_MLKEM_HPP__

#include <certpp/crypto/kem.hpp>
#include <certpp/crypto/pq/mlkem.hpp>

namespace certpp {
namespace crypto {

    /**
     * ML-KEM (FIPS 203) as an IKem, for all three parameter sets -- one instance per set, the
     * same arrangement CEcdsa has across its curves. This is the shape most callers should
     * prefer; CMlKem (crypto/pq/mlkem.hpp) is the algorithm underneath it, and this class
     * implements nothing itself beyond key objects, size bookkeeping and the CSPRNG draws.
     *
     * keySizes() accepts exactly one size, and it is the parameter set's own number (512, 768 or
     * 1024) rather than a modulus width or a claimed security strength. ML-KEM has no size that
     * can be scaled: the three sets differ in the module rank k and four other parameters, and
     * 512/768/1024 are names. Passing the number keeps generateKeyPair() usable the way every
     * other IAsymmetric/IKem in this library is, without inventing a figure that looks like it
     * means something it doesn't.
     *
     * Keys serialize as FIPS 203's own byte encodings and nothing more -- a public key is the
     * encapsulation key (800/1184/1568 bytes), a private key the decapsulation key
     * (1632/2400/3168). Since a decapsulation key embeds its own encapsulation key,
     * IKemPrivateKey::publicKey() reads it out rather than recomputing it. The
     * SubjectPublicKeyInfo wrapping that a certificate needs is not here; see
     * docs/pqc-review.md's Phase 6.
     *
     * This is also the layer where randomness enters. CMlKem::generateKeyPair()/encapsulate()
     * take their seeds and message as parameters so they can be driven from a test vector;
     * IKemContext::encapsulate() has no such parameter, so this class draws from CRng and is the
     * only part of the ML-KEM implementation that does.
     */
    class CERTPP_API MLKEM : public IKem {
    private:
        SMlKemParams _params;
        EKems _which;  // --> The specific parameter set, for IKemKeyBase::algorithm() --
                       // SMlKemParams itself carries only the five figures, no identity.

    public:
        /**
         * Maps an EKems value to the parameter set it names.
         * @param which The parameter set to look up.
         * @param out Receives the parameter set on success; untouched otherwise.
         * @return true if which is one of the three ML-KEM members of EKems.
         */
        static bool paramsOf(EKems which, SMlKemParams& out);

    public:
        /**
         * Constructs an ML-KEM instance for one parameter set; keySizes() accepts exactly that
         * set's number. An unrecognized value yields an instance whose keySizes() is empty and
         * whose every operation fails, rather than an exception -- IKem::builtIn() returns null
         * for such a value and is the way this is normally reached.
         * @param which The parameter set to run.
         */
        explicit MLKEM(EKems which);

        /**
         * @return The parameter set this instance runs.
         */
        inline const SMlKemParams& params() const {
            return _params;
        }

        ERetCode generateKeyPair(SKeySize keySize, SKemKeyPair& out) override;
        ERetCode checkPrivateKey(const IKemPrivateKeyPtr& key) const override;
        IKemPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const override;
        IKemPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const override;
        IKemContextPtr createContext() const override;
    };

} // namespace crypto
} // namespace certpp

#endif
