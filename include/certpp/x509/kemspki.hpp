#ifndef __INCLUDE_CERTPP_X509_KEMSPKI_HPP__
#define __INCLUDE_CERTPP_X509_KEMSPKI_HPP__

#include <certpp/common.hpp>
#include <certpp/crypto/kem.hpp>
#include <certpp/io/buffer.hpp>

namespace certpp {
namespace x509 {

    /** RFC 9935 SubjectPublicKeyInfo codec for ML-KEM encapsulation keys. */
    class CERTPP_API CKemSubjectPublicKeyInfo {
    public:
        /** Encodes an ML-KEM public key as DER SubjectPublicKeyInfo. */
        static ERetCode encode(const crypto::IKemPublicKeyPtr& key, CBuffer& out);

        /**
         * Decodes a DER SubjectPublicKeyInfo carrying an ML-KEM public key.
         * AlgorithmIdentifier parameters must be absent and the BIT STRING must be byte-aligned.
         */
        static ERetCode decode(
            SReadOnlyByteSpan der, crypto::EKems& outAlgorithm,
            crypto::IKemPublicKeyPtr& outKey
        );
    };

} // namespace x509
} // namespace certpp

#endif
