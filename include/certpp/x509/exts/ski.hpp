#ifndef __INCLUDE_CERTPP_X509_EXTS_SKI_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_SKI_HPP__

#include <certpp/x509/ext.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief SubjectKeyIdentifier (RFC 5280 4.2.1.2, OID 2.5.29.14): an opaque identifier for
     * this certificate's public key, typically its SHA-1 hash, used to match against a child
     * certificate's AuthorityKeyIdentifier when building a certification path.
     */
    class CERTPP_API CSkiExtension : public IExtension {
    public:
        static constexpr const char* OID = "2.5.29.14"; // --> id-ce-subjectKeyIdentifier

    private:
        COctet _keyIdentifier;

    public:
        /**
         * @brief Parses a SubjectKeyIdentifier extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CSkiExtension(const COctet& value);

        /**
         * @brief The key identifier bytes. Empty if value didn't decode as an OCTET STRING.
         * @return The key identifier.
         */
        inline const COctet& keyIdentifier() const { return _keyIdentifier; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds a SubjectKeyIdentifier extension (see CSkiExtension).
     */
    class CERTPP_API CSkiExtensionBuilder : public IExtensionBuilder {
    private:
        COctet _keyIdentifier;

    public:
        /**
         * @brief Sets the key identifier bytes (typically the public key's SHA-1 hash).
         * @param keyIdentifier The key identifier bytes.
         * @return A reference to this builder, for chaining.
         */
        inline CSkiExtensionBuilder& setKeyIdentifier(const COctet& keyIdentifier) {
            _keyIdentifier = keyIdentifier;
            return *this;
        }

        /* Builds the SubjectKeyIdentifier extension. */
        IExtensionPtr build() const override;
    };

}
}

#endif
