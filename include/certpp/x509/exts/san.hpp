#ifndef __INCLUDE_CERTPP_X509_EXTS_SAN_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_SAN_HPP__

#include <certpp/x509/ext.hpp>
#include <certpp/x509/generalname.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief SubjectAltName (RFC 5280 4.2.1.6, OID 2.5.29.17): additional identities bound to
     * the certificate's subject (DNS names, IP addresses, email addresses, etc.), the field
     * most TLS/S-MIME implementations actually match a peer's identity against.
     */
    class CERTPP_API CSanExtension : public IExtension {
    public:
        static constexpr SKnownOid OID = COid::EXT_SUBJECT_ALT_NAME; // --> id-ce-subjectAltName

    private:
        TArray<CGeneralName> _names;

    public:
        /**
         * @brief Parses a SubjectAltName extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CSanExtension(const COctet& value);

        /**
         * @brief The decoded alternative names. Empty if value didn't decode as a GeneralNames
         * SEQUENCE.
         * @return The names.
         */
        inline const TArray<CGeneralName>& names() const { return _names; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds a SubjectAltName extension (see CSanExtension).
     */
    class CERTPP_API CSanExtensionBuilder : public IExtensionBuilder {
    private:
        TArray<CGeneralName> _names;

    public:
        /**
         * @brief Adds an alternative name.
         * @param name The name to add.
         * @return A reference to this builder, for chaining.
         */
        inline CSanExtensionBuilder& addName(const CGeneralName& name) {
            _names.add(name);
            return *this;
        }

        /* Builds the SubjectAltName extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
