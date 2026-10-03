#ifndef __INCLUDE_CERTPP_X509_EXTS_AKI_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_AKI_HPP__

#include <certpp/x509/ext.hpp>
#include <certpp/x509/generalname.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief AuthorityKeyIdentifier (RFC 5280 4.2.1.1, OID 2.5.29.35): identifies the issuing
     * CA's key used to sign this certificate -- keyIdentifier() is by far the most commonly
     * populated field in practice, meant to match a candidate issuer's own
     * CSkiExtension when building a certification path.
     * authorityCertIssuer()/authorityCertSerialNumber() are an alternative (rarely used)
     * identification method and are usually both empty.
     */
    class CERTPP_API CAkiExtension : public IExtension {
    public:
        static constexpr const char* OID = "2.5.29.35"; // --> id-ce-authorityKeyIdentifier

    private:
        COctet _keyIdentifier;
        TArray<CGeneralName> _authorityCertIssuer;
        COctet _authorityCertSerialNumber;

    public:
        /**
         * @brief Parses an AuthorityKeyIdentifier extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CAkiExtension(const COctet& value);

        /**
         * @brief Whether keyIdentifier() is present (every field of AuthorityKeyIdentifier is
         * OPTIONAL).
         * @return true if present.
         */
        inline bool hasKeyIdentifier() const { return !_keyIdentifier.empty(); }

        /**
         * @brief The issuing CA's key identifier, matching its own
         * CSkiExtension::keyIdentifier(). Empty if absent.
         * @return The key identifier.
         */
        inline const COctet& keyIdentifier() const { return _keyIdentifier; }

        /**
         * @brief The issuing certificate's issuer, as an alternative to keyIdentifier(). Empty
         * if absent.
         * @return The names.
         */
        inline const TArray<CGeneralName>& authorityCertIssuer() const { return _authorityCertIssuer; }

        /**
         * @brief Whether authorityCertSerialNumber() is present.
         * @return true if present.
         */
        inline bool hasAuthorityCertSerialNumber() const { return !_authorityCertSerialNumber.empty(); }

        /**
         * @brief The issuing certificate's serial number, paired with authorityCertIssuer() as
         * an alternative to keyIdentifier(). Raw two's-complement big-endian content, same
         * convention as CCert::serialNumber(). Empty if absent.
         * @return The serial number.
         */
        inline const COctet& authorityCertSerialNumber() const { return _authorityCertSerialNumber; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds an AuthorityKeyIdentifier extension (see CAkiExtension).
     */
    class CERTPP_API CAkiExtensionBuilder : public IExtensionBuilder {
    private:
        COctet _keyIdentifier;
        TArray<CGeneralName> _authorityCertIssuer;
        COctet _authorityCertSerialNumber;

    public:
        /**
         * @brief Sets the issuing CA's key identifier, matching its own
         * CSkiExtension::keyIdentifier().
         * @param keyIdentifier The key identifier bytes.
         * @return A reference to this builder, for chaining.
         */
        inline CAkiExtensionBuilder& setKeyIdentifier(const COctet& keyIdentifier) {
            _keyIdentifier = keyIdentifier;
            return *this;
        }

        /**
         * @brief Adds a name to the issuing certificate's issuer, an alternative to
         * keyIdentifier().
         * @param name The name to add.
         * @return A reference to this builder, for chaining.
         */
        inline CAkiExtensionBuilder& addAuthorityCertIssuer(const CGeneralName& name) {
            _authorityCertIssuer.add(name);
            return *this;
        }

        /**
         * @brief Sets the issuing certificate's serial number, paired with
         * authorityCertIssuer() as an alternative to keyIdentifier(). Raw two's-complement
         * big-endian content, same convention as CCert::serialNumber().
         * @param serialNumber The serial number bytes.
         * @return A reference to this builder, for chaining.
         */
        inline CAkiExtensionBuilder& setAuthorityCertSerialNumber(const COctet& serialNumber) {
            _authorityCertSerialNumber = serialNumber;
            return *this;
        }

        /* Builds the AuthorityKeyIdentifier extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
