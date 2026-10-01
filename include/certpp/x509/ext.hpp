#ifndef __INCLUDE_CERTPP_X509_EXT_HPP__
#define __INCLUDE_CERTPP_X509_EXT_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/buffer.hpp>

namespace certpp {
namespace x509 {

    /**
     * Forward declaration of the IExtension and IExtensionBuilder interface.
     */
    class IExtension;
    class IExtensionBuilder;

    /**
     * Shared pointer type for the IExtension interface.
     */
    using IExtensionPtr = std::shared_ptr<IExtension>;
    using IExtensionBuilderPtr = std::shared_ptr<IExtensionBuilder>;

    /**
     * Interface for X.509 extensions.
     */
    class CERTPP_API IExtension {
    private:
        CString _oid;
        COctet _value;
        bool _critical = false;

    public:
        /**
         * Factory method to create an instance of IExtension. Dispatches by oid to the matching
         * concrete IExtension subclass under x509/exts/ (see IExtension::create()'s definition in
         * ext.cpp for the dispatch table); falls back to a generic, oid()/value()-only instance
         * for any OID this library doesn't model further, so this never returns null for a
         * present extension.
         *
         * @param oid The OID of the extension.
         * @param value The value of the extension.
         * @return A shared pointer to the created IExtension instance.
         */
        static IExtensionPtr create(const CString& oid, const COctet& value);

    public:
        /**
         * Constructor.
         *
         * @param oid The OID of the extension.
         * @param value The value of the extension.
         */
        IExtension(const CString& oid, const COctet& value) : _oid(oid), _value(value) { }

        /**
         * Constructor with rvalue reference for the value.
         *
         * @param oid The OID of the extension.
         * @param value The value of the extension.
         */
        IExtension(const CString& oid, COctet&& value) : _oid(oid), _value(std::move(value)) { }

        /**
         * Destructor.
         */
        virtual ~IExtension() = default;

        /**
         * Gets the OID of the extension.
         *
         * @return The OID of the extension.
         */
        inline const CString& oid() const {
            return _oid;
        }

        /**
         * Gets the value of the extension.
         *
         * @return The value of the extension.
         */
        inline const COctet& value() const {
            return _value;
        }

        /**
         * Whether this extension was marked critical (Extension.critical, RFC 5280 4.2: "If a
         * CA does not recognize [a critical] extension type, then it MUST treat the certificate
         * as invalid" -- a relying party is expected to apply the same rule for any critical
         * extension type it doesn't itself recognize). Defaults to false (DER's own default for
         * an absent/unparsed critical field); CCert::parseExtensions() sets it to the value
         * actually read from a parsed certificate's Extension.critical field.
         * @return true if this extension was marked critical.
         */
        inline bool critical() const {
            return _critical;
        }

        /**
         * Sets whether this extension is critical. Exposed so CCert::parseExtensions() can
         * record the value it parsed from Extension.critical after IExtension::create()
         * constructs the concrete instance (every concrete subclass's own constructor only
         * takes oid/value, so this is set as a separate step rather than threaded through all of
         * them) -- and so IExtensionBuilder subclasses can opt an extension they build into
         * being critical.
         * @param value The new critical flag.
         */
        inline void critical(bool value) {
            _critical = value;
        }

        /**
         * @brief Encodes this extension into its DER representation.
         *
         * @param out The destination buffer to append the encoded data to.
         * @return true on success; false if encoding fails.
         */
        virtual bool encode(CBuffer& out) const = 0;

    protected:
        /**
         * @brief Appends value()'s already-encoded bytes to out. Every concrete extension type
         * under x509/exts/ is immutable after construction (parsing or IExtensionBuilder::build()
         * both settle value() once, up front), so encode() has nothing further to derive -- this
         * is the shared body every one of their encode() overrides delegates to.
         * @param out The destination buffer; value()'s bytes are appended to whatever it already holds.
         * @return true on success; false if out couldn't be grown.
         */
        bool encodeValue(CBuffer& out) const;
    };

    /**
     * Interface for building X.509 extensions.
     */
    class CERTPP_API IExtensionBuilder {
    public:
        /**
         * Destructor.
         */
        virtual ~IExtensionBuilder() = default;

    public:
        /**
         * Builds and returns an IExtension instance.
         *
         * @return A shared pointer to the created IExtension instance; nullptr if this builder's
         * current field values can't be DER-encoded (e.g. a malformed OID string).
         */
        virtual IExtensionPtr build() const = 0;
    };

}
}

#endif