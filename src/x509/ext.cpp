#include <certpp/x509/ext.hpp>
#include <certpp/x509/exts/bc.hpp>
#include <certpp/x509/exts/ku.hpp>
#include <certpp/x509/exts/eku.hpp>
#include <certpp/x509/exts/san.hpp>
#include <certpp/x509/exts/ski.hpp>
#include <certpp/x509/exts/aki.hpp>
#include <certpp/x509/exts/cdp.hpp>
#include <certpp/x509/exts/aia.hpp>
#include <certpp/x509/exts/cp.hpp>
#include <certpp/x509/exts/nc.hpp>
#include <cstring>

namespace certpp {
namespace x509 {

    /**
     * Represents an unknown X.509 extension.
     */
    class UnknownExtension : public IExtension {
    public:
        UnknownExtension(const CString& oid, const COctet& value) : IExtension(oid, value) { }
        UnknownExtension(const CString& oid, COctet&& value) : IExtension(oid, std::move(value)) { }

        bool encode(CBuffer& out) const override { return encodeValue(out); }
    };

    /* Appends value()'s already-encoded bytes to out. */
    bool IExtension::encodeValue(CBuffer& out) const {
        size_t oldSize = out.size();
        if (!out.resize(oldSize + _value.size())) {
            return false;
        }

        if (_value.size()) {
            std::memcpy(out.toPtr() + oldSize, _value.toPtr(), _value.size());
        }

        return true;
    }

    /**
     * Factory method implementation for creating an IExtension instance: dispatches by OID to
     * the matching concrete IExtension subclass, falling back to UnknownExtension (still keeping
     * oid()/value()) for any OID this library doesn't model in full.
     */
    IExtensionPtr IExtension::create(const CString& oid, const COctet& value) {
        if (oid.compare(CBasicConstraintsExtension::OID) == 0) {
            return std::make_shared<CBasicConstraintsExtension>(value);
        }
        if (oid.compare(CKeyUsagesExtension::OID) == 0) {
            return std::make_shared<CKeyUsagesExtension>(value);
        }
        if (oid.compare(CEkuExtension::OID) == 0) {
            return std::make_shared<CEkuExtension>(value);
        }
        if (oid.compare(CSanExtension::OID) == 0) {
            return std::make_shared<CSanExtension>(value);
        }
        if (oid.compare(CSkiExtension::OID) == 0) {
            return std::make_shared<CSkiExtension>(value);
        }
        if (oid.compare(CAkiExtension::OID) == 0) {
            return std::make_shared<CAkiExtension>(value);
        }
        if (oid.compare(CCdpExtension::OID) == 0) {
            return std::make_shared<CCdpExtension>(value);
        }
        if (oid.compare(CAiaExtension::OID) == 0) {
            return std::make_shared<CAiaExtension>(value);
        }
        if (oid.compare(CPoliciesExtension::OID) == 0) {
            return std::make_shared<CPoliciesExtension>(value);
        }
        if (oid.compare(CNameConstraintsExtension::OID) == 0) {
            return std::make_shared<CNameConstraintsExtension>(value);
        }

        return std::make_shared<UnknownExtension>(oid, value);
    }
}
}
