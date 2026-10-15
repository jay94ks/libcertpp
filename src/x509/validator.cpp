#include <certpp/x509/validator.hpp>
#include <certpp/x509/exts/aia.hpp>
#include <certpp/x509/exts/aki.hpp>
#include <certpp/x509/exts/bc.hpp>
#include <certpp/x509/exts/cdp.hpp>
#include <certpp/x509/exts/cp.hpp>
#include <certpp/x509/exts/eku.hpp>
#include <certpp/x509/exts/ku.hpp>
#include <certpp/x509/exts/nc.hpp>
#include <certpp/x509/exts/san.hpp>
#include <certpp/x509/exts/ski.hpp>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>

namespace certpp {
namespace x509 {

    namespace {
        bool sameBytes(const COctet& a, const COctet& b) {
            return a.size() == b.size()
                && (a.empty() || std::memcmp(a.toPtr(), b.toPtr(), a.size()) == 0);
        }

        bool sameCertificate(const CCert& a, const CCert& b) {
            return !a.empty() && !b.empty() && sameBytes(a.rawData(), b.rawData());
        }

        std::string lowerAscii(const CString& value) {
            if (value.empty()) {
                return std::string();
            }
            std::string out(value.toPtr(), value.size());
            std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
                return char(std::tolower(ch));
            });
            while (!out.empty() && out.back() == '.') {
                out.pop_back();
            }
            return out;
        }

        bool domainWithin(const std::string& name, const std::string& constraint) {
            if (name.empty() || constraint.empty()) {
                return false;
            }

            if (constraint[0] == '.') {
                return name.size() > constraint.size()
                    && name.compare(name.size() - constraint.size(), constraint.size(), constraint) == 0;
            }

            if (name == constraint) {
                return true;
            }

            return name.size() > constraint.size()
                && name[name.size() - constraint.size() - 1] == '.'
                && name.compare(name.size() - constraint.size(), constraint.size(), constraint) == 0;
        }

        bool dnsWithin(const CString& name, const CString& constraint) {
            return domainWithin(lowerAscii(name), lowerAscii(constraint));
        }

        bool emailWithin(const CString& nameValue, const CString& constraintValue) {
            const std::string name = lowerAscii(nameValue);
            const std::string constraint = lowerAscii(constraintValue);
            const size_t at = name.rfind('@');
            if (at == std::string::npos || at + 1 >= name.size() || constraint.empty()) {
                return false;
            }

            if (constraint.find('@') != std::string::npos) {
                return name == constraint;
            }

            return domainWithin(name.substr(at + 1), constraint);
        }

        bool uriWithin(const CString& value, const CString& constraintValue) {
            const std::string uri = lowerAscii(value);
            const std::string constraint = lowerAscii(constraintValue);
            const size_t scheme = uri.find("://");
            if (scheme == std::string::npos) {
                return false;
            }

            size_t first = scheme + 3;
            size_t last = uri.find_first_of("/?#", first);
            std::string authority = uri.substr(first, last == std::string::npos ? std::string::npos : last - first);
            const size_t user = authority.rfind('@');
            if (user != std::string::npos) {
                authority.erase(0, user + 1);
            }
            if (authority.empty() || authority[0] == '[') {
                return false;
            }
            const size_t port = authority.rfind(':');
            if (port != std::string::npos) {
                authority.erase(port);
            }
            return domainWithin(authority, constraint);
        }

        bool ipWithin(const COctet& address, const COctet& constraint) {
            const size_t addressSize = address.size();
            if ((addressSize != 4 && addressSize != 16) || constraint.size() != addressSize * 2) {
                return false;
            }

            const uint8_t* addressBytes = address.toPtr();
            const uint8_t* constraintBytes = constraint.toPtr();
            for (size_t i = 0; i < addressSize; ++i) {
                const uint8_t mask = constraintBytes[i + addressSize];
                if ((addressBytes[i] & mask) != (constraintBytes[i] & mask)) {
                    return false;
                }
            }
            return true;
        }

        bool supportedConstraintType(EGeneralNameType type) {
            return type == EGNAME_RFC822 || type == EGNAME_DNS || type == EGNAME_URI
                || type == EGNAME_IP_ADDRESS || type == EGNAME_REGISTERED_ID;
        }

        bool nameWithin(const CGeneralName& name, const CGeneralName& constraint) {
            if (name.type() != constraint.type()) {
                return false;
            }

            switch (name.type()) {
            case EGNAME_RFC822:
                return emailWithin(name.text(), constraint.text());
            case EGNAME_DNS:
                return dnsWithin(name.text(), constraint.text());
            case EGNAME_URI:
                return uriWithin(name.text(), constraint.text());
            case EGNAME_IP_ADDRESS:
                return ipWithin(name.raw(), constraint.raw());
            case EGNAME_REGISTERED_ID:
                return name.registeredId() == constraint.registeredId();
            default:
                return false;
            }
        }

        bool isKnownExtension(const COid& oid) {
            return oid == COid(CBasicConstraintsExtension::OID)
                || oid == COid(CKeyUsagesExtension::OID)
                || oid == COid(CEkuExtension::OID)
                || oid == COid(CSanExtension::OID)
                || oid == COid(CSkiExtension::OID)
                || oid == COid(CAkiExtension::OID)
                || oid == COid(CCdpExtension::OID)
                || oid == COid(CAiaExtension::OID)
                || oid == COid(CPoliciesExtension::OID)
                || oid == COid(CNameConstraintsExtension::OID);
        }

        bool hasEku(const CCert& cert, const COid& required) {
            auto eku = cert.extension<CEkuExtension>();
            if (!eku) {
                return true;
            }

            const COid any(CEkuExtension::OID_ANY_EXTENDED_KEY_USAGE);
            for (const COid& purpose : eku->purposes()) {
                if (purpose == required || purpose == any) {
                    return true;
                }
            }
            return false;
        }

        SPathValidationResult fail(
            const TArray<CCert>& path,
            EPathValidationStatus status,
            size_t index,
            ERetCode detail = ERET_OK
        ) {
            SPathValidationResult result;
            result.status = status;
            result.certificateIndex = index;
            result.detail = detail;
            result.path = path;
            return result;
        }

        SPathValidationResult checkCriticalExtensions(
            const TArray<CCert>& path,
            const SPathValidationPolicy& policy
        ) {
            if (!policy.rejectUnknownCriticalExtensions) {
                SPathValidationResult ok;
                ok.status = EPATH_OK;
                return ok;
            }

            for (size_t i = 0; i + 1 < path.size(); ++i) {
                for (const IExtensionPtr& ext : path[i].extensions()) {
                    if (!ext || !ext->critical()) {
                        continue;
                    }
                    if (!isKnownExtension(ext->oid())) {
                        return fail(path, EPATH_UNKNOWN_CRITICAL_EXTENSION, i);
                    }
                    if (ext->oid() == COid(CPoliciesExtension::OID)) {
                        return fail(path, EPATH_UNSUPPORTED_CRITICAL_EXTENSION, i);
                    }
                    if (ext->oid() == COid(CNameConstraintsExtension::OID)
                        && !policy.checkNameConstraints)
                    {
                        return fail(path, EPATH_UNSUPPORTED_CRITICAL_EXTENSION, i);
                    }
                }
            }

            SPathValidationResult ok;
            ok.status = EPATH_OK;
            return ok;
        }

        SPathValidationResult checkNameConstraints(
            const TArray<CCert>& path,
            const SPathValidationPolicy& policy
        ) {
            if (!policy.checkNameConstraints) {
                SPathValidationResult ok;
                ok.status = EPATH_OK;
                return ok;
            }

            for (size_t issuerIndex = 1; issuerIndex < path.size(); ++issuerIndex) {
                auto constraints = path[issuerIndex].extension<CNameConstraintsExtension>();
                if (!constraints) {
                    continue;
                }

                for (const CGeneralSubtree& subtree : constraints->permittedSubtrees()) {
                    if (subtree.minimum() != 0 || subtree.hasMaximum()
                        || !supportedConstraintType(subtree.base().type()))
                    {
                        return fail(path, EPATH_UNSUPPORTED_NAME_CONSTRAINT, issuerIndex);
                    }
                }
                for (const CGeneralSubtree& subtree : constraints->excludedSubtrees()) {
                    if (subtree.minimum() != 0 || subtree.hasMaximum()
                        || !supportedConstraintType(subtree.base().type()))
                    {
                        return fail(path, EPATH_UNSUPPORTED_NAME_CONSTRAINT, issuerIndex);
                    }
                }

                for (size_t subjectIndex = 0; subjectIndex < issuerIndex; ++subjectIndex) {
                    if (subjectIndex != 0 && CCertCollection::isSelfIssued(path[subjectIndex])) {
                        continue;
                    }

                    auto san = path[subjectIndex].extension<CSanExtension>();
                    if (!san) {
                        continue;
                    }

                    for (const CGeneralName& name : san->names()) {
                        if (!supportedConstraintType(name.type())) {
                            continue;
                        }

                        bool hasPermittedType = false;
                        bool permitted = false;
                        for (const CGeneralSubtree& subtree : constraints->permittedSubtrees()) {
                            if (subtree.base().type() == name.type()) {
                                hasPermittedType = true;
                                permitted = permitted || nameWithin(name, subtree.base());
                            }
                        }
                        if (hasPermittedType && !permitted) {
                            return fail(path, EPATH_NAME_CONSTRAINT, subjectIndex);
                        }

                        for (const CGeneralSubtree& subtree : constraints->excludedSubtrees()) {
                            if (nameWithin(name, subtree.base())) {
                                return fail(path, EPATH_NAME_CONSTRAINT, subjectIndex);
                            }
                        }
                    }
                }
            }

            SPathValidationResult ok;
            ok.status = EPATH_OK;
            return ok;
        }
    }

    ERetCode CTrustStore::add(const CCert& anchor) {
        if (anchor.empty()) {
            return ERET_BADREQ;
        }
        if (!contains(anchor)) {
            _anchors.push_back(anchor);
        }
        return ERET_OK;
    }

    void CTrustStore::clear() {
        _anchors.clear();
    }

    size_t CTrustStore::count() const {
        return _anchors.size();
    }

    bool CTrustStore::at(size_t index, CCert& out) const {
        if (index >= _anchors.size()) {
            return false;
        }
        out = _anchors[index];
        return true;
    }

    bool CTrustStore::contains(const CCert& cert) const {
        for (const CCert& anchor : _anchors) {
            if (sameCertificate(anchor, cert)) {
                return true;
            }
        }
        return false;
    }

    SPathValidationResult CPathValidator::validate(
        const CCert& leaf,
        const CCertCollection& intermediates,
        const CTrustStore& trustStore,
        const SPathValidationPolicy& policy
    ) {
        TArray<CCert> path;
        if (leaf.empty()) {
            return fail(path, EPATH_EMPTY, 0);
        }
        path.add(leaf);

        while (!trustStore.contains(path[path.size() - 1])) {
            if (path.size() >= policy.maxDepth) {
                return fail(path, EPATH_TOO_DEEP, path.size() - 1);
            }

            const CCert& current = path[path.size() - 1];
            CCert selected;
            bool found = false;

            COctet authorityKeyId;
            const bool hasAuthorityKeyId = current.authorityKeyIdentifier(authorityKeyId) == ERET_OK;

            for (int preferKeyId = hasAuthorityKeyId ? 1 : 0; preferKeyId >= 0 && !found; --preferKeyId) {
                const size_t candidateCount = intermediates.count() + trustStore.count();
                for (size_t i = 0; i < candidateCount; ++i) {
                    CCert candidate;
                    if (i < intermediates.count()) {
                        SCertEntry entry;
                        if (intermediates.at(i, entry) != ERET_OK) {
                            continue;
                        }
                        candidate = entry.cert;
                    } else if (!trustStore.at(i - intermediates.count(), candidate)) {
                        continue;
                    }

                    if (candidate.empty() || current.issuer() != candidate.subject()) {
                        continue;
                    }
                    bool seen = false;
                    for (const CCert& existing : path) {
                        seen = seen || sameCertificate(existing, candidate);
                    }
                    if (seen) {
                        continue;
                    }

                    if (preferKeyId) {
                        COctet subjectKeyId;
                        if (candidate.subjectKeyIdentifier(subjectKeyId) != ERET_OK
                            || !sameBytes(authorityKeyId, subjectKeyId))
                        {
                            continue;
                        }
                    }

                    if (current.verifyBy(candidate) == ERET_OK) {
                        selected = candidate;
                        found = true;
                        break;
                    }
                }
            }

            if (!found) {
                return fail(path, EPATH_INCOMPLETE, path.size() - 1);
            }
            path.add(selected);
        }

        return validateOrdered(path, trustStore, policy);
    }

    SPathValidationResult CPathValidator::validateOrdered(
        const TArray<CCert>& path,
        const CTrustStore& trustStore,
        const SPathValidationPolicy& policy
    ) {
        if (path.empty()) {
            return fail(path, EPATH_EMPTY, 0);
        }
        if (path.size() > policy.maxDepth) {
            return fail(path, EPATH_TOO_DEEP, policy.maxDepth);
        }
        if (!trustStore.contains(path[path.size() - 1])) {
            return fail(path, EPATH_UNTRUSTED_ROOT, path.size() - 1);
        }
        if (policy.requireRevocation) {
            return fail(path, EPATH_REVOCATION_UNAVAILABLE, 0);
        }
        if (policy.requirePolicyProcessing) {
            return fail(path, EPATH_POLICY_PROCESSING_UNAVAILABLE, 0);
        }

        const uint64_t now = (policy.validationTime.isZero()
            ? SDateTime::now(true)
            : policy.validationTime.toUtc()).toMilliseconds();

        for (size_t i = 0; i < path.size(); ++i) {
            const CCert& cert = path[i];
            if (cert.empty()) {
                return fail(path, EPATH_EMPTY, i);
            }

            if (policy.checkTime) {
                if (now < cert.notBefore().toUtc().toMilliseconds()) {
                    return fail(path, EPATH_NOT_YET_VALID, i);
                }
                if (now > cert.notAfter().toUtc().toMilliseconds()) {
                    return fail(path, EPATH_EXPIRED, i);
                }
            }

            if (i + 1 < path.size()) {
                if (cert.issuer() != path[i + 1].subject()) {
                    return fail(path, EPATH_ISSUER_NAME_MISMATCH, i);
                }
                ERetCode verified = cert.verifyBy(path[i + 1]);
                if (verified != ERET_OK) {
                    return fail(path, EPATH_SIGNATURE_INVALID, i, verified);
                }
            }
        }

        for (size_t i = 1; i + 1 < path.size(); ++i) {
            auto basic = path[i].extension<CBasicConstraintsExtension>();
            if (!basic || !basic->isCa()) {
                return fail(path, EPATH_CA_REQUIRED, i);
            }

            auto keyUsage = path[i].extension<CKeyUsagesExtension>();
            if (keyUsage && !(keyUsage->bits() & EKUSE_KEY_CERT_SIGN)) {
                return fail(path, EPATH_KEY_USAGE, i);
            }

            if (basic->hasPathLenConstraint()) {
                size_t caBelow = 0;
                for (size_t j = 1; j < i; ++j) {
                    if (!CCertCollection::isSelfIssued(path[j])) {
                        ++caBelow;
                    }
                }
                if (caBelow > size_t(basic->pathLenConstraint())) {
                    return fail(path, EPATH_PATH_LENGTH, i);
                }
            }
        }

        if (policy.requiredLeafKeyUsages) {
            auto usage = path[0].extension<CKeyUsagesExtension>();
            if (usage && (usage->bits() & policy.requiredLeafKeyUsages) != policy.requiredLeafKeyUsages) {
                return fail(path, EPATH_KEY_USAGE, 0);
            }
        }

        if (policy.requiredExtendedKeyPurpose) {
            for (size_t i = 0; i + 1 < path.size(); ++i) {
                if (!hasEku(path[i], policy.requiredExtendedKeyPurpose)) {
                    return fail(path, EPATH_EXTENDED_KEY_USAGE, i);
                }
            }
        }

        SPathValidationResult critical = checkCriticalExtensions(path, policy);
        if (!critical.ok()) {
            return critical;
        }
        SPathValidationResult names = checkNameConstraints(path, policy);
        if (!names.ok()) {
            return names;
        }

        SPathValidationResult result;
        result.status = EPATH_OK;
        result.certificateIndex = 0;
        result.path = path;
        return result;
    }

} // namespace x509
} // namespace certpp
