#include <certpp/x509/chain.hpp>
#include <certpp/x509/chain/pem.hpp>
#include <certpp/x509/chain/pfx.hpp>
#include <certpp/x509/exts/aki.hpp>
#include <certpp/x509/exts/ski.hpp>
#include <certpp/crypto/asym.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>
#include <utility>

namespace certpp {
namespace x509 {

    namespace {

        /* Byte-wise equality for two COctets, and for a COctet against a span. An empty operand
         * never matches: every lookup that takes an identifier treats "absent" as "no match"
         * rather than as "matches the absent ones", which is the difference between finding the
         * certificate you asked for and finding every certificate that lacks the extension. */
        bool octetEquals(const COctet& a, const SReadOnlyByteSpan& b) {
            if (a.empty() || !b.data || b.size == 0) {
                return false;
            }
            if (a.size() != b.size) {
                return false;
            }

            return std::memcmp(a.toPtr(), b.data, b.size) == 0;
        }

        /* Reads a certificate's SubjectKeyIdentifier, or leaves out empty when the extension is
         * absent or does not parse. */
        void subjectKeyIdOf(const CCert& cert, COctet& out) {
            out = COctet();

            IExtensionPtr ext;
            if (cert.extensionOf(CSkiExtension::OID, ext) != ERET_OK || !ext) {
                return;
            }

            auto ski = std::dynamic_pointer_cast<CSkiExtension>(ext);
            if (ski) {
                out = ski->keyIdentifier();
            }
        }

        /* Reads a certificate's AuthorityKeyIdentifier keyIdentifier field, or leaves out empty.
         * Every field of AuthorityKeyIdentifier is optional, so an AKI that carries only an
         * issuer+serial yields nothing here -- which is why findIssuerOf() treats this as a
         * refinement of the name match rather than a replacement for it. */
        void authorityKeyIdOf(const CCert& cert, COctet& out) {
            out = COctet();

            IExtensionPtr ext;
            if (cert.extensionOf(CAkiExtension::OID, ext) != ERET_OK || !ext) {
                return;
            }

            auto aki = std::dynamic_pointer_cast<CAkiExtension>(ext);
            if (aki && aki->hasKeyIdentifier()) {
                out = aki->keyIdentifier();
            }
        }

    } // namespace

    /* Constructs an empty entry. */
    SCertEntry::SCertEntry() {
    }

    /* Constructs an empty collection. */
    CCertCollection::CCertCollection() {
    }

    /* Destroys the collection, clearing any private key material it holds. */
    CCertCollection::~CCertCollection() {
        clear();
    }

    /* Returns the number of entries. */
    size_t CCertCollection::count() const {
        return _entries.size();
    }

    /* Reports whether the collection holds nothing. */
    bool CCertCollection::empty() const {
        return _entries.empty();
    }

    /* Returns an entry by index. */
    ERetCode CCertCollection::at(size_t index, SCertEntry& out) const {
        if (index >= _entries.size()) {
            return ERET_BADREQ;
        }

        out = _entries[index];
        return ERET_OK;
    }

    /* Removes every entry, clearing any private key material first. */
    void CCertCollection::clear() {
        // --> The key objects are reference-counted and their own destructors scrub their
        // material, so dropping the references is what actually clears them. The localKeyId is
        // wiped here because it is the handle that pairs a certificate with a key inside a PFX,
        // and leaving it in freed memory is a small but free-to-avoid leak of structure.
        for (size_t i = 0; i < _entries.size(); ++i) {
            SCertEntry& entry = _entries[i];

            entry.privateKey.reset();

            if (!entry.localKeyId.empty()) {
                CSecure::zero(SByteSpan(
                    const_cast<uint8_t*>(entry.localKeyId.toPtr()), entry.localKeyId.size()));
            }
        }

        _entries.clear();
    }

    /* Adds a certificate with no private key. */
    ERetCode CCertCollection::add(const CCert& cert, size_t& outIndex) {
        return add(cert, crypto::IPrivateKeyPtr(), outIndex);
    }

    /* Adds a certificate together with its private key. */
    ERetCode CCertCollection::add(
        const CCert& cert, const crypto::IPrivateKeyPtr& privateKey, size_t& outIndex
    ) {
        SCertEntry entry;
        entry.cert = cert;
        entry.privateKey = privateKey;

        return add(entry, outIndex);
    }

    /* Adds a fully-specified entry. */
    ERetCode CCertCollection::add(const SCertEntry& entry, size_t& outIndex) {
        if (entry.cert.empty()) {
            return ERET_BADREQ;
        }

        _entries.push_back(entry);
        outIndex = _entries.size() - 1;

        return ERET_OK;
    }

    /* Removes one entry. */
    ERetCode CCertCollection::removeAt(size_t index) {
        if (index >= _entries.size()) {
            return ERET_BADREQ;
        }

        SCertEntry& entry = _entries[index];
        entry.privateKey.reset();

        if (!entry.localKeyId.empty()) {
            CSecure::zero(SByteSpan(
                const_cast<uint8_t*>(entry.localKeyId.toPtr()), entry.localKeyId.size()));
        }

        _entries.erase(_entries.begin() + index);
        return ERET_OK;
    }

    /* Attaches a private key to an entry. */
    ERetCode CCertCollection::attachPrivateKey(
        size_t index, const crypto::IPrivateKeyPtr& privateKey
    ) {
        if (index >= _entries.size() || !privateKey) {
            return ERET_BADREQ;
        }

        _entries[index].privateKey = privateKey;
        return ERET_OK;
    }

    /* Sets an entry's PKCS#9 friendlyName. */
    ERetCode CCertCollection::setFriendlyName(size_t index, const CString& name) {
        if (index >= _entries.size()) {
            return ERET_BADREQ;
        }

        _entries[index].friendlyName = name;
        return ERET_OK;
    }

    /* Sets an entry's PKCS#9 localKeyId. */
    ERetCode CCertCollection::setLocalKeyId(size_t index, const SReadOnlyByteSpan& id) {
        if (index >= _entries.size()) {
            return ERET_BADREQ;
        }

        if (!id.data || id.size == 0) {
            _entries[index].localKeyId = COctet();
            return ERET_OK;
        }

        _entries[index].localKeyId = COctet(id);
        return ERET_OK;
    }

    /* Finds the first entry whose subject matches. */
    size_t CCertCollection::findBySubject(const CDistinguishedName& subject) const {
        for (size_t i = 0; i < _entries.size(); ++i) {
            if (_entries[i].cert.subject() == subject) {
                return i;
            }
        }

        return NOT_FOUND;
    }

    /* Finds every entry whose subject matches. */
    size_t CCertCollection::findAllBySubject(
        const CDistinguishedName& subject, TArray<size_t>& out
    ) const {
        out.clear();

        for (size_t i = 0; i < _entries.size(); ++i) {
            if (_entries[i].cert.subject() == subject) {
                out.add(i);
            }
        }

        return out.size();
    }

    /* Finds the entry with a given issuer and serial number. */
    size_t CCertCollection::findByIssuerAndSerial(
        const CDistinguishedName& issuer, const SReadOnlyByteSpan& serial
    ) const {
        for (size_t i = 0; i < _entries.size(); ++i) {
            const CCert& cert = _entries[i].cert;

            if (cert.issuer() == issuer && octetEquals(cert.serialNumber(), serial)) {
                return i;
            }
        }

        return NOT_FOUND;
    }

    /* Finds the entry whose SubjectKeyIdentifier matches. */
    size_t CCertCollection::findBySubjectKeyId(const SReadOnlyByteSpan& keyId) const {
        for (size_t i = 0; i < _entries.size(); ++i) {
            COctet ski;
            subjectKeyIdOf(_entries[i].cert, ski);

            if (octetEquals(ski, keyId)) {
                return i;
            }
        }

        return NOT_FOUND;
    }

    /* Finds the entry with a given PKCS#9 friendlyName. */
    size_t CCertCollection::findByFriendlyName(const CString& name) const {
        if (name.size() == 0) {
            return NOT_FOUND;
        }

        for (size_t i = 0; i < _entries.size(); ++i) {
            if (_entries[i].friendlyName == name) {
                return i;
            }
        }

        return NOT_FOUND;
    }

    /* Finds the entry with a given PKCS#9 localKeyId. */
    size_t CCertCollection::findByLocalKeyId(const SReadOnlyByteSpan& id) const {
        for (size_t i = 0; i < _entries.size(); ++i) {
            if (octetEquals(_entries[i].localKeyId, id)) {
                return i;
            }
        }

        return NOT_FOUND;
    }

    /* Reports whether a certificate names itself as its own issuer. */
    bool CCertCollection::isSelfIssued(const CCert& cert) {
        if (cert.empty()) {
            return false;
        }

        return cert.subject() == cert.issuer();
    }

    /* Finds the entry that appears to have issued a certificate. */
    size_t CCertCollection::findIssuerOf(const CCert& cert) const {
        if (cert.empty() || isSelfIssued(cert)) {
            // --> A self-issued certificate is not its own issuer for this purpose. Reporting it
            // as one would turn every root into a one-element cycle, and buildChain() would have
            // to special-case what is simply the end of the chain.
            return NOT_FOUND;
        }

        const CDistinguishedName& wanted = cert.issuer();

        COctet aki;
        authorityKeyIdOf(cert, aki);

        size_t firstNameMatch = NOT_FOUND;

        for (size_t i = 0; i < _entries.size(); ++i) {
            if (!(_entries[i].cert.subject() == wanted)) {
                continue;
            }

            // --> The AuthorityKeyIdentifier decides between candidates that share a subject,
            // which is the case a CA that has re-keyed produces: two of its certificates, same
            // name, different keys. Matching on the name alone would pick whichever came first
            // in the collection, and the failure is not a clean one -- the chain assembles, and
            // verifyLinks() then fails on a signature that was never going to match, pointing
            // the blame at the signature rather than at this lookup.
            if (!aki.empty()) {
                COctet ski;
                subjectKeyIdOf(_entries[i].cert, ski);

                if (octetEquals(ski, SReadOnlyByteSpan(aki.toPtr(), aki.size()))) {
                    return i;
                }

                if (firstNameMatch == NOT_FOUND) {
                    firstNameMatch = i;
                }

                continue;
            }

            return i;
        }

        // Either there was no AKI to refine with, or no candidate's SKI matched it. Falling back
        // to the name match is deliberate: an AKI whose identifier names a certificate the
        // collection does not hold should not hide one that at least claims the right name, and
        // the signature check is what settles it either way.
        return firstNameMatch;
    }

    /* Collects every entry that is self-issued. */
    size_t CCertCollection::collectSelfIssued(TArray<size_t>& out) const {
        out.clear();

        for (size_t i = 0; i < _entries.size(); ++i) {
            if (isSelfIssued(_entries[i].cert)) {
                out.add(i);
            }
        }

        return out.size();
    }

    /* Orders the collection into a chain starting from one of its entries. */
    EChainResults CCertCollection::buildChain(size_t leafIndex, TArray<size_t>& out) const {
        out.clear();

        if (leafIndex >= _entries.size()) {
            return ECHAINRES_NOT_FOUND;
        }

        out.add(leafIndex);

        if (isSelfIssued(_entries[leafIndex].cert)) {
            return ECHAINRES_OK;
        }

        size_t current = leafIndex;

        for (size_t step = 0; step < MAX_DEPTH; ++step) {
            const size_t issuer = findIssuerOf(_entries[current].cert);
            if (issuer == NOT_FOUND) {
                return ECHAINRES_PARTIAL;
            }

            // --> Linear scan of what has been collected so far rather than a set: MAX_DEPTH is
            // 16, so this is at most 120 comparisons for the whole walk, and a set would cost an
            // allocation to save nothing measurable. It catches a cycle before the step counter
            // does, which matters because ECHAINRES_CYCLE tells the caller something true about
            // their data while ECHAINRES_TOO_DEEP only says the walk gave up.
            for (size_t i = 0; i < out.size(); ++i) {
                if (out[i] == issuer) {
                    return ECHAINRES_CYCLE;
                }
            }

            out.add(issuer);

            if (isSelfIssued(_entries[issuer].cert)) {
                return ECHAINRES_OK;
            }

            current = issuer;
        }

        return ECHAINRES_TOO_DEEP;
    }

    /* Orders the collection into a chain starting from a certificate not necessarily in it. */
    EChainResults CCertCollection::buildChainFor(const CCert& leaf, TArray<size_t>& out) const {
        out.clear();

        if (leaf.empty()) {
            return ECHAINRES_PARTIAL;
        }

        if (isSelfIssued(leaf)) {
            // The leaf is its own root, so there is nothing above it to collect. Reporting OK
            // with an empty chain is the honest answer: the walk succeeded and found no links.
            return ECHAINRES_OK;
        }

        const size_t first = findIssuerOf(leaf);
        if (first == NOT_FOUND) {
            return ECHAINRES_PARTIAL;
        }

        TArray<size_t> above;
        const EChainResults rc = buildChain(first, above);

        for (size_t i = 0; i < above.size(); ++i) {
            out.add(above[i]);
        }

        return rc;
    }

    /* Checks the signature on each link of an already-assembled chain. */
    ERetCode CCertCollection::verifyLinks(const TArray<size_t>& chain) const {
        if (chain.size() == 0) {
            return ERET_BADREQ;
        }

        for (size_t i = 0; i < chain.size(); ++i) {
            if (chain[i] >= _entries.size()) {
                return ERET_BADREQ;
            }
        }

        for (size_t i = 0; i + 1 < chain.size(); ++i) {
            const ERetCode rc =
                _entries[chain[i]].cert.verifyBy(_entries[chain[i + 1]].cert);

            if (rc != ERET_OK) {
                return rc;
            }
        }

        // --> The last certificate is checked against itself only when it is self-issued. A
        // chain that ended in ECHAINRES_PARTIAL has an ordinary intermediate at its top, whose
        // issuer is simply not present, and verifying that against itself would fail for a
        // reason that says nothing about the chain.
        const CCert& top = _entries[chain[chain.size() - 1]].cert;
        if (isSelfIssued(top)) {
            return top.verifyBy(top);
        }

        return ERET_OK;
    }

    /* Checks that an entry's private key really belongs to its certificate. */
    ERetCode CCertCollection::checkKeyPairing(size_t index) const {
        if (index >= _entries.size()) {
            return ERET_BADREQ;
        }

        const SCertEntry& entry = _entries[index];
        if (!entry.privateKey) {
            return ERET_KEY_EMPTY;
        }

        const crypto::IPublicKeyPtr publicKey = entry.cert.publicKey();
        if (!publicKey) {
            return ERET_NOTSUP; // the certificate's algorithm is one this library cannot resolve
        }

        crypto::IAsymmetricPtr algo = crypto::IAsymmetric::builtIn(publicKey->algorithm());
        if (!algo) {
            return ERET_NOTSUP;
        }

        crypto::IAsymmetricContextPtr ctx = algo->createContext();
        if (!ctx) {
            return ERET_NOTSUP;
        }

        ctx->keyPair(publicKey, entry.privateKey);

        // --> A fixed value rather than a random one. The point is to prove the two keys are a
        // pair, which does not need freshness, and a deterministic input makes a failure
        // reproducible. It is not a challenge-response against a remote party, where the
        // opposite would be true.
        uint8_t probe[32];
        std::memset(probe, 0x5A, sizeof(probe));

        const size_t capacity = ctx->sizeOfSign() ? ctx->sizeOfSign() : 512;

        TArray<uint8_t> buffer;
        if (!buffer.resize(capacity)) {
            return ERET_UNKNOWN;
        }

        SByteSpan signature(buffer.begin(), buffer.size());

        const ERetCode signRc =
            ctx->sign(SReadOnlyByteSpan(probe, sizeof(probe)), signature);

        if (signRc != ERET_OK) {
            // An algorithm that cannot sign at all (X25519, say) is unsupported here rather
            // than mismatched -- the caller asked a question this key type cannot answer.
            return (signRc == ERET_NOTSUP) ? ERET_NOTSUP : signRc;
        }

        const ERetCode verifyRc = ctx->verify(
            SReadOnlyByteSpan(probe, sizeof(probe)),
            SReadOnlyByteSpan(signature.data, signature.size));

        // --> A verification failure here means the key does not match the certificate, which is
        // a different thing from the verification machinery failing, and the caller acts on it
        // differently: a mismatch means the container pairs the wrong key with the wrong
        // certificate, and will fail on first use with a far more confusing symptom.
        return (verifyRc == ERET_OK) ? ERET_OK : ERET_KEY_ERROR;
    }

    /* Guesses a container's format from its first bytes. */
    EChainFormats IChainFormat::detect(const SReadOnlyByteSpan& data) {
        if (!data.data || data.size == 0) {
            return ECHAINFMT_UNKNOWN;
        }

        // --> PEM is text and RFC 7468 requires the encapsulation boundary to start a line, so
        // leading whitespace is skipped rather than treated as a mismatch: a file that begins
        // with a stray newline is still PEM, and a caller that trimmed it already would
        // otherwise get a different answer than one that did not.
        size_t at = 0;
        // Space, tab, CR and LF, written as values rather than escapes.
        while (at < data.size) {
            const uint8_t ch = data.data[at];
            if (ch != 0x20 && ch != 0x09 && ch != 0x0D && ch != 0x0A) {
                break;
            }
            ++at;
        }

        static const char PEM_OPEN[] = "-----BEGIN";
        const size_t openLen = sizeof(PEM_OPEN) - 1;

        if (data.size - at >= openLen &&
            std::memcmp(data.data + at, PEM_OPEN, openLen) == 0) {
            return ECHAINFMT_PEM;
        }

        // A PFX is DER, so it opens with a constructed SEQUENCE tag. This says nothing about
        // whether the DER inside is a PFX rather than some other structure -- load() decides
        // that. Guessing here is the point, and the doc comment says so.
        if (data.data[at] == 0x30) {
            return ECHAINFMT_PFX;
        }

        return ECHAINFMT_UNKNOWN;
    }

    /* Creates the built-in implementation of a format. */
    IChainFormatPtr IChainFormat::builtIn(EChainFormats which) {
        // --> The one place that has to know which concrete formats exist under x509/chain/,
        // which is why adding a format is a change here and nowhere else. A format with no
        // implementation yet reports "no implementation" rather than pretending.
        switch (which) {
            case ECHAINFMT_PEM:
                // --> Deliberately the certificates-only form: a caller who wants private keys
                // written out in the clear constructs CPemChainFormat(true) itself and can be
                // seen to have asked for it. See CPemChainFormat's own doc comment.
                return std::make_shared<CPemChainFormat>();

            case ECHAINFMT_PFX:
                return std::make_shared<CPfxFormat>();

            default:
                break;
        }

        return IChainFormatPtr();
    }

} // namespace x509
} // namespace certpp
