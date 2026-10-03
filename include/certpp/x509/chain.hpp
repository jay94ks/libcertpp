#ifndef __INCLUDE_CERTPP_X509_CHAIN_HPP__
#define __INCLUDE_CERTPP_X509_CHAIN_HPP__

#include <certpp/common.hpp>
#include <certpp/crypto/keys.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/span.hpp>
#include <certpp/name.hpp>
#include <certpp/string.hpp>
#include <certpp/x509/cert.hpp>
#include <certpp/io/buffer.hpp>
#include <memory>
#include <vector>

namespace certpp {
namespace x509 {

    /**
     * How an attempt to order a collection into a chain ended.
     *
     * These describe the *shape* of the linkage found, not whether the chain is trustworthy --
     * see `CCertCollection`'s own doc comment for why that distinction is the whole point of
     * this type.
     */
    enum EChainResults {
        ECHAINRES_OK = 0,        /**< Reached a self-issued certificate held in the collection. */
        ECHAINRES_PARTIAL,       /**< Ran out of issuers before reaching a self-issued one. */
        ECHAINRES_CYCLE,         /**< The issuer links lead back to a certificate already seen. */
        ECHAINRES_TOO_DEEP,      /**< More links than `CCertCollection::MAX_DEPTH` allows. */
        ECHAINRES_NOT_FOUND,     /**< The certificate to start from is not in the collection. */
    };

    /**
     * The container formats a `CCertCollection` can be read from and written to.
     *
     * Both carry certificates; only one carries private keys safely. See `IChainFormat`.
     */
    enum EChainFormats {
        ECHAINFMT_UNKNOWN = 0,  /**< Not a recognised container format. */
        ECHAINFMT_PEM,          /**< Concatenated RFC 7468 PEM blocks. No password, no secrecy. */
        ECHAINFMT_PFX,          /**< PKCS#12/PFX (RFC 7292). Password-based encryption and integrity. */
    };

    /**
     * One certificate in a `CCertCollection`, with the things a PKCS#12 container stores
     * alongside it.
     *
     * The private key is optional because a collection usually holds a mixture: one end-entity
     * certificate whose key the holder has, and the CA certificates above it, whose keys the
     * holder emphatically does not. `friendlyName` and `localKeyId` are PKCS#9 attributes
     * (1.2.840.113549.1.9.20 and .21) that PKCS#12 carries on its bags; `localKeyId` is how a
     * PFX pairs a certificate bag with its key bag, so a collection that is going to become a
     * PFX needs somewhere to keep it even before the container itself exists.
     */
    struct CERTPP_API SCertEntry {
        /** The certificate. */
        CCert cert;

        /** The matching private key, or null when the collection holds only the certificate. */
        crypto::IPrivateKeyPtr privateKey;

        /** The PKCS#9 `friendlyName` attribute, or empty if there is none. */
        CString friendlyName;

        /** The PKCS#9 `localKeyId` attribute, or empty if there is none. */
        COctet localKeyId;

        /**
         * Constructs an empty entry.
         */
        SCertEntry();

        /**
         * Reports whether this entry carries a private key.
         * @return True if a private key is present.
         */
        inline bool hasPrivateKey() const {
            return privateKey != nullptr;
        }
    };

    /**
     * A set of certificates, optionally with their private keys, plus the lookups needed to
     * order them into a chain.
     *
     * This is the layer a PKCS#12/PFX container sits on. A PFX is, in substance, exactly this:
     * a bag of certificates, zero or more private keys, the PKCS#9 attributes that pair them,
     * and an ordering. Building that container needs all of this and no more, so it lives here
     * rather than inside the container format, where it would be stuck behind
     * password-based encryption and unavailable to anything else.
     *
     * **This does not validate a certification path, and the distinction is not a quibble.**
     * `buildChain()` orders certificates by who issued whom. A path validator additionally
     * checks signatures, validity periods, `basicConstraints` (`cA` and `pathLenConstraint`),
     * `keyUsage`, `extendedKeyUsage`, name constraints, policy constraints and revocation, and
     * decides whether the root is one the caller trusts. None of that happens here. An ordered
     * chain out of this class says "these certificates claim to form a chain", which is what a
     * container format needs to store and what a validator needs as *input* -- it is not a
     * statement that the chain is good. `verifyLinks()` goes one step further and checks the
     * signatures, and is still not path validation; its own doc comment lists what it leaves
     * out.
     *
     * Lookups return an index into the collection, with `NOT_FOUND` for a miss, rather than a
     * pointer or an iterator. An index stays meaningful across a copy of the collection and is
     * what `buildChain()` reports a chain as, so the two compose; it is invalidated by
     * `removeAt()` and `clear()`, like any index into a sequence.
     */
    class CERTPP_API CCertCollection {
    private:
        std::vector<SCertEntry> _entries;

    public:
        /** Returned by every lookup that finds nothing. */
        static constexpr size_t NOT_FOUND = size_t(-1);

        /**
         * The longest chain `buildChain()` will assemble before giving up with
         * `ECHAINRES_TOO_DEEP`.
         *
         * A bound is needed because a collection is caller-supplied data: without one, a
         * sufficiently long chain -- or a cycle that the already-seen check somehow missed --
         * turns a lookup into an unbounded loop. Real hierarchies are a handful of links deep.
         */
        static constexpr size_t MAX_DEPTH = 16;

    public:
        /**
         * Constructs an empty collection.
         */
        CCertCollection();

        /**
         * Destroys the collection, clearing any private key material it holds.
         */
        ~CCertCollection();

    public:
        /**
         * Returns the number of entries.
         * @return The entry count.
         */
        size_t count() const;

        /**
         * Reports whether the collection holds nothing.
         * @return True if there are no entries.
         */
        bool empty() const;

        /**
         * Returns an entry by index.
         * @param index The entry index, below count().
         * @param out Receives the entry.
         * @return ERET_OK, or ERET_BADREQ if index is out of range.
         */
        ERetCode at(size_t index, SCertEntry& out) const;

        /**
         * Removes every entry, clearing any private key material first.
         */
        void clear();

    public:
        /**
         * Adds a certificate with no private key.
         * @param cert The certificate; must not be empty.
         * @param outIndex Receives the index of the new entry.
         * @return ERET_OK, or ERET_BADREQ if cert is empty.
         */
        ERetCode add(const CCert& cert, size_t& outIndex);

        /**
         * Adds a certificate together with its private key.
         *
         * The two are **not** checked against each other here -- see `checkKeyPairing()`, which
         * is separate because the check costs a signature operation and a caller importing a
         * container of many entries may not want to pay it for every one.
         * @param cert The certificate; must not be empty.
         * @param privateKey The matching private key; may be null, which is the same as add().
         * @param outIndex Receives the index of the new entry.
         * @return ERET_OK, or ERET_BADREQ if cert is empty.
         */
        ERetCode add(
            const CCert& cert, const crypto::IPrivateKeyPtr& privateKey, size_t& outIndex
        );

        /**
         * Adds a fully-specified entry, PKCS#9 attributes included.
         * @param entry The entry to add; its cert must not be empty.
         * @param outIndex Receives the index of the new entry.
         * @return ERET_OK, or ERET_BADREQ if the entry's certificate is empty.
         */
        ERetCode add(const SCertEntry& entry, size_t& outIndex);

        /**
         * Removes one entry, clearing its private key material first.
         *
         * Every index at or above `index` shifts down by one, as with any sequence.
         * @param index The entry to remove.
         * @return ERET_OK, or ERET_BADREQ if index is out of range.
         */
        ERetCode removeAt(size_t index);

        /**
         * Attaches a private key to an entry that does not have one.
         * @param index The entry.
         * @param privateKey The key to attach; must not be null.
         * @return ERET_OK, ERET_BADREQ if index is out of range or privateKey is null.
         */
        ERetCode attachPrivateKey(size_t index, const crypto::IPrivateKeyPtr& privateKey);

        /**
         * Sets an entry's PKCS#9 `friendlyName`.
         * @param index The entry.
         * @param name The name; may be empty, which removes it.
         * @return ERET_OK, or ERET_BADREQ if index is out of range.
         */
        ERetCode setFriendlyName(size_t index, const CString& name);

        /**
         * Sets an entry's PKCS#9 `localKeyId`.
         * @param index The entry.
         * @param id The identifier; may be empty, which removes it.
         * @return ERET_OK, or ERET_BADREQ if index is out of range.
         */
        ERetCode setLocalKeyId(size_t index, const SReadOnlyByteSpan& id);

    public:
        /**
         * Finds the first entry whose subject matches.
         *
         * More than one certificate can share a subject -- a CA re-keying itself issues a new
         * certificate with the same subject and a different key -- so this returns the first
         * match and `findAllBySubject()` returns every one. Prefer
         * `findBySubjectKeyId()` where the key identifier is known, since it distinguishes
         * exactly the case this cannot.
         * @param subject The subject to match.
         * @return The entry index, or NOT_FOUND.
         */
        size_t findBySubject(const CDistinguishedName& subject) const;

        /**
         * Finds every entry whose subject matches.
         * @param subject The subject to match.
         * @param out Receives the matching indices; cleared first.
         * @return The number of matches.
         */
        size_t findAllBySubject(const CDistinguishedName& subject, TArray<size_t>& out) const;

        /**
         * Finds the entry with a given issuer and serial number, which is the identifier X.509
         * itself treats as unique: a CA must not reuse a serial.
         * @param issuer The issuing CA's subject name, as it appears in the certificate's
         *        issuer field.
         * @param serial The serial number, as the bytes `CCert::serialNumber()` reports.
         * @return The entry index, or NOT_FOUND.
         */
        size_t findByIssuerAndSerial(
            const CDistinguishedName& issuer, const SReadOnlyByteSpan& serial
        ) const;

        /**
         * Finds the entry whose SubjectKeyIdentifier extension matches.
         *
         * Entries with no such extension never match, rather than matching an empty identifier.
         * @param keyId The key identifier.
         * @return The entry index, or NOT_FOUND.
         */
        size_t findBySubjectKeyId(const SReadOnlyByteSpan& keyId) const;

        /**
         * Finds the entry with a given PKCS#9 `friendlyName`.
         * @param name The name to match; an empty name never matches.
         * @return The entry index, or NOT_FOUND.
         */
        size_t findByFriendlyName(const CString& name) const;

        /**
         * Finds the entry with a given PKCS#9 `localKeyId`, which is how a PFX pairs a
         * certificate with a key.
         * @param id The identifier to match; an empty identifier never matches.
         * @return The entry index, or NOT_FOUND.
         */
        size_t findByLocalKeyId(const SReadOnlyByteSpan& id) const;

    public:
        /**
         * Reports whether a certificate names itself as its own issuer.
         *
         * This is a check on the *names* only -- it does not verify that the certificate's
         * signature was made by its own key, which is what would make it genuinely self-signed.
         * A certificate can be self-issued without being self-signed. `buildChain()` stops at a
         * self-issued certificate because that is where the naming links run out; whether it is
         * really self-signed is for `verifyLinks()` or a validator to establish.
         * @param cert The certificate.
         * @return True if the subject and issuer names are equal.
         */
        static bool isSelfIssued(const CCert& cert);

        /**
         * Finds the entry that appears to have issued a certificate.
         *
         * Matches the certificate's issuer name against candidate subjects, and where the
         * certificate carries an AuthorityKeyIdentifier with a key identifier, prefers the
         * candidate whose SubjectKeyIdentifier matches it. That preference is what makes the
         * result well-defined when a CA has re-keyed and two of its certificates share a
         * subject.
         *
         * A self-issued certificate is not reported as its own issuer, so this returning
         * NOT_FOUND for one is the normal end of a chain rather than a failure.
         * @param cert The certificate whose issuer to find.
         * @return The entry index, or NOT_FOUND.
         */
        size_t findIssuerOf(const CCert& cert) const;

        /**
         * Collects every entry that is self-issued, i.e. every candidate root.
         * @param out Receives the indices; cleared first.
         * @return The number found.
         */
        size_t collectSelfIssued(TArray<size_t>& out) const;

    public:
        /**
         * Orders the collection into a chain starting from one of its entries.
         *
         * Walks `findIssuerOf()` from the given entry upwards. `out` receives the indices in
         * order, leaf first, including the starting entry; on anything other than `ECHAINRES_OK`
         * it holds the partial chain assembled before the problem, which is more useful to a
         * caller than an empty array.
         *
         * This performs no verification whatsoever -- see this class's own doc comment.
         * @param leafIndex The entry to start from.
         * @param out Receives the chain as indices, leaf first; cleared first.
         * @return How the walk ended.
         */
        EChainResults buildChain(size_t leafIndex, TArray<size_t>& out) const;

        /**
         * Orders the collection into a chain starting from a certificate that need not be in it.
         *
         * Useful for the common case where the leaf arrived separately from the CA certificates
         * that support it. The leaf itself is not included in `out`, since it has no index in
         * this collection.
         * @param leaf The certificate to start from.
         * @param out Receives the chain above the leaf as indices, nearest issuer first;
         *        cleared first.
         * @return How the walk ended; never ECHAINRES_NOT_FOUND, since the leaf is supplied
         *         directly.
         */
        EChainResults buildChainFor(const CCert& leaf, TArray<size_t>& out) const;

        /**
         * Checks the signature on each link of an already-assembled chain.
         *
         * Calls `CCert::verifyBy()` for every adjacent pair, and for a chain ending in a
         * self-issued certificate also checks that one against itself.
         *
         * **This is still not path validation.** It establishes only that each certificate was
         * signed by the key in the one above it. It does not check validity periods,
         * `basicConstraints`, `keyUsage`, `extendedKeyUsage`, name or policy constraints, or
         * revocation, and it has no notion of which roots the caller trusts -- a chain of
         * perfectly-signed certificates rooted in an attacker's own CA passes this.
         * @param chain The chain as indices, leaf first, as `buildChain()` produces.
         * @return ERET_OK if every link verifies; otherwise the first failure's code, or
         *         ERET_BADREQ if an index is out of range.
         */
        ERetCode verifyLinks(const TArray<size_t>& chain) const;

        /**
         * Checks that an entry's private key really belongs to its certificate.
         *
         * Signs a fixed value with the private key and verifies it against the certificate's
         * public key, which is the only way to establish the pairing for a signature algorithm
         * -- comparing serialized keys works for some algorithms and not others, and comparing
         * nothing at all is how a container ends up holding a key that silently fails on first
         * use. Separate from `add()` because it costs a signature operation.
         * @param index The entry; must hold a private key.
         * @return ERET_OK if the key matches, ERET_KEY_ERROR if it does not, ERET_KEY_EMPTY if
         *         the entry holds no private key, ERET_BADREQ if index is out of range, or
         *         ERET_NOTSUP if the key's algorithm cannot sign.
         */
        ERetCode checkKeyPairing(size_t index) const;
    };

    /**
     * Forward declaration of the container-format interface.
     */
    class IChainFormat;

    /**
     * Shared pointer type for the container-format interface.
     */
    using IChainFormatPtr = std::shared_ptr<IChainFormat>;

    /**
     * Reads and writes a `CCertCollection` as a container file.
     *
     * One implementation per format under `x509/chain/`, the same arrangement `x509/exts/` has
     * for extension types: the interface is here, the concrete formats are there, and
     * `builtIn()` is the only thing that needs to know which exist.
     *
     * The two formats are not interchangeable, and the difference is not cosmetic:
     *
     * - **PEM** is concatenated base64 blocks with no password and no encryption. A private key
     *   written to PEM by this interface is written **in the clear**. That is what PEM is, and
     *   it is occasionally what a caller wants (a key they are about to hand to a tool that
     *   expects it), but `needsPassword()` returning false is not a convenience -- it is a
     *   warning.
     * - **PFX** (PKCS#12, RFC 7292) encrypts its key bags and MACs the whole container under a
     *   password. It is the format to use when a private key is going to rest on disk or cross
     *   a network.
     *
     * Both round-trip the certificates and the PKCS#9 attributes. Only PFX round-trips a
     * private key without exposing it.
     */
    class CERTPP_API IChainFormat {
    public:
        /**
         * Destructor for the container-format interface.
         */
        virtual ~IChainFormat() = default;

        /**
         * Creates the built-in implementation of a format.
         * @param which The format.
         * @return The implementation, or null for `ECHAINFMT_UNKNOWN` or an unimplemented one.
         */
        static IChainFormatPtr builtIn(EChainFormats which);

        /**
         * Guesses a container's format from its first bytes.
         *
         * PEM begins with the ASCII `-----BEGIN`; a PFX is DER and so begins with a SEQUENCE
         * tag. That is enough to tell them apart and is **not** a validity check -- a buffer
         * that merely starts like one is reported as that one, and the subsequent `load()` is
         * what decides whether it really is.
         * @param data The start of the container; a few bytes are enough.
         * @return The guessed format, or `ECHAINFMT_UNKNOWN`.
         */
        static EChainFormats detect(const SReadOnlyByteSpan& data);

    public:
        /**
         * Returns which format this implementation handles.
         * @return The format.
         */
        virtual EChainFormats format() const = 0;

        /**
         * Reports whether this format requires a password.
         *
         * False means the format has no confidentiality at all, not that a password is
         * optional -- see this interface's own doc comment.
         * @return True if `load()`/`save()` need a non-empty password.
         */
        virtual bool needsPassword() const = 0;

        /**
         * Reads a container into a collection.
         *
         * Entries are appended, so loading two containers into one collection merges them.
         * On failure the collection is left as it was rather than half-populated.
         * @param data The container's bytes.
         * @param password The password; ignored by a format where `needsPassword()` is false.
         * @param out Receives the entries, appended.
         * @return ERET_OK, ERET_BADREQ for a malformed container, ERET_KEY_ERROR for a wrong
         *         password or a failed integrity check, or ERET_NOTSUP for a container using an
         *         algorithm this library does not implement.
         */
        virtual ERetCode load(
            const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& password,
            CCertCollection& out
        ) const = 0;

        /**
         * Writes a collection out as a container.
         * @param in The collection; must not be empty.
         * @param password The password; ignored by a format where `needsPassword()` is false.
         * @param out Receives the container's bytes, replacing any content it held.
         * @return ERET_OK, ERET_BADREQ if the collection is empty or the password is required
         *         and empty, or ERET_NOTSUP if an entry holds a key this format cannot carry.
         */
        virtual ERetCode save(
            const CCertCollection& in, const SReadOnlyByteSpan& password, CBuffer& out
        ) const = 0;
    };

} // namespace x509
} // namespace certpp

#endif
