#ifndef __INCLUDE_CERTPP_X509_OCSP_HPP__
#define __INCLUDE_CERTPP_X509_OCSP_HPP__

#include <certpp/common.hpp>
#include <certpp/x509/cert.hpp>
#include <certpp/x509/crl.hpp>

namespace certpp {
namespace x509 {

    /**
     * Enumeration representing OCSP status.
     */
    enum EOcspStatus {
        EOCSP_OK = 0,
        EOCSP_MALFORMED = 1,
        EOCSP_INTERNAL = 2,
        EOCSP_TRY_LATER = 3,
        EOCSP_SIG_REQUIRED = 5,
        EOCSP_UNAUTHORIZED = 6,
    };

    /**
     * A class representing an OCSP certificate identifier.
     */
    class CERTPP_API COcspCertId {
    private:
        COctet _serialNumber;
        COctet _issuerKeyHash;
        COctet _issuerNameHash;

        crypto::EHashers _hashAlgo;

        /* CertID.hashAlgorithm's OID <-> EHashers, and whether that OID's AlgorithmIdentifier
         * conventionally carries an explicit NULL parameter -- SHA-1 (the historical, still most
         * interoperable OCSP default) always does in deployed practice; the SHA-2 family follows
         * RFC 5754's SHOULD-be-absent guidance, matching this library's own RSASSA-PSS
         * hashAlgorithm encoding (CCert::buildRsaPssParams()). Only these five hashers (not MD5
         * or the variable-length SHAKE256) are usable for OCSP hashing. Used by encode()/decode(). */
        static bool hashAlgoToOid(crypto::EHashers hash, CString& outOid, bool& outNeedsNull);
        static bool oidToHashAlgo(const CString& oid, crypto::EHashers& outHash);

    public:
        /**
         * Default constructor.
         */
        COcspCertId() {
            _hashAlgo = crypto::EHASH_UNKNOWN;
        }

        /**
         * Parameterized constructor.
         *
         * @param serialNumber The serial number of the certificate.
         * @param issuerKeyHash The issuer key hash of the certificate.
         * @param issuerNameHash The issuer name hash of the certificate.
         * @param hashAlgo The hash algorithm used for the issuer key and name hashes.
         */
        COcspCertId(
            const COctet& serialNumber, 
            const COctet& issuerKeyHash, 
            const COctet& issuerNameHash, 
            crypto::EHashers hashAlgo) 
        {
            _serialNumber = serialNumber;
            _issuerKeyHash = issuerKeyHash;
            _issuerNameHash = issuerNameHash;
            _hashAlgo = hashAlgo;
        }

        /**
         * Copy constructor.
         *
         * @param other The COcspCertId object to copy from.
         */
        COcspCertId(const COcspCertId& other) {
            _serialNumber = other._serialNumber;
            _issuerKeyHash = other._issuerKeyHash;
            _issuerNameHash = other._issuerNameHash;
            _hashAlgo = other._hashAlgo;
        }

        /**
         * Move constructor.
         *
         * @param other The COcspCertId object to move from.
         */
        COcspCertId(COcspCertId&& other) {
            _serialNumber = move(other._serialNumber);
            _issuerKeyHash = move(other._issuerKeyHash);
            _issuerNameHash = move(other._issuerNameHash);
            _hashAlgo = other._hashAlgo;
        }

        /**
         * Copy assignment operator.
         *
         * @param other The COcspCertId object to copy from.
         * @return Reference to this object.
         */
        inline COcspCertId& operator=(const COcspCertId& other) {
            if (this != &other) {
                _serialNumber = other._serialNumber;
                _issuerKeyHash = other._issuerKeyHash;
                _issuerNameHash = other._issuerNameHash;
                _hashAlgo = other._hashAlgo;
            }

            return *this;
        }

        /**
         * Move assignment operator.
         *
         * @param other The COcspCertId object to move from.
         * @return Reference to this object.
         */
        inline COcspCertId& operator=(COcspCertId&& other) {
            if (this != &other) {
                swap(_serialNumber, other._serialNumber);
                swap(_issuerKeyHash, other._issuerKeyHash);
                swap(_issuerNameHash, other._issuerNameHash);
                swap(_hashAlgo, other._hashAlgo);
            }

            return *this;
        }

        /**
         * Checks if this COcspCertId object is empty.
         *
         * @return True if the object is empty, false otherwise.
         */
        inline bool empty() const {
             return _hashAlgo == crypto::EHASH_UNKNOWN;
        }

        /**
         * Boolean conversion operator.
         *
         * @return True if the object is not empty, false otherwise.
         */
        inline operator bool() const {
            return !empty();
        }

        /**
         * Logical NOT operator.
         *
         * @return True if the object is empty, false otherwise.
         */
        inline bool operator!() const {
            return empty();
        }

        /**
         * Returns the serial number of the certificate.
         */
        inline const COctet& serialNumber() const { return _serialNumber; }

        /**
         * Returns the issuer key hash of the certificate.
         */
        inline const COctet& issuerKeyHash() const { return _issuerKeyHash; }

        /**
         * Returns the issuer name hash of the certificate.
         */
        inline const COctet& issuerNameHash() const { return _issuerNameHash; }

        /**
         * Returns the hash algorithm used for the issuer key and name hashes.
         */
        inline crypto::EHashers hashAlgo() const { return _hashAlgo; }

        /**
         * Creates a COcspCertId object for the given certificate, deriving the issuer's name
         * hash from cert's own issuer() field and the issuer's key hash from cert's own
         * AuthorityKeyIdentifier extension (id-ce-authorityKeyIdentifier)'s keyIdentifier --
         * which, per RFC 5280 4.2.1.1 method 1 (the convention this library's own CAkiExtensionBuilder
         * follows, and by far the most common one in practice), already *is* the SHA-1 hash of
         * the issuer's SubjectPublicKeyInfo.subjectPublicKey -- exactly what OCSP's issuerKeyHash
         * needs. Always uses SHA-1 (EHASH_SHA1), matching that convention; use the other make()
         * overload (which takes the issuer's own certificate directly) for any other hash
         * algorithm, or when cert has no usable AuthorityKeyIdentifier.
         *
         * @param cert The certificate to create the OCSP Cert ID for.
         * @param out The resulting COcspCertId object.
         * @return ERET_OK on success; ERET_INVAL if cert is empty; ERET_NOTSUP if cert has no
         * AuthorityKeyIdentifier extension with a keyIdentifier to use.
         */
        static ERetCode make(const CCert& cert, COcspCertId& out);

        /**
         * Creates a COcspCertId object for cert, hashing issuer's own Name and
         * SubjectPublicKeyInfo.subjectPublicKey directly with hashAlgo -- the fully general form
         * (RFC 6960 4.1.1), correct for any hash algorithm and not dependent on cert carrying any
         * particular extension.
         *
         * @param cert The certificate to create the OCSP Cert ID for.
         * @param issuer cert's own issuing CA certificate.
         * @param hashAlgo The hash algorithm to use for issuerNameHash/issuerKeyHash.
         * @param out The resulting COcspCertId object.
         * @return ERET_OK on success; ERET_INVAL if cert/issuer is empty; ERET_NOTSUP if
         * hashAlgo isn't one this library can hash with.
         */
        static ERetCode make(const CCert& cert, const CCert& issuer, crypto::EHashers hashAlgo, COcspCertId& out);

        /**
         * Decodes a complete CertID SEQUENCE TLV (RFC 6960 4.1.1) into out.
         *
         * @param rawData The complete CertID TLV bytes.
         * @param out The object to store the decoded certificate ID.
         * @return ERetCode indicating success or failure.
         */
        static ERetCode decode(const COctet& rawData, COcspCertId& out);

        /**
         * Encodes this certificate ID as a complete CertID SEQUENCE TLV (RFC 6960 4.1.1).
         *
         * @param rawData The buffer to receive the encoded TLV.
         * @return ERetCode indicating success or failure.
         */
        ERetCode encode(COctet& rawData) const;

        /**
         * Checks if this COcspCertId object is equal to another.
         *
         * @param other The COcspCertId object to compare with.
         * @return True if the objects are equal, false otherwise.
         */
        bool equals(const COcspCertId& other) const;

        /**
         * Checks if this COcspCertId object is for the given certificate.
         *
         * @param cert The certificate to check against.
         * @return True if this COcspCertId is for the given certificate, false otherwise.
         */
        bool isFor(const CCert& cert) const;

        /**
         * Equality operator.
         *
         * @param other The COcspCertId object to compare with.
         * @return True if the objects are equal, false otherwise.
         */
        inline bool operator==(const COcspCertId& other) const {
            return equals(other);
        }

        /**
         * Inequality operator.
         *
         * @param other The COcspCertId object to compare with.
         * @return True if the objects are not equal, false otherwise.
         */
        inline bool operator!=(const COcspCertId& other) const {
            return !equals(other);
        }
    };

    /**
     * Enumeration representing the status of an OCSP entry.
     */
    enum EOcspEntryStatus {
        EOCSPENT_GOOD = 0,
        EOCSPENT_REVOKED = 1,
        EOCSPENT_UNKNOWN = 2
    };

    /**
     * Represents an OCSP entry.
     */
    class CERTPP_API COcspEntry {
    private:
        COcspCertId _certId;
        EOcspEntryStatus _status;
        ECrlReasons _reason;

        SDateTime _thisUpdate;      // --> Required (SingleResponse.thisUpdate, RFC 6960 4.2.1).
        SDateTime _nextUpdate;      // --> Optional.
        SDateTime _revocationTime;  // --> Meaningful only when status() == EOCSPENT_REVOKED.

    public:
        /**
         * Default constructor initializing the OCSP entry with unknown status and no reason.
         */
        COcspEntry() : _status(EOCSPENT_UNKNOWN), _reason(ECRLR_NONE) {}

        /**
         * Constructor initializing the OCSP entry with the given certificate ID, status, reason,
         * and timing fields.
         *
         * @param certId The certificate ID associated with the OCSP entry.
         * @param status The status of the OCSP entry.
         * @param reason The reason for the OCSP entry's status (meaningful only when status is
         * EOCSPENT_REVOKED).
         * @param thisUpdate The time at which this status was known to be correct
         * (SingleResponse.thisUpdate) -- required for a usable entry.
         * @param nextUpdate The time by which newer status information will be available, if
         * known (SingleResponse.nextUpdate) -- optional.
         * @param revocationTime The time this certificate was revoked (RevokedInfo.revocationTime)
         * -- meaningful (and required for a usable entry) only when status is EOCSPENT_REVOKED.
         */
        COcspEntry(
            const COcspCertId& certId, EOcspEntryStatus status = EOCSPENT_UNKNOWN, ECrlReasons reason = ECRLR_NONE,
            const SDateTime& thisUpdate = SDateTime(), const SDateTime& nextUpdate = SDateTime(),
            const SDateTime& revocationTime = SDateTime()
        )
            : _certId(certId), _status(status), _reason(reason),
              _thisUpdate(thisUpdate), _nextUpdate(nextUpdate), _revocationTime(revocationTime)
        {
        }

        /**
         * Copy constructor.
         *
         * @param other The COcspEntry object to copy from.
         */
        COcspEntry(const COcspEntry& other)
            : _certId(other._certId), _status(other._status), _reason(other._reason),
              _thisUpdate(other._thisUpdate), _nextUpdate(other._nextUpdate), _revocationTime(other._revocationTime)
        {
        }

        /**
         * Move constructor.
         *
         * @param other The COcspEntry object to move from.
         */
        COcspEntry(COcspEntry&& other) noexcept
            : _certId(std::move(other._certId)), _status(other._status), _reason(other._reason),
              _thisUpdate(other._thisUpdate), _nextUpdate(other._nextUpdate), _revocationTime(other._revocationTime)
        {
        }

        /**
         * Copy assignment operator.
         *
         * @param other The COcspEntry object to assign from.
         * @return Reference to the assigned COcspEntry object.
         */
        inline COcspEntry& operator=(const COcspEntry& other) {
            if (this != &other) {
                _certId = other._certId;
                _status = other._status;
                _reason = other._reason;
                _thisUpdate = other._thisUpdate;
                _nextUpdate = other._nextUpdate;
                _revocationTime = other._revocationTime;
            }

            return *this;
        }

        /**
         * Move assignment operator.
         *
         * @param other The COcspEntry object to assign from.
         * @return Reference to the assigned COcspEntry object.
         */
        inline COcspEntry& operator=(COcspEntry&& other) noexcept {
            if (this != &other) {
                swap(_certId, other._certId);
                swap(_status, other._status);
                swap(_reason, other._reason);
                swap(_thisUpdate, other._thisUpdate);
                swap(_nextUpdate, other._nextUpdate);
                swap(_revocationTime, other._revocationTime);
            }

            return *this;
        }

        /**
         * Checks if the OCSP entry is empty.
         *
         * @return True if the OCSP entry is empty, false otherwise.
         */
        inline bool empty() const {
            return _certId.empty();
        }

        /**
         * Checks if the OCSP entry is not empty.
         *
         * @return True if the OCSP entry is not empty, false otherwise.
         */
        inline operator bool() const {
            return !empty();
        }

        /**
         * Checks if the OCSP entry is empty using the logical NOT operator.
         *
         * @return True if the OCSP entry is empty, false otherwise.
         */
        inline bool operator!() const {
            return empty();
        }

        /**
         * Returns the certificate ID associated with the OCSP entry.
         */
        inline const COcspCertId& certId() const { return _certId; }

        /**
         * Returns the status of the OCSP entry.
         */
        inline EOcspEntryStatus status() const { return _status; }

        /**
         * Returns the reason for the OCSP entry's status.
         */
        inline ECrlReasons reason() const { return _reason; }

        /**
         * Returns the time at which this entry's status was known to be correct
         * (SingleResponse.thisUpdate).
         */
        inline const SDateTime& thisUpdate() const { return _thisUpdate; }

        /**
         * Returns the time by which newer status information will be available, if known
         * (SingleResponse.nextUpdate) -- SDateTime::isZero() when absent.
         */
        inline const SDateTime& nextUpdate() const { return _nextUpdate; }

        /**
         * Returns the time this certificate was revoked (RevokedInfo.revocationTime).
         * Meaningful only when status() == EOCSPENT_REVOKED.
         */
        inline const SDateTime& revocationTime() const { return _revocationTime; }

        /**
         * Checks if the OCSP entry is for the specified certificate.
         *
         * @param cert The certificate to check against.
         * @return True if the OCSP entry is for the specified certificate, false otherwise.
         */
        inline bool isFor(const CCert& cert) const {
            return _certId.isFor(cert);
        }

        /**
         * Decodes a complete SingleResponse SEQUENCE TLV (RFC 6960 4.2.1) into out.
         *
         * @param rawData The complete SingleResponse TLV bytes.
         * @param out The object to store the decoded entry.
         * @return ERetCode indicating success or failure.
         */
        static ERetCode decode(const COctet& rawData, COcspEntry& out);

        /**
         * Encodes this entry as a complete SingleResponse SEQUENCE TLV (RFC 6960 4.2.1).
         *
         * @param rawData The buffer to receive the encoded TLV.
         * @return ERET_OK on success; ERET_INVAL if certId()/thisUpdate() (or, for a revoked
         * entry, revocationTime()) aren't set.
         */
        ERetCode encode(COctet& rawData) const;
    };
    
    /**
     * Represents an OCSP request (OCSPRequest, RFC 6960 4.1.1) -- a reader, parsing a request a
     * client sent; see COcspRequestBuilder for the writer side (the Reader/Writer split
     * CCrlReader/CCrlWriter already use).
     */
    class CERTPP_API COcspRequest {
    private:
        COctet _rawData;
        COctet _nonceBytes;
        CDistinguishedName _requestorName; // --> From requestorName's directoryName alternative only.

        TArray<COcspCertId> _certIds;

        // --> Set only by decode(), for verifySignature()'s own use (mirrors COcspResponse's own
        // _tbsResponseDataRaw/_sigHashAlgo/_signatureValue): tbsRequest's complete SEQUENCE TLV
        // bytes, the digest algorithm optionalSignature.signatureAlgorithm resolves to
        // (EHASH_UNKNOWN for a self-hashing EdDSA signature), and the raw signature bytes.
        // _signatureValue stays empty for an unsigned request (optionalSignature absent).
        COctet _tbsRequestRaw;
        crypto::EHashers _sigHashAlgo = crypto::EHASH_UNKNOWN;
        COctet _signatureValue;

    public:

        /**
         * Returns the raw data of the OCSP request.
         */
        inline const COctet& rawData() const { return _rawData; }

        /**
         * Returns the nonce bytes of the OCSP request.
         */
        inline const COctet& nonceBytes() const { return _nonceBytes; }

        /**
         * Returns the certificate IDs included in the OCSP request.
         */
        inline const TArray<COcspCertId>& certIds() const { return _certIds; }

        /**
         * Returns the requestor's claimed identity (TBSRequest.requestorName), if present and a
         * directoryName -- empty if absent, or present as some other GeneralName alternative.
         * Set regardless of whether the request is actually signed; see verifySignature() to
         * check that independently.
         */
        inline const CDistinguishedName& requestorName() const { return _requestorName; }

        /**
         * Checks if the OCSP request contains a certificate ID for the specified certificate.
         *
         * @param cert The certificate to check against.
         * @return True if the OCSP request contains a certificate ID for the specified certificate, false otherwise.
         */
        bool contains(const CCert& cert) const {
            for (const auto& certId : _certIds) {
                if (certId.isFor(cert)) {
                    return true;
                }
            }

            return false;
        }

        /**
         * Decodes the OCSP request from the specified data.
         *
         * @param data The data to decode the OCSP request from.
         * @return ERetCode indicating success or failure.
         */
        ERetCode decode(const CBuffer& data);

        /**
         * Decodes the OCSP request from a COctet, which is what every other decoder in this
         * module takes -- and what COcspRequestBuilder::build() produces, so without this
         * overload the module's own writer could not be fed to its own reader without an
         * intermediate re-wrap.
         *
         * @param rawData The data to decode the OCSP request from.
         * @return ERetCode indicating success or failure.
         */
        inline ERetCode decode(const COctet& rawData) {
            return decode(CBuffer(rawData.toPtr(), rawData.size()));
        }

        /**
         * Verifies this request's optionalSignature against requestorCert's public key -- only
         * meaningful for a request that was actually signed (see requestorName()'s own doc
         * comment: a present requestorName doesn't by itself mean the request was signed).
         *
         * @param requestorCert The certificate whose public key signed this request (typically
         * the certificate named by requestorName(), though this method doesn't itself check
         * that correspondence).
         * @return ERET_OK if the signature is valid; ERET_INVAL if this request carries no
         * signature to check; another ERetCode otherwise (e.g. the signature doesn't match).
         */
        ERetCode verifySignature(const CCert& requestorCert) const;
    };

    /**
     * Builds an OCSP request (OCSPRequest, RFC 6960 4.1.1) -- the writer side; see COcspRequest
     * for the reader (the Reader/Writer split CCrlReader/CCrlWriter already use).
     */
    class CERTPP_API COcspRequestBuilder {
    private:
        TArray<COcspCertId> _certIds;
        COctet _nonceBytes;
        CCert _requestorCert; // --> Optional; see requestorCert()'s own doc comment.

    public:
        /**
         * Returns the certificate IDs this builder will query for.
         */
        inline const TArray<COcspCertId>& certIds() const { return _certIds; }

        /**
         * Returns the nonce bytes build() will embed.
         */
        inline const COctet& nonceBytes() const { return _nonceBytes; }

        /**
         * Sets the nonce bytes build() embeds, replacing any previously set one -- an
         * alternative to generateNonce() for a caller that already has its own nonce bytes
         * (e.g. one being reused, or generated by other means).
         * @param nonce The nonce bytes to set.
         * @return A reference to this builder, for chaining.
         */
        inline COcspRequestBuilder& nonceBytes(const COctet& nonce) {
            _nonceBytes = nonce;
            return *this;
        }

        /**
         * Returns the requestor certificate build() signs with, if set.
         */
        inline const CCert& requestorCert() const { return _requestorCert; }

        /**
         * Sets the requestor's own certificate: build() embeds its subject() as
         * TBSRequest.requestorName and signs the request with its attached private key
         * (CCert::privateKey(IPrivateKeyPtr&)) -- a private key is then required at build() time
         * (ERET_KEY_EMPTY otherwise), since setting this field at all is taken as an explicit
         * request to sign, not merely to claim an identity. Leave unset (the default) for the
         * overwhelmingly common unsigned request, which RFC 6960 fully allows.
         * @param cert The requestor's own certificate, with its private key attached.
         * @return A reference to this builder, for chaining.
         */
        inline COcspRequestBuilder& requestorCert(const CCert& cert) {
            _requestorCert = cert;
            return *this;
        }

        /**
         * Generates a fresh random nonce (RFC 8954), replacing any previously set one -- an
         * anti-replay measure a client adds to a newly-built request, which a conforming
         * responder echoes back unchanged in its response (see COcspResponse::nonceBytes()).
         *
         * @param size The nonce length in bytes (RFC 8954 recommends 1-32; defaults to 16).
         * @return ERET_OK on success; another ERetCode if the underlying CSPRNG fails.
         */
        ERetCode generateNonce(size_t size = 16);

        /**
         * Checks if a certificate ID for the specified certificate has already been added.
         *
         * @param cert The certificate to check against.
         * @return True if present, false otherwise.
         */
        inline bool contains(const CCert& cert) const {
            for (const auto& certId : _certIds) {
                if (certId.isFor(cert)) {
                    return true;
                }
            }

            return false;
        }

        /**
         * Adds a certificate ID to the request, derived from cert's own
         * AuthorityKeyIdentifier extension -- see COcspCertId::make(const CCert&, COcspCertId&)'s
         * own doc comment for the exact convention/limitation this relies on.
         *
         * @param cert The certificate to add.
         * @return ERetCode indicating success or failure.
         */
        ERetCode add(const CCert& cert);

        /**
         * Adds a certificate ID to the request, hashing issuer's own Name/public key directly
         * with hashAlgo -- the fully general form; see
         * COcspCertId::make(const CCert&, const CCert&, EHashers, COcspCertId&).
         *
         * @param cert The certificate to add.
         * @param issuer cert's own issuing CA certificate.
         * @param hashAlgo The hash algorithm to use for issuerNameHash/issuerKeyHash.
         * @return ERetCode indicating success or failure.
         */
        ERetCode add(const CCert& cert, const CCert& issuer, crypto::EHashers hashAlgo = crypto::EHASH_SHA1);

        /**
         * Removes a certificate ID from the request.
         *
         * @param cert The certificate whose ID to remove.
         * @return ERetCode indicating success or failure.
         */
        ERetCode remove(const CCert& cert);

        /**
         * Builds (and, if requestorCert() is set, signs) this request, the inverse of
         * COcspRequest::decode().
         *
         * @param out The buffer to receive the encoded request.
         * @return ERET_OK on success; ERET_INVAL if no certificate ID has been added;
         * ERET_KEY_EMPTY if requestorCert() is set but has no private key attached; ERET_NOTSUP
         * if requestorCert()'s algorithm can't sign at all; another ERetCode for other failures.
         */
        ERetCode build(COctet& out) const;
    };

    /**
     * Represents an OCSP response (OCSPResponse, RFC 6960 4.2.1) -- both a reader (decode(), for
     * a client consuming a responder's answer) and a writer (add()/build(), for a responder
     * producing one), the same single-class split CCert itself follows for its own
     * import/export. responseStatus values other than successful (status() != EOCSP_OK) carry no
     * further data at all (no entries, no signature, no responder) -- see build()'s own doc
     * comment for how that's handled on encode.
     *
     * Only the id-pkix-ocsp-basic response type is supported (the only one RFC 6960 defines),
     * and only ResponderID's byName CHOICE alternative (responderName()) -- byKey is a
     * decode()-time no-op (responderName() stays empty); the optional BasicOCSPResponse.certs
     * field (embedded certificates) is never produced and, if present, is skipped on decode().
     */
    class CERTPP_API COcspResponse {
    private:
        COctet _rawData;

        EOcspStatus _status;
        uint32_t _version;
        CDistinguishedName _responderName;
        SDateTime _producedAt;
        TArray<COcspEntry> _entries;
        COctet _nonceBytes;

        // --> Set only by decode(), for verifySignature()'s own use: tbsResponseData's complete
        // SEQUENCE TLV bytes (the signed message), the digest algorithm BasicOCSPResponse.
        // signatureAlgorithm resolves to (EHASH_UNKNOWN for a self-hashing EdDSA signature, same
        // convention CCert::_sigHashAlgo uses), and the raw signatureValue bytes.
        COctet _tbsResponseDataRaw;
        crypto::EHashers _sigHashAlgo;
        COctet _signatureValue;

    public:
        /**
         * Default constructor.
         */
        COcspResponse() : _status(EOCSP_INTERNAL), _version(0), _sigHashAlgo(crypto::EHASH_UNKNOWN) {}

        /**
         * Copy constructor.
         * @param other The object to copy from.
         */
        COcspResponse(const COcspResponse& other)
            : _rawData(other._rawData), _status(other._status), _version(other._version),
              _responderName(other._responderName), _producedAt(other._producedAt), _entries(other._entries),
              _nonceBytes(other._nonceBytes), _tbsResponseDataRaw(other._tbsResponseDataRaw),
              _sigHashAlgo(other._sigHashAlgo), _signatureValue(other._signatureValue)
        {
        }

        /**
         * Move constructor.
         * @param other The object to move from.
         */
        COcspResponse(COcspResponse&& other) noexcept
            : _rawData(move(other._rawData)), _status(other._status), _version(other._version),
              _responderName(move(other._responderName)), _producedAt(other._producedAt),
              _entries(move(other._entries)), _nonceBytes(move(other._nonceBytes)),
              _tbsResponseDataRaw(move(other._tbsResponseDataRaw)), _sigHashAlgo(other._sigHashAlgo),
              _signatureValue(move(other._signatureValue))
        {
        }

        /**
         * Copy assignment operator.
         * @param other The object to copy from.
         * @return A reference to this object.
         */
        inline COcspResponse& operator=(const COcspResponse& other) {
            if (this != &other) {
                _rawData = other._rawData;
                _status = other._status;
                _version = other._version;
                _responderName = other._responderName;
                _producedAt = other._producedAt;
                _entries = other._entries;
                _nonceBytes = other._nonceBytes;
                _tbsResponseDataRaw = other._tbsResponseDataRaw;
                _sigHashAlgo = other._sigHashAlgo;
                _signatureValue = other._signatureValue;
            }

            return *this;
        }

        /**
         * Move assignment operator.
         * @param other The object to move from.
         * @return A reference to this object.
         */
        inline COcspResponse& operator=(COcspResponse&& other) noexcept {
            if (this != &other) {
                swap(_rawData, other._rawData);
                swap(_status, other._status);
                swap(_version, other._version);
                swap(_responderName, other._responderName);
                swap(_producedAt, other._producedAt);
                swap(_entries, other._entries);
                swap(_nonceBytes, other._nonceBytes);
                swap(_tbsResponseDataRaw, other._tbsResponseDataRaw);
                swap(_sigHashAlgo, other._sigHashAlgo);
                swap(_signatureValue, other._signatureValue);
            }

            return *this;
        }

        /**
         * Checks if the OCSP response is empty (never decode()d).
         */
        inline bool empty() const { return _rawData.empty(); }

        /**
         * @return True if the OCSP response is not empty.
         */
        inline operator bool() const { return !empty(); }

        /**
         * @return True if the OCSP response is empty.
         */
        inline bool operator!() const { return empty(); }

        /**
         * Resets this response to an empty, default state.
         */
        void clear();

        /**
         * Returns the raw DER-encoded data of the OCSP response.
         */
        inline const COctet& rawData() const { return _rawData; }

        /**
         * Returns the top-level responseStatus (RFC 6960 4.2.1). Only EOCSP_OK carries any
         * further data (version()/responderName()/producedAt()/entries() are all empty/zero for
         * any other status).
         */
        inline EOcspStatus status() const { return _status; }

        /**
         * Returns ResponseData.version (0 = v1, the only version RFC 6960 defines).
         */
        inline uint32_t version() const { return _version; }

        /**
         * Returns the responder's own name (ResponderID.byName) -- empty if this response used
         * ResponderID.byKey instead (not decoded by this class), or hasn't been decoded yet.
         */
        inline const CDistinguishedName& responderName() const { return _responderName; }

        /**
         * Returns ResponseData.producedAt: when this response was signed.
         */
        inline const SDateTime& producedAt() const { return _producedAt; }

        /**
         * Returns this response's own per-certificate entries (ResponseData.responses).
         */
        inline const TArray<COcspEntry>& entries() const { return _entries; }

        /**
         * Returns the nonce bytes carried in responseExtensions (RFC 8954) -- empty if the
         * response didn't use one. A client typically compares this against its own request's
         * nonceBytes() to rule out a replayed response.
         */
        inline const COctet& nonceBytes() const { return _nonceBytes; }

        /**
         * Finds the entry for cert, if any.
         * @param cert The certificate to search for.
         * @param out The object to store the found entry.
         * @return ERET_OK if found (out populated); ERET_INVAL otherwise.
         */
        ERetCode find(const CCert& cert, COcspEntry& out) const;

        /**
         * Checks cert's status according to this response's entries.
         * @param cert The certificate to check.
         * @return ERET_OK if cert's entry says EOCSPENT_GOOD; ERET_ALREADY if EOCSPENT_REVOKED
         * (mirroring CCrlReader::check()'s own convention); ERET_NOTSUP if EOCSPENT_UNKNOWN;
         * ERET_INVAL if cert has no entry here at all, or is itself empty.
         */
        ERetCode check(const CCert& cert) const;

        /**
         * Verifies this response's signature against responderCert's public key. No-op/fails
         * for a non-EOCSP_OK response, which carries no signature at all.
         *
         * @param responderCert The certificate whose public key signed this response (the
         * responder's own certificate -- a client would normally also independently validate
         * that this certificate is actually authorized to answer for the certificate in
         * question, which is outside this method's own scope).
         * @return ERET_OK if the signature is valid; ERET_INVAL if this response carries no
         * signature to check (status() != EOCSP_OK, or never decode()d); another ERetCode
         * otherwise (e.g. the signature doesn't match).
         */
        ERetCode verifySignature(const CCert& responderCert) const;

        /**
         * Decodes an OCSPResponse (RFC 6960 4.2.1) from raw DER data, the inverse of
         * COcspResponseBuilder::build(). When responseStatus isn't successful (status() !=
         * EOCSP_OK), there's nothing further to parse (responseBytes is absent by the grammar)
         * -- version()/responderName()/producedAt()/entries() are simply left at their
         * default/empty state.
         *
         * @param rawData The raw DER-encoded OCSP response.
         * @return ERET_OK on success; ERET_INVAL if rawData is empty; ERET_BADREQ if rawData
         * isn't a well-formed OCSPResponse; ERET_NOTSUP if responseBytes.responseType isn't
         * id-pkix-ocsp-basic (the only response type this library implements).
         */
        ERetCode decode(const COctet& rawData);
    };

    /**
     * Builds an OCSP response (OCSPResponse, RFC 6960 4.2.1) -- the writer side; see
     * COcspResponse for the reader (the Reader/Writer split CCrlReader/CCrlWriter and
     * COcspRequest/COcspRequestBuilder already use).
     */
    class CERTPP_API COcspResponseBuilder {
    private:
        EOcspStatus _status;
        CDistinguishedName _responderName;
        SDateTime _producedAt;
        TArray<COcspEntry> _entries;
        COctet _nonceBytes;

    public:
        /**
         * Default constructor. status() defaults to EOCSP_INTERNAL (an explicit "not yet
         * decided" sentinel distinct from EOCSP_OK, so build() never silently succeeds with a
         * status the caller never actually chose).
         */
        COcspResponseBuilder() : _status(EOCSP_INTERNAL) {}

        /**
         * Returns the responseStatus build() will encode.
         */
        inline EOcspStatus status() const { return _status; }

        /**
         * Sets the responseStatus to encode via build().
         * @param status The status to set.
         * @return A reference to this builder, for chaining.
         */
        inline COcspResponseBuilder& status(EOcspStatus status) {
            _status = status;
            return *this;
        }

        /**
         * Returns the responder name build() will embed, if explicitly set.
         */
        inline const CDistinguishedName& responderName() const { return _responderName; }

        /**
         * Overrides the responder name build() embeds, instead of deriving it from the
         * responder certificate's own subject() -- see build()'s own doc comment.
         * @param name The responder name to set.
         * @return A reference to this builder, for chaining.
         */
        inline COcspResponseBuilder& responderName(const CDistinguishedName& name) {
            _responderName = name;
            return *this;
        }

        /**
         * Returns the producedAt time build() will encode.
         */
        inline const SDateTime& producedAt() const { return _producedAt; }

        /**
         * Sets the producedAt time to encode via build().
         * @param producedAt The time to set.
         * @return A reference to this builder, for chaining.
         */
        inline COcspResponseBuilder& producedAt(const SDateTime& producedAt) {
            _producedAt = producedAt;
            return *this;
        }

        /**
         * Returns this builder's own per-certificate entries added so far.
         */
        inline const TArray<COcspEntry>& entries() const { return _entries; }

        /**
         * Returns the nonce bytes build() will echo back.
         */
        inline const COctet& nonceBytes() const { return _nonceBytes; }

        /**
         * Sets the nonce bytes to echo back via build() (RFC 8954) -- a responder typically sets
         * this from the originating request's own nonceBytes().
         * @param nonce The nonce bytes to echo.
         * @return A reference to this builder, for chaining.
         */
        inline COcspResponseBuilder& nonceBytes(const COctet& nonce) {
            _nonceBytes = nonce;
            return *this;
        }

        /**
         * Adds a pre-built entry (e.g. one a responder built directly from a request's own
         * COcspCertId, without necessarily holding the subject certificate itself) -- replacing
         * any existing entry for the same certificate, like CCrlWriter::add().
         * @param entry The entry to add.
         * @return ERET_OK on success; ERET_INVAL if entry is empty.
         */
        ERetCode add(const COcspEntry& entry);

        /**
         * Builds and adds an entry for cert, deriving its COcspCertId via
         * COcspCertId::make(cert, issuer, hashAlgo, ...) -- a convenience over
         * add(const COcspEntry&) for a responder that holds the actual certificates.
         *
         * @param cert The certificate this entry answers for.
         * @param issuer cert's own issuing CA certificate.
         * @param status The certificate's status.
         * @param thisUpdate When this status was known to be correct.
         * @param nextUpdate When newer status information will be available, if any.
         * @param reason The revocation reason (meaningful only when status is EOCSPENT_REVOKED).
         * @param revocationTime The revocation time (required when status is EOCSPENT_REVOKED).
         * @param hashAlgo The hash algorithm for the entry's own COcspCertId.
         * @return ERetCode indicating success or failure.
         */
        ERetCode add(
            const CCert& cert, const CCert& issuer, EOcspEntryStatus status, const SDateTime& thisUpdate,
            const SDateTime& nextUpdate = SDateTime(), ECrlReasons reason = ECRLR_NONE,
            const SDateTime& revocationTime = SDateTime(), crypto::EHashers hashAlgo = crypto::EHASH_SHA1
        );

        /**
         * Removes cert's entry, if present.
         * @param cert The certificate whose entry to remove.
         * @return ERET_OK on success; ERET_INVAL if cert has no entry here.
         */
        ERetCode remove(const CCert& cert);

        /**
         * Builds and signs a response from this builder's current status()/entries()/
         * producedAt(), the inverse of COcspResponse::decode(). When status() is EOCSP_OK,
         * responder must have an attached private key (CCert::privateKey(IPrivateKeyPtr&));
         * responderName() is used if explicitly set, otherwise derived from responder's own
         * subject(). When status() is anything else, responder/entries/producedAt are all
         * ignored entirely -- a non-successful OCSPResponse carries nothing beyond its
         * responseStatus (RFC 6960 4.2.1), so build() just encodes that single ENUMERATED value.
         *
         * @param responder The responder's own certificate, with its private key attached
         * (ignored when status() != EOCSP_OK).
         * @param out The buffer to receive the encoded, signed response.
         * @return ERET_OK on success; ERET_INVAL if status() is EOCSP_OK but producedAt() (or
         * responderName(), with neither it nor responder's own subject() set) is missing;
         * ERET_KEY_EMPTY if responder has no private key attached; ERET_NOTSUP if responder's
         * algorithm can't sign at all; another ERetCode for other failures.
         */
        ERetCode build(const CCert& responder, COctet& out) const;
    };
} // namespace x509
} // namespace certpp

#endif
