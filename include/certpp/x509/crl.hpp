#ifndef __INCLUDE_CERTPP_X509_CRL_HPP__
#define __INCLUDE_CERTPP_X509_CRL_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>
#include <certpp/time.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/x509/access.hpp>
#include <certpp/x509/cert.hpp>

namespace certpp {
namespace x509 {

    /**
     * Represents revocation information for a certificate in a CRL.
     */
    class CERTPP_API CCrlRevokationInfo {
        friend class CCrlWriter;

    private:
        COctet _rawData;
        COctet _serialNumber;
        SDateTime _timestamp;
        ECrlReasons _reason;

        /* id-ce-cRLReason (RFC 5280 5.3.1) -- the only per-entry crlEntryExtensions extension
         * this class interprets; any other extension present in an entry is simply ignored, the
         * same "only what's exposed is interpreted" contract CCert::parseExtensions() follows.
         * Used by encode()/decode(). */
        static constexpr SKnownOid OID_REASON_CODE = COid::EXT_CRL_REASON_CODE;

    public:
        /**
         * Default constructor initializes the timestamp and reason.
         */
        CCrlRevokationInfo() {
            _timestamp = SDateTime();
            _reason = ECRLR_NONE;
        }

        /**
         * Copy constructor.
         * @param other The object to copy from.
         */
        CCrlRevokationInfo(const CCrlRevokationInfo& other) {
            _rawData = other._rawData;
            _serialNumber = other._serialNumber;
            _timestamp = other._timestamp;
            _reason = other._reason;
        }

        /**
         * Move constructor.
         * @param other The object to move from.
         */
        CCrlRevokationInfo(CCrlRevokationInfo&& other) {
            _rawData = std::move(other._rawData);
            _serialNumber = std::move(other._serialNumber);
            _timestamp = std::move(other._timestamp);
            _reason = other._reason;
        }

        /**
         * Copy assignment operator.
         * @param other The object to copy from.
         * @return A reference to this object.
         */
        inline CCrlRevokationInfo& operator=(const CCrlRevokationInfo& other) {
            if (this != &other) {
                _rawData = other._rawData;
                _serialNumber = other._serialNumber;
                _timestamp = other._timestamp;
                _reason = other._reason;
            }

            return *this;
        }

        /**
         * Move assignment operator.
         * @param other The object to move from.
         * @return A reference to this object.
         */
        inline CCrlRevokationInfo& operator=(CCrlRevokationInfo&& other) {
            if (this != &other) {
                swap(_rawData, other._rawData);
                swap(_serialNumber, other._serialNumber);
                swap(_timestamp, other._timestamp);
                swap(_reason, other._reason);
            }

            return *this;
        }

        /**
         * Decodes the raw data to extract revocation information.
         * @param rawData The raw data containing the revocation information.
         * @param info The object to store the decoded revocation information.
         * @return An error code indicating success or failure.
         */
        static ERetCode decode(const COctet& rawData, CCrlRevokationInfo& info);

        /**
         * Encodes the revocation information into raw data.
         * @param rawData The object to store the encoded raw data.
         * @return An error code indicating success or failure.
         */
        ERetCode encode(COctet& rawData) const;

        /**
         * Checks if the revocation information is empty.
         */
        inline bool empty() const {
            return _rawData.empty();
         }

        /**
         * Returns the raw data of the revocation information.
         */
        inline const COctet& rawData() const { return _rawData; }

        /**
         * Returns the serial number of the revoked certificate.
         */
        inline const COctet& serialNumber() const { return _serialNumber; }

        /**
         * Returns the timestamp of the revocation.
         */
        inline const SDateTime& timestamp() const { return _timestamp; }

        /**
         * Returns the reason for the revocation.
         */
        inline ECrlReasons reason() const { return _reason; }

        /**
         * Checks if the revocation information is for the given certificate.
         * @param cert The certificate to check.
         * @return An error code indicating success or failure.
         */
        ERetCode isFor(const CCert& cert) const;
    };

    /**
     * Represents a reader for Certificate Revocation Lists (CRLs).
     */
    class CERTPP_API CCrlReader {
    private:
        COctet _rawData;
        TArray<CCrlRevokationInfo> _revokations;

        uint32_t _version;
        CDistinguishedName _issuer;
        SDateTime _thisUpdate;
        SDateTime _nextUpdate;
        COctet _signature;
        crypto::EHashers _sigHashAlgo;

    public:
        /**
         * Default constructor initializes the revocation list.
         */
        CCrlReader() {
            _version = 0;
            _thisUpdate = SDateTime();
            _nextUpdate = SDateTime();
            _sigHashAlgo = crypto::EHASH_UNKNOWN;
        }

        /**
         * Copy constructor.
         * @param other The object to copy from.
         */
        CCrlReader(const CCrlReader& other) {
            _rawData = other._rawData;
            _revokations = other._revokations;
            _version = other._version;
            _issuer = other._issuer;
            _thisUpdate = other._thisUpdate;
            _nextUpdate = other._nextUpdate;
            _signature = other._signature;
            _sigHashAlgo = other._sigHashAlgo;
        }

        /**
         * Move constructor.
         * @param other The object to move from.
         */
        CCrlReader(CCrlReader&& other) noexcept {
            _rawData = std::move(other._rawData);
            _revokations = std::move(other._revokations);
            _version = other._version;
            _issuer = std::move(other._issuer);
            _thisUpdate = std::move(other._thisUpdate);
            _nextUpdate = std::move(other._nextUpdate);
            _signature = std::move(other._signature);
            _sigHashAlgo = other._sigHashAlgo;
        }

        /**
         * Copy assignment operator.
         * @param other The object to copy from.
         * @return A reference to this object.
         */
        inline CCrlReader& operator=(const CCrlReader& other) {
            if (this != &other) {
                _rawData = other._rawData;
                _revokations = other._revokations;
                _version = other._version;
                _issuer = other._issuer;
                _thisUpdate = other._thisUpdate;
                _nextUpdate = other._nextUpdate;
                _signature = other._signature;
                _sigHashAlgo = other._sigHashAlgo;
            }

            return *this;
        }

        /**
         * Move assignment operator.
         * @param other The object to move from.
         * @return A reference to this object.
         */
        inline CCrlReader& operator=(CCrlReader&& other) noexcept {
            if (this != &other) {
                swap(_rawData, other._rawData);
                swap(_revokations, other._revokations);
                swap(_version, other._version);
                swap(_issuer, other._issuer);
                swap(_thisUpdate, other._thisUpdate);
                swap(_nextUpdate, other._nextUpdate);
                swap(_signature, other._signature);
                swap(_sigHashAlgo, other._sigHashAlgo);
            }

            return *this;
        }

        /**
         * Checks if the CRL reader is empty, i.e., all its data members are in their default states.
         * @return True if the CRL reader is empty, false otherwise.
         */
        inline bool empty() const {
            return _rawData.empty() 
                && _revokations.empty() 
                && _version == 0 && _issuer.empty() 
                ;
        }

        /**
         * Returns the raw data of the CRL.
         */
        inline const COctet& rawData() const { return _rawData; }

        /**
         * Returns the version of the CRL.
         */
        inline uint32_t version() const { return _version; }

        /**
         * Returns the issuer of the CRL.
         */
        inline const CDistinguishedName& issuer() const { return _issuer; }

        /**
         * Returns the thisUpdate timestamp of the CRL.
         */
        inline const SDateTime& thisUpdate() const { return _thisUpdate; }

        /**
         * Returns the nextUpdate timestamp of the CRL.
         */
        inline const SDateTime& nextUpdate() const { return _nextUpdate; }

        /**
         * Decodes the raw data to extract the list of revocation information.
         * @param rawData The raw data containing the CRL.
         * @return An error code indicating success or failure.
         */
        ERetCode decode(const COctet& rawData);

        /**
         * Encodes the list of revocation information into raw data.
         * @param rawData The object to store the encoded raw data.
         * @return An error code indicating success or failure.
         */
        ERetCode encode(COctet& rawData) const;

        /**
         * Clears the CRL reader, resetting all its data members to their default states.
         */
        inline void clear() {
            _rawData.clear();
            _revokations.clear();
            _version = 0;
            _issuer = CDistinguishedName{};
            _thisUpdate = SDateTime{};
            _nextUpdate = SDateTime{};
        }

        /**
         * Returns the list of revocation information.
         */
        inline const TArray<CCrlRevokationInfo>& revokations() const { return _revokations; }

        /**
         * Finds the revocation information for the given certificate.
         * @param cert The certificate to search for.
         * @param out The object to store the found revocation information.
         * @return An error code indicating success or failure.
         */
        ERetCode find(const CCert& cert, CCrlRevokationInfo& out) const;

        /**
         * Checks if the given certificate is revoked according to the CRL.
         *
         * This answers only "does this CRL list this certificate": it does not verify the CRL's
         * own signature, nor confirm the CRL was issued by the certificate's issuer. A caller
         * that needs either must call verifyBy() and compare issuer() itself -- a CRL from an
         * unrelated CA with a colliding serial number would otherwise produce a verdict about a
         * certificate it says nothing about.
         * @param cert The certificate to check.
         * @return An error code indicating if the certificate is revoked or not.
         */
        ERetCode check(const CCert& cert) const;

        /**
         * Returns the raw signature bits from CertificateList.signatureValue, with the BIT STRING
         * wrapper and its unused-bit count stripped. Its internal format is the signature
         * algorithm's own, exactly as with CCert::signature().
         * @return The signature value, or an empty COctet if no CRL has been decoded.
         */
        inline const COctet& signature() const { return _signature; }

        /**
         * Returns the exact tbsCertList element the signature was computed over: its complete TLV
         * (tag and length included), as it appears inside rawData(). These are the original
         * issuer-produced bytes rather than a re-encoding, for the same reason
         * CCert::tbsCertificate() is -- the signature covers what the issuer wrote.
         * @return The tbsCertList's complete DER element, or an empty span if no CRL has been
         * decoded or its outer structure cannot be walked.
         */
        SReadOnlyByteSpan tbsCertList() const;

        /**
         * Verifies this CRL's signature against an issuer certificate's public key.
         *
         * Like CCert::verifyBy(), this is a single-link signature check only: it does not confirm
         * that issuer() matches the certificate's subject, nor check thisUpdate()/nextUpdate().
         * @param issuer The certificate whose public key is expected to have signed this CRL.
         * @return ERET_OK if the signature verifies; ERET_INVAL if no CRL has been decoded or it
         * carries no signature/tbsCertList; ERET_KEY_EMPTY if the issuer exposes no usable public
         * key; ERET_NOTSUP if the signature algorithm isn't one this library can verify;
         * ERET_HASH_PIPE if hashing failed; otherwise whatever the algorithm's verify() reported.
         */
        ERetCode verifyBy(const CCert& issuer) const;
    };


    /**
     * A class for writing CRLs.
     */
    class CERTPP_API CCrlWriter {
    private:
        TArray<CCrlRevokationInfo> _revokations;

        uint32_t _version;
        CDistinguishedName _issuer;
        SDateTime _thisUpdate;
        SDateTime _nextUpdate;

    public:
        /**
         * Constructs a new CRL writer with default values.
         */
        CCrlWriter() {
            _version = 0;
            _thisUpdate = SDateTime{};
            _nextUpdate = SDateTime{};
        }

        /**
         * Copy constructor.
         * @param other The CRL writer to copy from.
         */
        CCrlWriter(const CCrlWriter& other) {
            _revokations = other._revokations;
            _version = other._version;
            _issuer = other._issuer;
            _thisUpdate = other._thisUpdate;
            _nextUpdate = other._nextUpdate;
        }

        /**
         * Move constructor.
         * @param other The CRL writer to move from.
         */
        CCrlWriter(CCrlWriter&& other) noexcept {
            _revokations = std::move(other._revokations);
            _version = other._version;
            _issuer = std::move(other._issuer);
            _thisUpdate = other._thisUpdate;
            _nextUpdate = other._nextUpdate;
        }
    
        /**
         * Copy assignment operator.
         * @param other The CRL writer to copy from.
         * @return A reference to this CRL writer.
         */
        inline CCrlWriter& operator=(const CCrlWriter& other) {
            if (this != &other) {
                _revokations = other._revokations;
                _version = other._version;
                _issuer = other._issuer;
                _thisUpdate = other._thisUpdate;
                _nextUpdate = other._nextUpdate;
            }

            return *this;
        }

        /**
         * Move assignment operator.
         * @param other The CRL writer to move from.
         * @return A reference to this CRL writer.
         */
        inline CCrlWriter& operator=(CCrlWriter&& other) noexcept {
            if (this != &other) {
                swap(_revokations, other._revokations);
                swap(_version, other._version);
                swap(_issuer, other._issuer);
                swap(_thisUpdate, other._thisUpdate);
                swap(_nextUpdate, other._nextUpdate);
            }

            return *this;
        }

        /**
         * Clears the CRL writer, resetting all its data members to their default states.
         */
        inline void clear() {
            _revokations.clear();
            _version = 0;
            _issuer = CDistinguishedName{};
            _thisUpdate = SDateTime{};
            _nextUpdate = SDateTime{};
        }

        /**
         * Returns the list of revocation information.
         */
        inline const TArray<CCrlRevokationInfo>& revokations() const { return _revokations; }

        /**
         * Returns the version of the CRL.
         */
        inline uint32_t version() const { return _version; }

        /**
         * Returns the issuer of the CRL.
         */
        inline const CDistinguishedName& issuer() const { return _issuer; }

        /**
         * Returns the date and time of the last update of the CRL.
         */
        inline const SDateTime& thisUpdate() const { return _thisUpdate; }

        /**
         * Returns the date and time of the next update of the CRL.
         */
        inline const SDateTime& nextUpdate() const { return _nextUpdate; }

        /**
         * Sets the version of the CRL.
         * @param version The version to set.
         * @return A reference to this CRL writer.
         */
        inline CCrlWriter& version(uint32_t version) {
            _version = version;
            return *this;
        }

        /**
         * Sets the issuer of the CRL.
         * @param issuer The issuer to set.
         * @return A reference to this CRL writer.
         * @note The issuer certificate must match the issuer of the CRL.
         */
        inline CCrlWriter& issuer(const CDistinguishedName& issuer) {
            _issuer = issuer;
            return *this;
        }

        /**
         * Sets the date and time of the last update of the CRL.
         * @param thisUpdate The date and time to set.
         * @return A reference to this CRL writer.
         */
        inline CCrlWriter& thisUpdate(const SDateTime& thisUpdate) {
            _thisUpdate = thisUpdate;
            return *this;
        }

        /**
         * Sets the date and time of the next update of the CRL.
         * @param nextUpdate The date and time to set.
         * @return A reference to this CRL writer.
         */
        inline CCrlWriter& nextUpdate(const SDateTime& nextUpdate) {
            _nextUpdate = nextUpdate;
            return *this;
        }

        /**
         * Adds a new revocation entry to the CRL.
         * @param cert The certificate to revoke.
         * @param when The date and time of revocation.
         * @param reason The reason for revocation.
         * @return An error code indicating success or failure.
         */
        ERetCode add(const CCert& cert, const SDateTime& when, ECrlReasons reason);

        /**
         * Removes a revocation entry from the CRL.
         * @param cert The certificate to remove from the revocation list.
         * @return An error code indicating success or failure.
         */
        ERetCode remove(const CCert& cert);

        /**
         * Builds the CRL.
         * @param issuer The issuer certificate.
         * @param out The output buffer to store the built CRL.
         * @return An error code indicating success or failure.
         */
        ERetCode build(const CCert& issuer, COctet& out);
    };

} // namespace x509
} // namespace certpp

#endif
