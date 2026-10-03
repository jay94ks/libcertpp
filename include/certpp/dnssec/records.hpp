#ifndef __INCLUDE_CERTPP_DNSSEC_RECORDS_HPP__
#define __INCLUDE_CERTPP_DNSSEC_RECORDS_HPP__

#include <certpp/common.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/io/span.hpp>
#include <certpp/string.hpp>

namespace certpp {
namespace dnssec {

    /**
     * DNSSEC algorithm numbers, as IANA assigns them. The numeric values are part of the wire
     * format, so they are pinned explicitly rather than left to run in declaration order.
     */
    enum EDnsAlgorithms {
        EDNSALG_UNKNOWN = 0,              /**< Not a recognised algorithm number */
        EDNSALG_RSAMD5 = 1,               /**< RSA/MD5 (RFC 3110); must not be used (RFC 8624) */
        EDNSALG_DSA = 3,                  /**< DSA/SHA-1 (RFC 2536) */
        EDNSALG_RSASHA1 = 5,              /**< RSA/SHA-1 (RFC 3110) */
        EDNSALG_DSA_NSEC3_SHA1 = 6,       /**< DSA-NSEC3-SHA1 (RFC 5155) */
        EDNSALG_RSASHA1_NSEC3_SHA1 = 7,   /**< RSASHA1-NSEC3-SHA1 (RFC 5155) */
        EDNSALG_RSASHA256 = 8,            /**< RSA/SHA-256 (RFC 5702) */
        EDNSALG_RSASHA512 = 10,           /**< RSA/SHA-512 (RFC 5702) */
        EDNSALG_ECC_GOST = 12,            /**< GOST R 34.10-2001 (RFC 5933); must not be used */
        EDNSALG_ECDSAP256SHA256 = 13,     /**< ECDSA P-256 with SHA-256 (RFC 6605) */
        EDNSALG_ECDSAP384SHA384 = 14,     /**< ECDSA P-384 with SHA-384 (RFC 6605) */
        EDNSALG_ED25519 = 15,             /**< Ed25519 (RFC 8080) */
        EDNSALG_ED448 = 16,               /**< Ed448 (RFC 8080) */
    };

    /**
     * DS digest algorithm numbers, as IANA assigns them. As with the algorithm numbers, these
     * values are on the wire and so are pinned explicitly.
     */
    enum EDnsDigests {
        EDNSDIG_UNKNOWN = 0,              /**< Not a recognised digest number */
        EDNSDIG_SHA1 = 1,                 /**< SHA-1 (RFC 4034) */
        EDNSDIG_SHA256 = 2,               /**< SHA-256 (RFC 4509) */
        EDNSDIG_GOST = 3,                 /**< GOST R 34.11-94 (RFC 5933); must not be used */
        EDNSDIG_SHA384 = 4,               /**< SHA-384 (RFC 6605) */
    };

    /**
     * A DNSKEY record's RDATA (RFC 4034 2.1): sixteen bits of flags, a protocol octet, an
     * algorithm octet, and the public key in an encoding the algorithm decides.
     *
     * The public key here is kept in its **DNS** encoding, not converted to a
     * `crypto::IPublicKey`. That conversion is `CDnssecKeys`' job, and it is kept separate
     * because the two directions fail for different reasons: RDATA can be well-formed and still
     * hold a key this library has no algorithm for, and the key tag and the DS digest are both
     * computed over the raw RDATA regardless of whether the key inside it can be parsed.
     */
    struct CERTPP_API SDnskey {
        /** The flags field, whose individual bits the accessors below name. */
        uint16_t flags;

        /** The protocol field, which RFC 4034 2.1.2 fixes at 3; any other value is invalid. */
        uint8_t protocol;

        /** The algorithm the public key belongs to. */
        EDnsAlgorithms algorithm;

        /** The public key, in the DNS encoding its algorithm defines. */
        CBuffer publicKey;

        /** The value RFC 4034 2.1.2 requires in the protocol field. */
        static constexpr uint8_t PROTOCOL_DNSSEC = 3;

        /** Flags bit 7, "Zone Key" (RFC 4034 2.1.1). */
        static constexpr uint16_t FLAG_ZONE_KEY = 0x0100;

        /** Flags bit 8, "Revoked" (RFC 5011 2.1). */
        static constexpr uint16_t FLAG_REVOKED = 0x0080;

        /** Flags bit 15, "Secure Entry Point" (RFC 4034 2.1.1, RFC 3757). */
        static constexpr uint16_t FLAG_SECURE_ENTRY_POINT = 0x0001;

        /**
         * Constructs an empty record with the protocol field already set to 3.
         */
        SDnskey();

        /**
         * Reports whether the Zone Key flag is set, i.e. whether this key signs zone data at all.
         * @return True if the flag is set.
         */
        inline bool isZoneKey() const {
            return (flags & FLAG_ZONE_KEY) != 0;
        }

        /**
         * Reports whether the Revoked flag is set (RFC 5011).
         * @return True if the flag is set.
         */
        inline bool isRevoked() const {
            return (flags & FLAG_REVOKED) != 0;
        }

        /**
         * Reports whether the Secure Entry Point flag is set, which conventionally marks a
         * key-signing key.
         * @return True if the flag is set.
         */
        inline bool isSecureEntryPoint() const {
            return (flags & FLAG_SECURE_ENTRY_POINT) != 0;
        }

        /**
         * Parses DNSKEY RDATA.
         * @param rdata The RDATA; at least four octets, followed by the public key.
         * @return True on success, false if the RDATA is too short or the protocol field is not 3.
         */
        bool fromRdata(const SReadOnlyByteSpan& rdata);

        /**
         * Serialises this record back to DNSKEY RDATA.
         * @param out Receives the RDATA; cleared first.
         * @return True on success, false if the public key is empty.
         */
        bool toRdata(TArray<uint8_t>& out) const;

        /**
         * Computes this key's key tag (RFC 4034 Appendix B).
         *
         * The tag is a checksum over the whole RDATA, not an identifier stored anywhere, so it
         * is derived here rather than held as a field -- holding it would let it disagree with
         * the key it names.
         * @param out Receives the key tag.
         * @return True on success, false if the record cannot be serialised.
         */
        bool keyTag(uint16_t& out) const;
    };

    /**
     * A DS record's RDATA (RFC 4034 5.1): the key tag and algorithm of the DNSKEY it points at,
     * the digest algorithm, and the digest itself.
     */
    struct CERTPP_API SDsRecord {
        /** The key tag of the DNSKEY this record points at. */
        uint16_t keyTag;

        /** The algorithm of the DNSKEY this record points at. */
        EDnsAlgorithms algorithm;

        /** The algorithm the digest was computed with. */
        EDnsDigests digestType;

        /** The digest itself. */
        CBuffer digest;

        /**
         * Constructs an empty record.
         */
        SDsRecord();

        /**
         * Parses DS RDATA.
         * @param rdata The RDATA; at least four octets, followed by the digest.
         * @return True on success, false if the RDATA is too short or the digest length does not
         *         match the digest algorithm.
         */
        bool fromRdata(const SReadOnlyByteSpan& rdata);

        /**
         * Serialises this record back to DS RDATA.
         * @param out Receives the RDATA; cleared first.
         * @return True on success, false if the digest is empty.
         */
        bool toRdata(TArray<uint8_t>& out) const;

        /**
         * Builds the DS record for a DNSKEY (RFC 4034 5.1.4).
         *
         * The digest is taken over the key's canonical owner name followed by its DNSKEY RDATA,
         * which is why the owner name has to be passed in: it is not part of the RDATA, and a
         * digest computed without it -- or over an unfolded name -- disagrees with every
         * published DS.
         * @param owner The DNSKEY's owner name, in presentation format.
         * @param key The DNSKEY.
         * @param digestType The digest algorithm to use.
         * @param out Receives the DS record.
         * @return True on success, false if the owner name or key is malformed, or the digest
         *         algorithm is one this library has no hash for.
         */
        static bool fromDnskey(
            const CString& owner, const SDnskey& key, EDnsDigests digestType, SDsRecord& out
        );

        /**
         * Reports whether this DS record vouches for a given DNSKEY, recomputing the digest and
         * comparing it in constant time.
         * @param owner The DNSKEY's owner name, in presentation format.
         * @param key The DNSKEY to check.
         * @return True if the key tag, algorithm, digest algorithm and digest all agree.
         */
        bool matches(const CString& owner, const SDnskey& key) const;
    };

    /**
     * An RRSIG record's RDATA (RFC 4034 3.1).
     *
     * The signature covers the RDATA up to but not including the signature field, followed by
     * the RRset in canonical form. `toSignedPrefix()` produces that first part;
     * assembling the canonical RRset is the caller's job, since it needs the records themselves
     * and this library does not model DNS RRsets.
     */
    struct CERTPP_API SRrsig {
        /** The RR type this signature covers. */
        uint16_t typeCovered;

        /** The signing algorithm. */
        EDnsAlgorithms algorithm;

        /** The number of labels in the signed name, excluding the root and any wildcard. */
        uint8_t labels;

        /** The original TTL of the covered RRset. */
        uint32_t originalTtl;

        /** Signature expiration, as seconds since the Unix epoch. */
        uint32_t expiration;

        /** Signature inception, as seconds since the Unix epoch. */
        uint32_t inception;

        /** The key tag of the DNSKEY that made this signature. */
        uint16_t keyTag;

        /** The signer's name, in presentation format. */
        CString signerName;

        /** The signature, in the encoding its algorithm defines. */
        CBuffer signature;

        /**
         * Constructs an empty record.
         */
        SRrsig();

        /**
         * Parses RRSIG RDATA.
         * @param rdata The RDATA: the eighteen fixed octets, the signer's name in wire format,
         *              then the signature.
         * @return True on success, false if the RDATA is too short or the signer's name is
         *         malformed.
         */
        bool fromRdata(const SReadOnlyByteSpan& rdata);

        /**
         * Serialises this record back to RRSIG RDATA.
         * @param out Receives the RDATA; cleared first.
         * @return True on success, false if the signer's name is malformed or the signature is
         *         empty.
         */
        bool toRdata(TArray<uint8_t>& out) const;

        /**
         * Serialises everything the signature covers from this record -- the RDATA with the
         * signature field omitted (RFC 4034 3.1.8.1).
         *
         * This is the first thing fed to the hash when signing or verifying; the canonical
         * RRset follows it.
         * @param out Receives the prefix; cleared first.
         * @return True on success, false if the signer's name is malformed.
         */
        bool toSignedPrefix(TArray<uint8_t>& out) const;
    };

} // namespace dnssec
} // namespace certpp

#endif
