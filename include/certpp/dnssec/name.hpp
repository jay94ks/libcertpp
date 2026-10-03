#ifndef __INCLUDE_CERTPP_DNSSEC_NAME_HPP__
#define __INCLUDE_CERTPP_DNSSEC_NAME_HPP__

#include <certpp/common.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/span.hpp>
#include <certpp/string.hpp>

namespace certpp {
namespace dnssec {

    /**
     * Domain names in DNS wire format: a sequence of length-prefixed labels terminated by a
     * zero-length root label, which is how a name appears inside DNSKEY, RRSIG and DS material.
     *
     * Everything here produces the **canonical** form RFC 4034 6.2 defines, meaning ASCII
     * uppercase letters are folded to lowercase. That is not cosmetic: a DS record's digest is
     * taken over the owner name followed by the DNSKEY RDATA, so a name that reaches the digest
     * unfolded yields a DS that disagrees with every published one. The conversion is one-way
     * about case by design -- `fromWire()` returns what the wire held, and `toWire()` always
     * folds -- because an API that let the caller choose would make it possible to compute a
     * non-canonical digest by accident.
     *
     * Compression pointers (RFC 1035 4.1.4) are deliberately **not** supported. DNSSEC forbids
     * them in the names it signs over, and accepting one here would mean accepting material that
     * cannot be canonicalised without the rest of the message to resolve the pointer against.
     */
    class CERTPP_API CDnsName {
    public:
        /** Maximum length of a name in wire format, including the root label (RFC 1035 2.3.4). */
        static constexpr size_t MAX_WIRE_BYTES = 255;

        /** Maximum length of a single label (RFC 1035 2.3.4). */
        static constexpr size_t MAX_LABEL_BYTES = 63;

    public:
        /**
         * Encodes a presentation-format name into canonical wire format, folding ASCII uppercase
         * to lowercase.
         *
         * A trailing dot is optional and means the same thing either way; the root name is
         * spelled "." or "" and encodes to the single zero octet.
         * @param name The name in presentation format, e.g. "example.net." or "example.net".
         * @param out Receives the wire-format name; cleared first.
         * @return True on success, false if a label is empty, over-long, or the whole name
         *         exceeds MAX_WIRE_BYTES.
         */
        static bool toWire(const CString& name, TArray<uint8_t>& out);

        /**
         * Decodes a wire-format name into presentation format, always with a trailing dot.
         *
         * The case is whatever the wire held; this does not fold, since the wire form is the
         * authoritative one at this point.
         * @param wire The wire-format name. Trailing bytes after the root label are rejected.
         * @param out Receives the presentation-format name; cleared first.
         * @return True on success, false if the encoding is malformed or over-long.
         */
        static bool fromWire(const SReadOnlyByteSpan& wire, CString& out);

        /**
         * Decodes a wire-format name that is followed by further data, reporting how many bytes
         * it consumed. This is what RRSIG RDATA needs, where the signer's name is followed
         * immediately by the signature.
         * @param wire The wire-format name, possibly followed by unrelated bytes.
         * @param out Receives the presentation-format name; cleared first.
         * @param consumed Receives the number of bytes the name occupied, root label included.
         * @return True on success, false if the encoding is malformed or over-long.
         */
        static bool fromWirePrefix(
            const SReadOnlyByteSpan& wire, CString& out, size_t& consumed
        );

        /**
         * Counts the labels in a wire-format name, excluding the root label.
         *
         * This is the value RRSIG's Labels field carries (RFC 4034 3.1.3), which a verifier uses
         * to recognise a wildcard expansion.
         * @param wire The wire-format name.
         * @param out Receives the label count.
         * @return True on success, false if the encoding is malformed.
         */
        static bool countLabels(const SReadOnlyByteSpan& wire, size_t& out);

        /**
         * Reports whether a wire-format name is already canonical, i.e. holds no ASCII uppercase.
         * @param wire The wire-format name.
         * @return True if the name is well-formed and contains no ASCII uppercase letter.
         */
        static bool isCanonical(const SReadOnlyByteSpan& wire);
    };

}
}

#endif
