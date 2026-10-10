#ifndef __INCLUDE_CERTPP_ASN1_READER_HPP__
#define __INCLUDE_CERTPP_ASN1_READER_HPP__

#include <certpp/common.hpp>
#include <certpp/time.hpp>
#include <certpp/string.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/stream.hpp>
#include <certpp/asn1/tag.hpp>
#include <certpp/asn1/decoder.hpp>

namespace certpp {
namespace asn1 {

    /**
     * Sequentially reads ASN.1 tag-length-values from an IStream (or an in-memory span), pairing
     * CDecoder's content-level decode*() methods with stream/cursor management.
     *
     * Constructed from an IStream, a CReader keeps that stream and pulls from it lazily: it reads
     * more bytes into an internal buffer only when a read actually needs data it doesn't already
     * have buffered, rather than reading the whole stream up front (data written to the stream
     * after construction, but before it's needed, is still visible -- CReader never assumes it
     * has already seen everything the stream will ever produce). CDecoder's decoders need a
     * contiguous in-memory span regardless (and BER/CER's indefinite-length form requires
     * scanning ahead), so growing that buffer is unavoidable; it just happens on demand instead
     * of eagerly. Constructed from a span directly (e.g. a parent element's content, for
     * descending into a SEQUENCE/SET -- see readSequence()/readSet()/readConstructed()), there's
     * no stream to grow from, so it simply aliases the span. Because of the owned, on-demand-
     * reallocated buffer a stream-backed CReader has, it is move-only: copying would leave the
     * copy's cursor pointing into the source's buffer instead of its own.
     *
     * Every typed read*() method reads and decodes the next element as a specific, plain
     * UNIVERSAL, primitive tag -- if the next element's tag doesn't match (including a
     * constructed value, since none of CDecoder's content-level decoders reassemble
     * constructed/segmented BER/CER strings) or its content fails to decode, the read fails and
     * the cursor is left exactly where it was, so the caller can try a different read or treat
     * the field as absent (e.g. an OPTIONAL/DEFAULT X.509 field). For IMPLICIT-tagged or
     * otherwise non-universal-tagged content, use the lower-level readNextElement() and call
     * CDecoder's content-level decode*() directly on the returned content.
     */
    class CERTPP_API CReader {
    private:
        IStreamPtr _stream;
        EEncodingRule _ruleSet;
        COctet _buffer;
        SReadOnlyByteSpan _cursor;

        /* Bumped every time growBuffer() reallocates _buffer, so a saved SReadOnlyByteSpan into
         * it can be recognized as potentially stale (see withRollback()). */
        size_t _generation;

    private:
        /**
         * Pulls one more chunk from _stream (if any), rebuilding _buffer from [the cursor's
         * current unconsumed bytes, followed by the newly-read chunk] and pointing _cursor at
         * the whole (grown) buffer. Bumps _generation on success.
         * @return True if more data was read; false if there's no stream, it's exhausted, or
         * reallocation failed.
         */
        bool growBuffer();

        /**
         * Snapshots the cursor, invokes fn (which may call readNextElement()/growBuffer() zero or
         * more times), and on failure restores the cursor to exactly what it was before fn ran --
         * even if growBuffer() reallocated _buffer along the way, in which case the snapshot's
         * pointer would otherwise be dangling. growBuffer() always rebuilds _buffer from exactly
         * the cursor's pre-growth unconsumed bytes plus newly-read ones, so whenever _generation
         * changed during fn, the whole current _buffer *is* the correct restored state; otherwise
         * the plain saved span is still valid as-is.
         */
        template<typename TFn>
        bool withRollback(TFn&& fn) {
            SReadOnlyByteSpan saved = _cursor;
            size_t savedGeneration = _generation;

            if (fn()) {
                return true;
            }

            _cursor = (_generation != savedGeneration) ? _buffer.toSpan() : saved;
            return false;
        }

        /**
         * Reads the next element and, only if its tag exactly matches expectedTag and decodeFn
         * accepts its content, commits the read. Otherwise the cursor is left untouched.
         */
        template<typename TDecodeFn>
        bool tryReadPrimitive(const CTag& expectedTag, TDecodeFn&& decodeFn) {
            return withRollback([&]() {
                CTag tag;
                SReadOnlyByteSpan content;
                return readNextElement(tag, content) && tag == expectedTag && decodeFn(content);
            });
        }

    public:
        /**
         * Constructs an empty CReader (atEnd() is immediately true).
         */
        CReader();

        /**
         * Constructs a CReader that reads from an in-memory span directly (aliased, not copied).
         * @param content The span to read from.
         * @param ruleSet The ASN.1 encoding rule set to use.
         */
        explicit CReader(SReadOnlyByteSpan content, EEncodingRule ruleSet = EAENC_DER);

        /**
         * Constructs a CReader that reads from an IStream, from its current position onward. No
         * data is read from stream yet at this point -- see the class comment.
         * @param stream The stream to read from.
         * @param ruleSet The ASN.1 encoding rule set to use.
         */
        explicit CReader(const IStreamPtr& stream, EEncodingRule ruleSet = EAENC_DER);

        CReader(const CReader&) = delete;
        CReader& operator=(const CReader&) = delete;
        CReader(CReader&&) = default;
        CReader& operator=(CReader&&) = default;

    public:
        /**
         * Checks whether the reader is at the end of its content: nothing left buffered, and
         * (for a stream-backed reader) the stream itself reports no more data either.
         */
        inline bool atEnd() const {
            if (!_cursor.empty()) {
                return false;
            }

            return !_stream || _stream->position() >= _stream->length();
        }

        /**
         * Returns the not-yet-consumed remainder of what's currently buffered. For a
         * stream-backed reader, this does not include data the stream could still produce but
         * that hasn't been read into the buffer yet.
         */
        inline SReadOnlyByteSpan remaining() const {
            return _cursor;
        }

        /**
         * Reads the next encoded ASN.1 value, advancing the cursor past it. The low-level
         * primitive every other read*() method builds on; use this directly for IMPLICIT-tagged
         * or CHOICE content the typed methods can't recognize by their plain universal tag.
         * @param outTag The output tag of the encoded value.
         * @param outArea The output span containing the encoded value's content.
         * @return True if a value was successfully read; false on a parse error or if the reader
         * was already at the end (the cursor is left unchanged either way).
         */
        bool readNextElement(CTag& outTag, SReadOnlyByteSpan& outArea);

        /**
         * Reads the next element expecting a constructed value, returning a nested CReader over
         * its content for the caller to descend into. Unlike the typed read*() methods, this
         * accepts any tag class/value as long as the value is constructed -- the caller checks
         * outTag themselves (e.g. to distinguish a context-specific [n] EXPLICIT wrapper).
         * @param outTag The output tag of the constructed value.
         * @param outReader A nested reader over the constructed value's content.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readConstructed(CTag& outTag, CReader& outReader);

        /**
         * Reads the next element expecting a SEQUENCE (universal, constructed), returning a
         * nested CReader over its content for the caller to iterate.
         * @param outReader A nested reader over the SEQUENCE's content.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readSequence(CReader& outReader);

        /**
         * Reads the next element expecting a SET (universal, constructed), returning a nested
         * CReader over its content for the caller to iterate. Doesn't re-validate CER/DER's
         * canonical child ordering; that's an encoder-side (CWriter-side) concern.
         * @param outReader A nested reader over the SET's content.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readSet(CReader& outReader);

        /**
         * Reads the next element expecting a BOOLEAN (universal, primitive).
         * @param outValue The decoded value.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readBoolean(bool& outValue);

        /**
         * Reads the next element expecting an INTEGER (universal, primitive).
         * @param outValue The decoded value.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readInteger(int64_t& outValue);

        /**
         * Reads the next element expecting an ENUMERATED (universal, primitive).
         * @param outValue The decoded value.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readEnumerated(uint32_t& outValue);

        /**
         * Reads the next element expecting a NULL (universal, primitive).
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readNull();

        /**
         * Reads the next element expecting an OCTET STRING (universal, primitive). Rejects a
         * constructed (segmented) encoding, since decodeOctetString() doesn't reassemble one.
         * @param outValue The decoded value (aliases into the reader's own buffer/span).
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readOctetString(SReadOnlyByteSpan& outValue);

        /**
         * Reads the next element expecting an OCTET STRING (universal, primitive) into an owning
         * COctet, copying the content rather than aliasing it.
         * @param outValue The decoded value.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readOctetString(COctet& outValue);

        /**
         * Reads the next element expecting a BIT STRING (universal, primitive). Rejects a
         * constructed (segmented) encoding, since decodeBitString() doesn't reassemble one.
         * @param outBits The packed bit data octets (aliases into the reader's own buffer/span).
         * @param outUnusedBits The number of unused (padding) bits in the last octet of outBits.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readBitString(SReadOnlyByteSpan& outBits, uint8_t& outUnusedBits);

        /**
         * Reads the next element expecting a BIT STRING (universal, primitive) into an owning
         * COctet, copying the packed bit data rather than aliasing it.
         * @param outBits The decoded packed bit data.
         * @param outUnusedBits The number of unused (padding) bits in the last octet of outBits.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readBitString(COctet& outBits, uint8_t& outUnusedBits);

        /**
         * Reads the next element expecting an OBJECT IDENTIFIER (universal, primitive).
         * @param outArcs The destination for the decoded arc values.
         * @param outArcCount The number of arcs written to outArcs.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readOid(TSpan<uint32_t> outArcs, size_t& outArcCount);

        /**
         * Reads the next element expecting an OBJECT IDENTIFIER (universal, primitive) into an
         * SRawOid; see CDecoder::decodeOid().
         *
         * The form to prefer over readOidString() when the OID is being kept rather than shown:
         * it decodes to the arcs once, and the dotted-decimal text is then available from the
         * same object if it is ever wanted, instead of being formatted on every read.
         * @param outOid Receives the decoded OID. Left empty if this returns false.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readOid(SRawOid& outOid);

        /**
         * Reads the next element expecting an OBJECT IDENTIFIER (universal, primitive) directly
         * into its dotted-decimal text form; see CDecoder::decodeOidString().
         * @tparam TChar The destination TString's character type (char or wchar_t).
         * @param outValue The decoded dotted-decimal text.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        template<typename TChar>
        bool readOidString(TString<TChar>& outValue) {
            return tryReadPrimitive(CTag::OBJ_ID, [&](SReadOnlyByteSpan content) {
                return CDecoder::decodeOidString(content, outValue);
            });
        }

        /**
         * Reads the next element expecting the given character string kind (universal,
         * primitive); see CDecoder::decodeText() for which kinds get their character set
         * validated.
         * @param kind The expected universal string tag.
         * @param outText The decoded text (aliases into the reader's own buffer/span).
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readText(EUniversalTags kind, SReadOnlyByteSpan& outText);

        /**
         * Reads the next element expecting the given character string kind (universal,
         * primitive) directly into a TString; see CDecoder::decodeString().
         * @tparam TChar The destination TString's character type (char or wchar_t).
         * @param kind The expected universal string tag.
         * @param outValue The decoded string.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        template<typename TChar>
        bool readString(EUniversalTags kind, TString<TChar>& outValue) {
            CTag expected(kind, false);
            if (!expected) {
                return false;
            }

            return tryReadPrimitive(expected, [&](SReadOnlyByteSpan content) {
                return CDecoder::decodeString(content, kind, outValue);
            });
        }

        /**
         * Reads the next element expecting a UTCTime (universal, primitive).
         * @param outTime The decoded time.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readUtcTime(SDateTime& outTime);

        /**
         * Reads the next element expecting a GeneralizedTime (universal, primitive).
         * @param outTime The decoded time.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readGeneralizedTime(SDateTime& outTime);

        /**
         * Reads the next element expecting a CDistinguishedName (universal, constructed
         * SEQUENCE); see CDecoder::decodeDistinguishedName() for the exact structure expected.
         * @param outValue The decoded distinguished name.
         * @return True on success; otherwise, false (cursor unchanged).
         */
        bool readDistinguishedName(CDistinguishedName& outValue);
    };

} // namespace asn1
} // namespace certpp

#endif
