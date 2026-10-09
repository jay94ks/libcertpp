#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::asn1;

// Each example is one function, preceded by a `// === <TypeName> ===` marker. The function body
// is what gets published as that type's example, dedented, so write it as the code a caller
// would write -- not as a test. See the brief for the rules.

// === CDecoder ===
// Reads a DER document's outer SEQUENCE and walks its members. The output span is the value's
// *content* octets, while bytesRead counts the tag and length too -- so iterating with the span
// is what descends into a constructed value, and iterating with bytesRead is what steps over it.
void exampleCDecoder(SReadOnlyByteSpan der) {
    CTag tag;
    SReadOnlyByteSpan content;
    size_t bytesRead = 0;

    if (!CDecoder::readEncodedValue(der, EAENC_DER, tag, content, bytesRead)) {
        return;
    }

    if (tag != CTag(CTag::SEQ)) {
        return;
    }

    SReadOnlyByteSpan cursor = content;
    CTag childTag;
    SReadOnlyByteSpan childContent;

    while (CDecoder::readNextElement(cursor, EAENC_DER, childTag, childContent)) {
        int64_t number = 0;
        if (childTag == CTag(CTag::INTEGER) && CDecoder::decodeInteger(childContent, number)) {
            // number holds this member's value
        }
    }
}

// === EDecoderStatus ===
// Drives a reader over bytes that arrive a chunk at a time. The point of the enum is the one
// distinction a bool cannot carry: EDEC_NEED_MORE means append more input and ask again, and
// every other non-OK status means this input will never parse however much is appended.
bool exampleEDecoderStatus(IStreamPtr source, CBuffer& sofar, size_t& filled) {
    CTag tag;
    SReadOnlyByteSpan content;
    size_t bytesRead = 0;

    while (true) {
        const EDecoderStatus status = CDecoder::tryReadEncodedValue(
            SReadOnlyByteSpan(sofar.toPtr(), filled), EAENC_DER, tag, content, bytesRead);

        if (status == EDEC_OK) {
            return true;        // content and bytesRead are now meaningful
        }

        if (status != EDEC_NEED_MORE) {
            return false;       // malformed, prohibited under DER, or past a decoder limit
        }

        // Incomplete, not wrong. How much more is not knowable in general -- the length octets
        // may themselves be the truncated part -- so read what the source has and retry.
        if (filled >= sofar.size() && !sofar.resize(sofar.size() * 2 + 64)) {
            return false;
        }

        // --> Named rather than a temporary, because IStream::read() takes its SByteSpan by
        // non-const reference, and C++ will not bind a non-const lvalue reference to a
        // temporary. MSVC accepts that; GCC and Clang reject it, so the example built on one
        // toolchain and not the other.
        SByteSpan chunk(sofar.toPtr() + filled, sofar.size() - filled);
        const size_t got = source->read(chunk);
        if (got == 0) {
            return false;       // the source ended mid-value: truncated for good
        }

        filled += got;
    }
}

// === EEncodingRule ===
// The rule set is not decoration -- it decides which encodings are legal. These bytes are a
// valid (if wasteful) BER OCTET STRING whose length uses the long form below 128, and an invalid
// DER one; read X.509 input with EAENC_DER or a hand-crafted non-canonical length slips past.
void exampleEEncodingRule() {
    const uint8_t data[] = { 0x04, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
    SReadOnlyByteSpan source(data, sizeof(data));

    CTag tag;
    SReadOnlyByteSpan content;
    size_t bytesRead = 0;

    if (CDecoder::readEncodedValue(source, EAENC_BER, tag, content, bytesRead)) {
        // accepted: BER permits any well-formed length form
    }

    if (!CDecoder::readEncodedValue(source, EAENC_DER, tag, content, bytesRead)) {
        // rejected: DER and CER both require the minimal length form
    }
}

// === CDer ===
// Builds the `SEQUENCE { INTEGER r, INTEGER s }` that DSA/ECDSA signatures use, then reads it
// back. Every append*() appends to what the destination already holds rather than replacing it,
// which is how the inner members are concatenated before appendSequence() wraps them.
void exampleCDer(const CBigNum& r, const CBigNum& s) {
    TArray<uint8_t> inner;
    if (!CDer::appendBigInteger(inner, r) || !CDer::appendBigInteger(inner, s)) {
        return;
    }

    TArray<uint8_t> signature;
    if (!CDer::appendSequence(signature, SReadOnlyByteSpan(inner.begin(), inner.size()))) {
        return;
    }

    SReadOnlyByteSpan content;
    if (!CDer::readOuterSequence(SReadOnlyByteSpan(signature.begin(), signature.size()), content)) {
        return;
    }

    // readBigInteger() advances the cursor past the element it read, so the two calls take the
    // members in order and an empty cursor afterwards means there was nothing trailing.
    CBigNum readR, readS;
    if (CDer::readBigInteger(content, readR) && CDer::readBigInteger(content, readS) && content.empty()) {
        // readR == r and readS == s
    }
}

// === CEncoder ===
// Encodes an INTEGER in two steps, because that is how the class is split: encodeInteger() writes
// only the content octets, and writeEncodedValue() wraps content in its tag and length. Each
// reports its own bytesWritten, and that -- not the buffer's sizeof -- is the encoded length.
void exampleCEncoder(int64_t serial) {
    uint8_t content[8];
    size_t contentLength = 0;

    if (!CEncoder::encodeInteger(TSpan<uint8_t>(content, sizeof(content)), serial, contentLength)) {
        return;
    }

    const CTag tag(EAUTAG_INTEGER, false);
    SReadOnlyByteSpan body(content, contentLength);

    uint8_t element[16];
    size_t elementLength = 0;

    if (CEncoder::encodedValueSize(tag, body) > sizeof(element)) {
        return;
    }

    if (!CEncoder::writeEncodedValue(TSpan<uint8_t>(element, sizeof(element)), EAENC_DER, tag, body, elementLength)) {
        return;
    }

    // element[0 .. elementLength) is the complete DER tag-length-value
}

// === CReader ===
// Descends into a DER SEQUENCE read from a stream. A failed typed read leaves the cursor exactly
// where it was, which is what makes probing an OPTIONAL or DEFAULT field safe: try the type the
// field would have, and if it is not there, read on as if nothing had happened.
void exampleCReader(const IStreamPtr& der) {
    CReader reader(der, EAENC_DER);

    CReader members;
    if (!reader.readSequence(members)) {
        return;
    }

    int64_t version = 0;
    if (!members.readInteger(version)) {
        version = 1;    // absent: the cursor still points at the next field
    }

    CWideString label;
    if (!members.readString(EAUTAG_STRING_UTF8, label)) {
        return;
    }

    while (!members.atEnd()) {
        CTag tag;
        SReadOnlyByteSpan content;
        if (!members.readNextElement(tag, content)) {
            return;
        }
    }
}

// === CTag ===
// Decodes the tag at the front of an encoded element and re-encodes it. Compare whole tags, not
// just value(): equals() takes the class and the constructed bit into account and deliberately
// ignores the raw low bits decode() keeps, so a decoded SEQUENCE tag does compare equal here.
void exampleCTag(SReadOnlyByteSpan element) {
    size_t bytesRead = 0;
    CTag tag = CTag::decode(element, bytesRead);

    if (!tag) {
        return;
    }

    if (tag == CTag(CTag::SEQ)) {
        // universal, constructed, number 16
    }

    uint8_t buf[6];
    size_t written = 0;

    if (!tag.encode(TSpan<uint8_t>(buf, sizeof(buf)), written)) {
        return;
    }

    if (written != bytesRead || std::memcmp(buf, element.data, written) != 0) {
        return;     // only reachable on a non-minimal (BER) tag encoding
    }
}

// === ETagClass ===
// Wraps an already-encoded value in a `[0] EXPLICIT` tag. The class is a constructor argument and
// cannot be inferred from the number: tag number 0 means an end-of-contents marker under
// EATAG_UNIVERSAL and the first context-specific field of the enclosing SEQUENCE under this one.
void exampleETagClass(const IStreamPtr& out, SReadOnlyByteSpan inner) {
    CTag explicitZero(EATAG_CONTEXT_SPECIFIC, 0, true);
    if (!explicitZero) {
        return;
    }

    CWriter writer(out, EAENC_DER);
    if (!writer.writeElement(explicitZero, inner)) {
        return;
    }

    // An IMPLICIT [0] over a primitive value is the same class with the constructed bit cleared.
    const CTag implicitZero = explicitZero.asPrimitive();
    if (implicitZero.tagClass() != EATAG_CONTEXT_SPECIFIC) {
        return;
    }
}

// === EUniversalTags ===
// Picks the string type a name is written as. The kind selects which character set gets
// validated, so a text containing anything outside PrintableString's restricted set is refused
// rather than written under a tag that lies about it -- fall back to UTF8String on that refusal.
void exampleEUniversalTags(const IStreamPtr& out, const CWideString& text) {
    CWriter writer(out, EAENC_DER);

    if (writer.writeString(EAUTAG_STRING_P, text)) {
        return;
    }

    if (!writer.writeString(EAUTAG_STRING_UTF8, text)) {
        return;
    }
}

// === CWriter ===
// Writes a few typed elements, then a SEQUENCE and a SET built from children that are already
// complete tag-length-values -- writeSequence()/writeSet() wrap, they do not encode. writeSet()
// also reorders its argument in place into DER's canonical order, so that array is not left as-is.
void exampleCWriter(const IStreamPtr& out, SReadOnlyByteSpan firstChild, SReadOnlyByteSpan secondChild) {
    CWriter writer(out, EAENC_DER);

    if (!writer.writeInteger(1) || !writer.writeNull()) {
        return;
    }

    SReadOnlyByteSpan children[] = { firstChild, secondChild };
    if (!writer.writeSequence(TReadOnlySpan<SReadOnlyByteSpan>(children, 2))) {
        return;
    }

    if (!writer.writeSet(TSpan<SReadOnlyByteSpan>(children, 2))) {
        return;
    }
}
