#include <certpp/asn1/der.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <cstring>

namespace certpp {
namespace asn1 {

    bool CDer::appendTlv(TArray<uint8_t>& out, const CTag& tag, SReadOnlyByteSpan content) {
        size_t need = CEncoder::encodedValueSize(tag, content);
        if (!need) {
            return false;
        }

        size_t oldSize = out.size();
        if (!out.resize(oldSize + need)) {
            return false;
        }

        TSpan<uint8_t> dest(out.begin() + oldSize, need);

        size_t written = 0;
        if (!CEncoder::writeEncodedValue(dest, EAENC_DER, tag, content, written) || written != need) {
            out.resize(oldSize);
            return false;
        }

        return true;
    }

    bool CDer::appendTlv(CBuffer& out, const CTag& tag, SReadOnlyByteSpan content) {
        size_t need = CEncoder::encodedValueSize(tag, content);
        if (!need) {
            return false;
        }

        size_t oldSize = out.size();
        if (!out.resize(oldSize + need)) {
            return false;
        }

        TSpan<uint8_t> dest(out.toPtr() + oldSize, need);

        size_t written = 0;
        if (!CEncoder::writeEncodedValue(dest, EAENC_DER, tag, content, written) || written != need) {
            out.resize(oldSize);
            return false;
        }

        return true;
    }

    bool CDer::appendBigInteger(TArray<uint8_t>& out, const CBigNum& value) {
        TArray<uint8_t> magnitude;
        value.toBigEndian(magnitude);

        bool needsPad = (magnitude[0] & 0x80) != 0;

        CBuffer content(magnitude.size() + (needsPad ? 1 : 0));
        uint8_t* contentPtr = content.toPtr();

        size_t offset = 0;
        if (needsPad) {
            contentPtr[0] = 0;
            offset = 1;
        }

        std::memcpy(contentPtr + offset, magnitude.begin(), magnitude.size());

        return appendTlv(out, CTag::INTEGER, content.toSpan());
    }

    bool CDer::appendSequence(TArray<uint8_t>& out, SReadOnlyByteSpan innerContent) {
        return appendTlv(out, CTag::SEQ, innerContent);
    }

    bool CDer::appendBigInteger(CBuffer& out, const CBigNum& value) {
        TArray<uint8_t> magnitude;
        value.toBigEndian(magnitude);

        bool needsPad = (magnitude[0] & 0x80) != 0;

        CBuffer content(magnitude.size() + (needsPad ? 1 : 0));
        uint8_t* contentPtr = content.toPtr();

        size_t offset = 0;
        if (needsPad) {
            contentPtr[0] = 0;
            offset = 1;
        }

        std::memcpy(contentPtr + offset, magnitude.begin(), magnitude.size());

        return appendTlv(out, CTag::INTEGER, content.toSpan());
    }

    bool CDer::appendSequence(CBuffer& out, SReadOnlyByteSpan innerContent) {
        return appendTlv(out, CTag::SEQ, innerContent);
    }

    bool CDer::appendRaw(CBuffer& out, SReadOnlyByteSpan bytes) {
        size_t oldSize = out.size();
        if (!out.resize(oldSize + bytes.size)) {
            return false;
        }

        if (bytes.size) {
            std::memcpy(out.toPtr() + oldSize, bytes.data, bytes.size);
        }

        return true;
    }

    bool CDer::readBigInteger(TReadOnlySpan<uint8_t>& cursor, CBigNum& out) {
        CTag tag;
        TReadOnlySpan<uint8_t> content;

        if (!CDecoder::readNextElement(cursor, EAENC_DER, tag, content)) {
            return false;
        }

        if (!tag.equals(CTag::INTEGER) || content.empty()) {
            return false;
        }

        if (content.data[0] & 0x80) {
            return false; // negative -- not a value this library's algorithms ever produce
        }

        SReadOnlyByteSpan magnitude = content;
        if (content.size > 1 && content.data[0] == 0x00) {
            magnitude = content.slice(1);
        }

        out = CBigNum::fromBigEndian(magnitude);
        return true;
    }

    bool CDer::readOuterSequence(SReadOnlyByteSpan der, TReadOnlySpan<uint8_t>& outContent) {
        CTag tag;
        TReadOnlySpan<uint8_t> content;
        size_t bytesRead = 0;

        if (!CDecoder::readEncodedValue(der, EAENC_DER, tag, content, bytesRead)) {
            return false;
        }

        if (!tag.equals(CTag::SEQ)) {
            return false;
        }

        outContent = content;
        return true;
    }

    size_t CDer::maxIntegerSize(size_t contentBytes) {
        size_t lenFieldSize = contentBytes < 128 ? 1 : (contentBytes < 256 ? 2 : 3);
        return 1 /* tag */ + lenFieldSize + contentBytes;
    }

    size_t CDer::maxSignatureSize(size_t orderByteLen) {
        size_t perInt = maxIntegerSize(orderByteLen + 1);
        size_t inner = 2 * perInt;
        size_t seqLenFieldSize = inner < 128 ? 1 : (inner < 256 ? 2 : 3);
        return 1 + seqLenFieldSize + inner;
    }

} // namespace asn1
} // namespace certpp
