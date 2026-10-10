#include <certpp/asn1/reader.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/buffer.hpp>
#include <cstring>

namespace certpp {
namespace asn1 {

    CReader::CReader()
        : _stream(), _ruleSet(EAENC_DER), _buffer(), _cursor(), _generation(0)
    {
    }

    CReader::CReader(SReadOnlyByteSpan content, EEncodingRule ruleSet)
        : _stream(), _ruleSet(ruleSet), _buffer(), _cursor(content), _generation(0)
    {
    }

    CReader::CReader(const IStreamPtr& stream, EEncodingRule ruleSet)
        : _stream(stream), _ruleSet(ruleSet), _buffer(), _cursor(), _generation(0)
    {
    }

    /* Pulls one more chunk from _stream, rebuilding _buffer from the cursor's unconsumed bytes
     * plus the newly-read chunk. */
    bool CReader::growBuffer() {
        if (!_stream) {
            return false;
        }

        uint8_t chunk[4096];
        size_t n = _stream->read(chunk, sizeof(chunk));
        if (!n) {
            return false;
        }

        CBuffer combined(_cursor.size + n);
        uint8_t* combinedPtr = combined.toPtr();
        std::memcpy(combinedPtr, _cursor.data, _cursor.size);
        std::memcpy(combinedPtr + _cursor.size, chunk, n);

        if (!_buffer.store(combined.toPtr(), combined.size())) {
            return false;
        }

        _cursor = _buffer.toSpan();
        ++_generation;
        return true;
    }

    /* Reads the next encoded ASN.1 value, growing the buffer from the stream as needed. */
    bool CReader::readNextElement(CTag& outTag, SReadOnlyByteSpan& outArea) {
        return withRollback([&]() {
            while (true) {
                if (CDecoder::readNextElement(_cursor, _ruleSet, outTag, outArea)) {
                    return true;
                }

                if (!growBuffer()) {
                    return false;
                }
            }
        });
    }

    /* Reads the next element expecting a constructed value, returning a nested reader over its content. */
    bool CReader::readConstructed(CTag& outTag, CReader& outReader) {
        return withRollback([&]() {
            CTag tag;
            SReadOnlyByteSpan content;
            if (!readNextElement(tag, content) || !tag.isConstructed()) {
                return false;
            }

            outTag = tag;
            outReader = CReader(content, _ruleSet);
            return true;
        });
    }

    /* Reads the next element expecting a SEQUENCE, returning a nested reader over its content. */
    bool CReader::readSequence(CReader& outReader) {
        return withRollback([&]() {
            CTag tag;
            SReadOnlyByteSpan content;
            if (!readNextElement(tag, content) || tag != CTag::SEQ) {
                return false;
            }

            outReader = CReader(content, _ruleSet);
            return true;
        });
    }

    /* Reads the next element expecting a SET, returning a nested reader over its content. */
    bool CReader::readSet(CReader& outReader) {
        return withRollback([&]() {
            CTag tag;
            SReadOnlyByteSpan content;
            if (!readNextElement(tag, content) || tag != CTag::SET_OF) {
                return false;
            }

            outReader = CReader(content, _ruleSet);
            return true;
        });
    }

    /* Reads the next element expecting a BOOLEAN. */
    bool CReader::readBoolean(bool& outValue) {
        return tryReadPrimitive(CTag::BOOLEAN, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeBoolean(content, _ruleSet, outValue);
        });
    }

    /* Reads the next element expecting an INTEGER. */
    bool CReader::readInteger(int64_t& outValue) {
        return tryReadPrimitive(CTag::INTEGER, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeInteger(content, outValue);
        });
    }

    /* Reads the next element expecting an ENUMERATED. */
    bool CReader::readEnumerated(uint32_t& outValue) {
        return tryReadPrimitive(CTag::ENUMERATED, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeEnumerated(content, outValue);
        });
    }

    /* Reads the next element expecting a NULL. */
    bool CReader::readNull() {
        return tryReadPrimitive(CTag::NULL_, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeNull(content);
        });
    }

    /* Reads the next element expecting an OCTET STRING. */
    bool CReader::readOctetString(SReadOnlyByteSpan& outValue) {
        return tryReadPrimitive(CTag::STRING_OCTET, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeOctetString(content, outValue);
        });
    }

    /* Reads the next element expecting an OCTET STRING into an owning COctet. */
    bool CReader::readOctetString(COctet& outValue) {
        return tryReadPrimitive(CTag::STRING_OCTET, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeOctetString(content, outValue);
        });
    }

    /* Reads the next element expecting a BIT STRING. */
    bool CReader::readBitString(SReadOnlyByteSpan& outBits, uint8_t& outUnusedBits) {
        return tryReadPrimitive(CTag::STRING_BIT, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeBitString(content, outBits, outUnusedBits);
        });
    }

    /* Reads the next element expecting a BIT STRING into an owning COctet. */
    bool CReader::readBitString(COctet& outBits, uint8_t& outUnusedBits) {
        return tryReadPrimitive(CTag::STRING_BIT, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeBitString(content, outBits, outUnusedBits);
        });
    }

    /* Reads the next element expecting an OBJECT IDENTIFIER. */
    bool CReader::readOid(TSpan<uint32_t> outArcs, size_t& outArcCount) {
        return tryReadPrimitive(CTag::OBJ_ID, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeOid(content, outArcs, outArcCount);
        });
    }

    /* Reads the next element expecting an OBJECT IDENTIFIER, into an SRawOid. */
    bool CReader::readOid(SRawOid& outOid) {
        return tryReadPrimitive(CTag::OBJ_ID, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeOid(content, outOid);
        });
    }

    /* Reads the next element expecting the given character string kind. */
    bool CReader::readText(EUniversalTags kind, SReadOnlyByteSpan& outText) {
        CTag expected(kind, false);
        if (!expected) {
            return false;
        }

        return tryReadPrimitive(expected, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeText(content, kind, outText);
        });
    }

    /* Reads the next element expecting a UTCTime. */
    bool CReader::readUtcTime(SDateTime& outTime) {
        return tryReadPrimitive(CTag::TIME_UTC_, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeUtcTime(content, outTime);
        });
    }

    /* Reads the next element expecting a GeneralizedTime. */
    bool CReader::readGeneralizedTime(SDateTime& outTime) {
        return tryReadPrimitive(CTag::TIME_GENERAL, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeGeneralizedTime(content, outTime);
        });
    }

    /* Reads the next element expecting a CDistinguishedName. */
    bool CReader::readDistinguishedName(CDistinguishedName& outValue) {
        return tryReadPrimitive(CTag::SEQ, [&](SReadOnlyByteSpan content) {
            return CDecoder::decodeDistinguishedName(content, outValue);
        });
    }

} // namespace asn1
} // namespace certpp
