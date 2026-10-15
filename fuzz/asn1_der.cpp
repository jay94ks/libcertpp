#include <certpp.hpp>
#include <cstddef>
#include <cstdint>

using namespace certpp;
using namespace certpp::asn1;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!data || size > 1024 * 1024) {
        return 0;
    }

    SReadOnlyByteSpan cursor(data, size);
    size_t elements = 0;
    while (!cursor.empty() && elements++ < 4096) {
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan before = cursor;
        if (!CDecoder::readNextElement(cursor, EAENC_DER, tag, content)) {
            break;
        }
        if (cursor.size >= before.size) {
            break;
        }
    }
    return 0;
}
