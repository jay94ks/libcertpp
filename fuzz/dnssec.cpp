#include <certpp.hpp>
#include <cstddef>
#include <cstdint>

using namespace certpp;
using namespace certpp::dnssec;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!data || size < 1 || size > 1024 * 1024) {
        return 0;
    }

    SReadOnlyByteSpan input(data + 1, size - 1);
    switch (data[0] % 4) {
    case 0: {
        CString name;
        CDnsName::fromWire(input, name);
        break;
    }
    case 1: {
        SDnskey key;
        key.fromRdata(input);
        break;
    }
    case 2: {
        SDsRecord record;
        record.fromRdata(input);
        break;
    }
    default: {
        SRrsig signature;
        signature.fromRdata(input);
        break;
    }
    }
    return 0;
}
