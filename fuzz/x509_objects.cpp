#include <certpp.hpp>
#include <cstddef>
#include <cstdint>

using namespace certpp;
using namespace certpp::x509;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!data || size < 1 || size > 1024 * 1024) {
        return 0;
    }

    COctet input(data + 1, size - 1);
    switch (data[0] % 6) {
    case 0: {
        CCert value;
        value.importDer(input);
        break;
    }
    case 1: {
        CCertRequest value;
        value.importDer(input);
        break;
    }
    case 2: {
        CCrlReader value;
        value.decode(input);
        break;
    }
    case 3: {
        COcspRequest value;
        value.decode(input);
        break;
    }
    case 4: {
        COcspResponse value;
        value.decode(input);
        break;
    }
    default: {
        COcspCertId value;
        COcspCertId::decode(input, value);
        break;
    }
    }
    return 0;
}
