#include <certpp.hpp>
#include <cstddef>
#include <cstdint>

using namespace certpp;
using namespace certpp::x509;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!data || size < 1 || size > 1024 * 1024) {
        return 0;
    }

    const EChainFormats detected = IChainFormat::detect(SReadOnlyByteSpan(data, size));
    const EChainFormats selected = (data[0] & 1) ? ECHAINFMT_PEM : ECHAINFMT_PFX;
    IChainFormatPtr format = IChainFormat::builtIn(
        detected == ECHAINFMT_UNKNOWN ? selected : detected
    );
    if (format) {
        CCertCollection collection;
        const uint8_t password[] = { 'f', 'u', 'z', 'z' };
        format->load(
            SReadOnlyByteSpan(data + 1, size - 1),
            SReadOnlyByteSpan(password, sizeof(password)), collection
        );
    }
    return 0;
}
