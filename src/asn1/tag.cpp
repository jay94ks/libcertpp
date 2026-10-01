#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace asn1 {

    /* Tries to decode an ASN.1 tag from the given source span. */
    CTag CTag::decode(TReadOnlySpan<uint8_t> source, size_t& bytesRead) {
        bytesRead = 0;
        
        if (source.empty()) {
            return CTag();
        }

        uint8_t first = source.data[0];
        bytesRead++;

        uint32_t tag = first & MASK_TAG;
        if (tag == CTag::MASK_TAG) {
            tag = 0;

            uint8_t cur;
            do {
                if (source.size <= bytesRead) {
                    bytesRead = 0;
                    return CTag();
                }

                cur = source.data[bytesRead];
                bytesRead++;
                
                if (tag >= (1 << 25)) {
                    bytesRead = 0;
                    return CTag();
                }

                uint8_t curVal = cur & MASK_VALUE;
                if ((tag = (tag << 7) | curVal) == 0) {
                    bytesRead = 0;
                    return CTag();
                }
            }

            while ((cur & FLAG_CONTINUE) != 0);

            if (tag <= 30) {
                bytesRead = 0;
                return CTag();
            }

            if (tag > INT32_MAX) {
                bytesRead = 0;
                return CTag();
            }
        }

        return CTag(first, tag);
    }

    /**
     * Encodes the ASN.1 tag into the given destination span.
     *
     * @param destination The destination span to write the encoded ASN.1 tag.
     * @param bytesWritten The number of bytes written to the destination span.
     * @return True if the encoding was successful, false otherwise.
     */
    bool CTag::encode(TSpan<uint8_t> destination, size_t& bytesWritten) const {
        bytesWritten = 0;

        size_t requiredSize = encodedSize();
        if (requiredSize == 0 || destination.size < requiredSize) {
            return false;
        }

        if (requiredSize == 1) {
            const uint8_t val
                = static_cast<uint8_t>(_flags & MASK_CTL)
                | (_value & MASK_TAG);

            destination.data[0] = val;
            bytesWritten = 1;
            return true;
        }

        uint8_t first = static_cast<uint8_t>(_flags & MASK_CTL) | MASK_TAG;
        destination.data[0] = first;

        uint32_t remaining = _value;
        uint32_t index = requiredSize - 1;

        while (remaining > 0) {
            uint32_t segment = remaining & MASK_VALUE;

            if (remaining != _value) {
                segment |= FLAG_CONTINUE;
            }
            
            destination.data[index] = static_cast<uint8_t>(segment);
            remaining >>= 7;
            index--;
        }

        bytesWritten = requiredSize;
        return true;
    }

}
}