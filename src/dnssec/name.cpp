#include <certpp/dnssec/name.hpp>
#include <cstring>

namespace certpp {
namespace dnssec {

    namespace {

        /* ASCII-only case folding, which is exactly what RFC 4034 6.2 asks for: it folds
         * "uppercase US-ASCII letters" and says nothing about any other octet. Using the locale's
         * tolower() here would be wrong, since a locale may map bytes above 0x7F. */
        inline uint8_t foldAscii(uint8_t ch) {
            return (ch >= 'A' && ch <= 'Z') ? uint8_t(ch + ('a' - 'A')) : ch;
        }

        /* Walks a wire-format name, reporting where it ends. Shared by everything below, since a
         * malformed name has to be rejected the same way whichever operation hit it. */
        bool walk(const SReadOnlyByteSpan& wire, size_t& labelCount, size_t& consumed) {
            if (!wire.data) {
                return false;
            }

            size_t offset = 0;
            size_t labels = 0;

            for (;;) {
                if (offset >= wire.size) {
                    return false;                       // ran out before the root label
                }

                const uint8_t length = wire.data[offset];

                // A length octet with its top two bits set is a compression pointer, which
                // DNSSEC does not allow in signed names and which cannot be resolved from the
                // name alone. Anything else above 63 is simply invalid.
                if (length > CDnsName::MAX_LABEL_BYTES) {
                    return false;
                }

                ++offset;

                if (length == 0) {
                    break;                              // root label: the name ends here
                }

                if (wire.size - offset < length) {
                    return false;
                }

                offset += length;
                ++labels;

                if (offset > CDnsName::MAX_WIRE_BYTES) {
                    return false;
                }
            }

            if (offset > CDnsName::MAX_WIRE_BYTES) {
                return false;
            }

            labelCount = labels;
            consumed = offset;
            return true;
        }

    }

    /* Encodes a presentation-format name into canonical wire format. */
    bool CDnsName::toWire(const CString& name, TArray<uint8_t>& out) {
        out.clear();

        const char* text = name.toPtr();
        const size_t length = name.size();

        // "." and "" are both the root, and both encode to the single zero octet.
        if (!text || length == 0 || (length == 1 && text[0] == '.')) {
            return out.add(uint8_t(0));
        }

        // A single trailing dot is the usual fully-qualified spelling and carries no label.
        size_t end = length;
        if (text[end - 1] == '.') {
            --end;
        }

        size_t cursor = 0;
        size_t total = 1;                               // the root label is always written

        while (cursor < end) {
            size_t labelEnd = cursor;
            while (labelEnd < end && text[labelEnd] != '.') {
                ++labelEnd;
            }

            const size_t labelLength = labelEnd - cursor;

            // An empty label means a doubled dot or a leading dot; neither is a name.
            if (labelLength == 0 || labelLength > MAX_LABEL_BYTES) {
                out.clear();
                return false;
            }

            total += 1 + labelLength;
            if (total > MAX_WIRE_BYTES) {
                out.clear();
                return false;
            }

            if (!out.add(uint8_t(labelLength))) {
                out.clear();
                return false;
            }

            for (size_t i = 0; i < labelLength; ++i) {
                if (!out.add(foldAscii(uint8_t(text[cursor + i])))) {
                    out.clear();
                    return false;
                }
            }

            cursor = labelEnd + 1;                      // step past the dot
        }

        if (!out.add(uint8_t(0))) {
            out.clear();
            return false;
        }

        return true;
    }

    /* Decodes a wire-format name into presentation format. */
    bool CDnsName::fromWire(const SReadOnlyByteSpan& wire, CString& out) {
        size_t consumed = 0;
        if (!fromWirePrefix(wire, out, consumed)) {
            return false;
        }

        // Unlike fromWirePrefix(), this entry point is handed a span that should hold nothing
        // but the name, so anything left over means the caller's framing is wrong.
        if (consumed != wire.size) {
            out = CString();
            return false;
        }

        return true;
    }

    /* Decodes a wire-format name that is followed by further data. */
    bool CDnsName::fromWirePrefix(
        const SReadOnlyByteSpan& wire, CString& out, size_t& consumed
    ) {
        out = CString();

        size_t labelCount = 0;
        size_t used = 0;
        if (!walk(wire, labelCount, used)) {
            return false;
        }

        // The root name prints as a bare dot rather than as the empty string, so that the result
        // is always a fully-qualified name that round-trips back through toWire().
        if (labelCount == 0) {
            out.append('.');
            consumed = used;
            return true;
        }

        size_t offset = 0;
        for (;;) {
            const uint8_t length = wire.data[offset];
            ++offset;

            if (length == 0) {
                break;
            }

            out.append(reinterpret_cast<const char*>(wire.data + offset), length);
            out.append('.');
            offset += length;
        }

        consumed = used;
        return true;
    }

    /* Counts the labels in a wire-format name, excluding the root. */
    bool CDnsName::countLabels(const SReadOnlyByteSpan& wire, size_t& out) {
        size_t labelCount = 0;
        size_t consumed = 0;
        if (!walk(wire, labelCount, consumed)) {
            return false;
        }

        out = labelCount;
        return true;
    }

    /* Reports whether a wire-format name holds no ASCII uppercase. */
    bool CDnsName::isCanonical(const SReadOnlyByteSpan& wire) {
        size_t labelCount = 0;
        size_t consumed = 0;
        if (!walk(wire, labelCount, consumed)) {
            return false;
        }

        size_t offset = 0;
        for (;;) {
            const uint8_t length = wire.data[offset];
            ++offset;

            if (length == 0) {
                break;
            }

            for (size_t i = 0; i < length; ++i) {
                const uint8_t ch = wire.data[offset + i];
                if (ch >= 'A' && ch <= 'Z') {
                    return false;
                }
            }

            offset += length;
        }

        return true;
    }

} // namespace dnssec
} // namespace certpp
