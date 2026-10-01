#ifndef __INCLUDE_CERTPP_UTILS_BASE64_HPP__
#define __INCLUDE_CERTPP_UTILS_BASE64_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/stream.hpp>
#include <certpp/io/buffer.hpp>

namespace certpp {

    /**
     * @brief Modes for Base64 encoding and decoding.
     */
    enum EBase64Mode {
        EB64M_ENCODE = 0,   /*< Base64 encoding without line breaks */
        EB64M_ENCODE_BR,    /*< Base64 encoding with line breaks */
        EB64M_DECODE,       /*< Base64 decoding */
    };

    /**
     * @brief A utility class for Base64 encoding and decoding.
     */
    class CERTPP_API CBase64 {
    private:
        /**
         * @brief The set of characters used in Base64 encoding.
         */
        static constexpr char BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        /* PEM canonical line length (RFC 7468) -- the wrap width EB64M_ENCODE_BR inserts a '\n'
         * at (this class never emits '\r'). */
        static constexpr size_t LINE_LENGTH = 64;

        /* Sentinel decodeChar() returns for a byte outside the Base64 alphabet. */
        static constexpr uint8_t INVALID_B64 = 0xFF;

        /* Hard ceiling on _buffer's size at any point in time: push() processes a large in in
         * internal chunks bounded by this instead of ever growing _buffer past it, so this
         * class's own working-set memory usage never scales with a single push() call's input
         * size. */
        static constexpr size_t MAX_BUFFER = 2048;

    private:
        EBase64Mode _mode;

        /**
         * Result of the most recently completed push()/finish() call, not a sticky/latched
         * error -- a recoverable outcome (e.g. ERET_NOSPC because the caller's out span was too
         * small) never blocks a later call, so simply retrying with a bigger out span works
         * without needing reset().
         */
        ERetCode _state;

        /**
         * Stores remaining data that has not yet been processed during Base64 encoding or decoding.
         * And, this buffer must be handled correctly for each `push` and `finish` operation.
         */
        CBuffer _buffer;

        /* Running output column (number of Base64 characters emitted on the current line),
         * tracked only in EB64M_ENCODE_BR mode so a line break can be inserted at the right place
         * even when it falls across two separate push() calls. */
        size_t _lineCol;

        /* Whether finish() has already converted the final (possibly partial) group into
         * _buffer -- once true, _buffer holds plain pending output bytes awaiting delivery rather
         * than not-yet-converted input, so a later finish() call (see its own doc comment on
         * calling it repeatedly) just drains it instead of re-converting. */
        bool _finished;

    public:
        /**
         * @brief Constructs a CBase64 object with the specified mode.
         * @param mode The mode for Base64 encoding or decoding.
         */
        CBase64(EBase64Mode mode) {
            _mode = mode;
            _state = ERET_OK;
            _buffer.clear();
            _lineCol = 0;
            _finished = false;
        }

        ~CBase64() { reset(); }

        // --
        CBase64(const CBase64&) = delete;
        CBase64(CBase64&&) = delete;
        CBase64& operator=(const CBase64&) = delete;
        CBase64& operator=(CBase64&&) = delete;

    private:
        /* Maps an ASCII byte to its 6-bit Base64 value, or INVALID_B64 for a byte outside the
         * alphabet (whitespace/'=' are handled by isSkippable(), not here). */
        static inline uint8_t decodeChar(uint8_t c) {
            if (c >= 'A' && c <= 'Z') {
                return static_cast<uint8_t>(c - 'A');
            }
            if (c >= 'a' && c <= 'z') {
                return static_cast<uint8_t>(c - 'a' + 26);
            }
            if (c >= '0' && c <= '9') {
                return static_cast<uint8_t>(c - '0' + 52);
            }
            if (c == '+') {
                return 62;
            }
            if (c == '/') {
                return 63;
            }

            return INVALID_B64;
        }

        /* Whitespace this decoder silently skips, the same way it skips '=' padding -- neither
         * carries information this class needs (see pushDecode()'s own comment on why '=' is
         * treated the same as whitespace rather than specially parsed). */
        static inline bool isSkippable(uint8_t c)  {
            return c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t';
        }

        /* Appends in's bytes to the end of _buffer, growing it. A no-op for an empty in. */
        void appendToBuffer(const SReadOnlyByteSpan& in);

        /* Removes the first consumed bytes from the front of _buffer, keeping whatever's left. */
        void consumeFromBuffer(size_t consumed);

        /* Encodes as many complete 3-byte groups as _buffer (already containing this call's
         * appended input) holds, bounded by out's capacity -- see pushEncode()/finish()'s own
         * comments for the required-size checks each caller performs before calling this. */
        size_t encodeGroups(const SByteSpan& out);

        /* Decodes as many complete 4-code groups as _buffer holds, bounded by out's capacity --
         * encodeGroups()'s decode-mode counterpart. */
        size_t decodeGroups(const SByteSpan& out);

        /* push()'s EB64M_ENCODE/EB64M_ENCODE_BR implementation. */
        size_t pushEncode(const SReadOnlyByteSpan& in, const SByteSpan& out);

        /* push()'s EB64M_DECODE implementation. */
        size_t pushDecode(const SReadOnlyByteSpan& in, const SByteSpan& out);
        
    public:
        /**
         * @brief Resets the Base64 encoder or decoder to its initial state and sets the mode.
         * @param mode The mode for Base64 encoding or decoding.
         */
        inline void reset(EBase64Mode mode) {
            _mode = mode;
            _state = ERET_OK;
            _buffer.clear();
            _lineCol = 0;
            _finished = false;
        }

        /**
         * @brief Resets the Base64 encoder or decoder to its initial state.
         */
        inline void reset() {
            reset(_mode);
        }

        /**
         * @brief Gets the current mode of the Base64 encoder or decoder.
         * @return The current Base64 mode.
         */
        inline EBase64Mode mode() const {
            return _mode;
        }

        /**
         * @brief Gets the current state of the Base64 encoder or decoder.
         * @return The current result code.
         */
        inline ERetCode state() const {
            return _state;
        }

        /**
         * @brief Pushes data into the Base64 encoder or decoder.
         * @param in The input data span.
         * @param out The output data span.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& in, const SByteSpan& out);

        /**
         * @brief Finishes the Base64 encoding or decoding process.
         * @param out The output data span.
         * @return The number of bytes processed.
         * @note Call this repeatedly when this did not return zero.
         */
        size_t finish(SByteSpan& out);

    public:
        /**
         * @brief Encodes the input data and writes it to the specified output string.
         * @param in The input data span.
         * @param out The output string.
         * @param breakLines Whether to insert line breaks in the output.
         * @return True if the encoding was successful, false otherwise.
         */
        static bool encode(CString& out, const SReadOnlyByteSpan& in, bool breakLines = false);

        /**
         * @brief Decodes the input data and writes it to the specified output buffer.
         * @param out The output buffer.
         * @param in The input string.
         * @return True if the decoding was successful, false otherwise.
         */
        static bool decode(CBuffer& out, const CString& in);
    };
}

#endif