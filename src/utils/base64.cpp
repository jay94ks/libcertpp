#include <certpp/utils/base64.hpp>
#include <cstring>

namespace certpp {

    /* Appends in's bytes to the end of _buffer, growing it. */
    void CBase64::appendToBuffer(const SReadOnlyByteSpan& in) {
        if (in.empty()) {
            return;
        }

        size_t oldSize = _buffer.size();
        _buffer.resize(oldSize + in.size);
        std::memcpy(_buffer.toPtr() + oldSize, in.data, in.size);
    }

    /* Removes the first consumed bytes from the front of _buffer, keeping whatever's left. */
    void CBase64::consumeFromBuffer(size_t consumed) {
        size_t remain = _buffer.size() - consumed;
        if (remain > 0 && consumed > 0) {
            std::memmove(_buffer.toPtr(), _buffer.toPtr() + consumed, remain);
        }
        _buffer.resize(remain);
    }

    /* Encodes as many complete 3-byte groups as _buffer holds, bounded by out's capacity. */
    size_t CBase64::encodeGroups(const SByteSpan& out) {
        size_t groups = _buffer.size() / 3;
        uint8_t* buf = _buffer.toPtr();
        size_t written = 0;
        size_t consumed = 0;

        for (size_t g = 0; g < groups; ++g) {
            uint32_t triple = (static_cast<uint32_t>(buf[consumed]) << 16)
                | (static_cast<uint32_t>(buf[consumed + 1]) << 8)
                | static_cast<uint32_t>(buf[consumed + 2]);

            out.data[written + 0] = BASE64_CHARS[(triple >> 18) & 0x3F];
            out.data[written + 1] = BASE64_CHARS[(triple >> 12) & 0x3F];
            out.data[written + 2] = BASE64_CHARS[(triple >> 6) & 0x3F];
            out.data[written + 3] = BASE64_CHARS[triple & 0x3F];
            written += 4;
            consumed += 3;

            if (_mode == EB64M_ENCODE_BR) {
                _lineCol += 4;
                if (_lineCol >= LINE_LENGTH) {
                    out.data[written] = '\n';
                    written += 1;
                    _lineCol = 0;
                }
            }
        }

        consumeFromBuffer(consumed);
        return written;
    }

    /* Decodes as many complete 4-code groups as _buffer holds, bounded by out's capacity. */
    size_t CBase64::decodeGroups(const SByteSpan& out) {
        size_t groups = _buffer.size() / 4;
        uint8_t* buf = _buffer.toPtr();
        size_t written = 0;
        size_t consumed = 0;

        for (size_t g = 0; g < groups; ++g) {
            uint32_t quad = (static_cast<uint32_t>(buf[consumed]) << 18)
                | (static_cast<uint32_t>(buf[consumed + 1]) << 12)
                | (static_cast<uint32_t>(buf[consumed + 2]) << 6)
                | static_cast<uint32_t>(buf[consumed + 3]);

            out.data[written + 0] = static_cast<uint8_t>((quad >> 16) & 0xFF);
            out.data[written + 1] = static_cast<uint8_t>((quad >> 8) & 0xFF);
            out.data[written + 2] = static_cast<uint8_t>(quad & 0xFF);
            written += 3;
            consumed += 4;
        }

        consumeFromBuffer(consumed);
        return written;
    }

    /* Pushes more data through the encoder: converts and writes every complete 3-byte group in's
     * bytes (combined with any previously buffered leftover) now form, leaving an incomplete tail
     * (< 3 bytes) buffered for a later push()/finish() call. Requires out to be large enough for
     * everything this call would produce -- ERET_NOSPC (recoverable, see _state's own doc
     * comment) rather than a partial write otherwise, so a retry with a bigger out never
     * double-converts anything. Processes in in <= MAX_BUFFER-sized chunks (see _buffer's own
     * doc comment) rather than ever appending all of a large in to _buffer at once, so this
     * class's memory usage never scales with a single call's input size. */
    size_t CBase64::pushEncode(const SReadOnlyByteSpan& in, const SByteSpan& out) {
        size_t groups = (_buffer.size() + in.size) / 3;
        size_t requiredOut = groups * 4;

        if (_mode == EB64M_ENCODE_BR && groups > 0) {
            size_t col = _lineCol;
            size_t remaining = groups;
            while (remaining > 0) {
                col += 4;
                --remaining;
                if (col >= LINE_LENGTH) {
                    ++requiredOut;
                    col = 0;
                }
            }
        }

        if (out.size < requiredOut) {
            _state = ERET_NOSPC;
            return 0;
        }

        size_t written = 0;
        size_t inOffset = 0;
        while (inOffset < in.size) {
            size_t room = MAX_BUFFER - _buffer.size();
            size_t chunk = (in.size - inOffset < room) ? (in.size - inOffset) : room;

            appendToBuffer(in.slice(inOffset, chunk));
            inOffset += chunk;

            SByteSpan outRemaining(out.data + written, out.size - written);
            written += encodeGroups(outRemaining);
        }

        return written;
    }

    /* Pushes more data through the decoder: whitespace and '=' padding are silently skipped (this
     * decoder is lenient about padding -- finish() infers the correct final-group shape purely
     * from how many real characters are left over once streaming ends, so the literal '='
     * characters carry no information this class actually needs); any other out-of-alphabet byte
     * is a genuine decode error. Like pushEncode(), requires out to be large enough for this
     * call's output up front, so a retry after ERET_NOSPC never double-converts anything, and
     * commits in's decoded codes into _buffer in <= MAX_BUFFER-sized batches rather than all at
     * once. */
    size_t CBase64::pushDecode(const SReadOnlyByteSpan& in, const SByteSpan& out) {
        size_t validCount = 0;
        for (size_t i = 0; i < in.size; ++i) {
            uint8_t c = in.data[i];
            if (isSkippable(c)) {
                continue;
            }
            if (decodeChar(c) == INVALID_B64) {
                _state = ERET_INVAL;
                return 0;
            }
            ++validCount;
        }

        size_t groups = (_buffer.size() + validCount) / 4;
        size_t requiredOut = groups * 3;
        if (out.size < requiredOut) {
            _state = ERET_NOSPC;
            return 0;
        }

        size_t written = 0;
        size_t i = 0;
        while (i < in.size) {
            size_t room = MAX_BUFFER - _buffer.size();
            size_t oldSize = _buffer.size();
            _buffer.resize(oldSize + room);

            size_t filled = 0;
            while (i < in.size && filled < room) {
                uint8_t c = in.data[i++];
                if (isSkippable(c)) {
                    continue;
                }
                _buffer[oldSize + filled] = decodeChar(c); // already validated above.
                ++filled;
            }

            if (filled < room) {
                _buffer.resize(oldSize + filled);
            }

            SByteSpan outRemaining(out.data + written, out.size - written);
            written += decodeGroups(outRemaining);
        }

        return written;
    }

    /* Pushes more data through the Base64 encoder/decoder (see EBase64Mode); resets state() to
     * reflect only this call's own outcome first (see _state's own doc comment). */
    size_t CBase64::push(const SReadOnlyByteSpan& in, const SByteSpan& out) {
        _state = ERET_OK;

        if (_finished) {
            // finish() has already begun draining -- _buffer now holds pending OUTPUT bytes, not
            // raw input, so feeding it more input here would silently corrupt that output. Call
            // reset() to start a fresh encode/decode session instead.
            _state = ERET_INVAL;
            return 0;
        }

        if (_mode == EB64M_DECODE) {
            return pushDecode(in, out);
        }

        return pushEncode(in, out);
    }

    /* Finishes encoding/decoding: the first call converts whatever's left (the final, possibly
     * partial group -- padded for encode, inferred purely from the leftover count for decode)
     * into _buffer, then every call (including this first one) drains as much of _buffer as fits
     * in out, narrowing out to the bytes actually written -- see _finished's own doc comment on
     * why this lets finish() be called repeatedly with an arbitrarily small out. */
    size_t CBase64::finish(SByteSpan& out) {
        _state = ERET_OK;

        if (!_finished) {
            uint8_t tail[5];
            size_t tailLen = 0;

            if (_mode == EB64M_DECODE) {
                size_t remain = _buffer.size();
                if (remain == 1) {
                    // A lone leftover 6-bit code can never decode to a full byte.
                    _state = ERET_INVAL;
                    out = SByteSpan(out.data, 0);
                    return 0;
                }

                if (remain >= 2) {
                    const uint8_t* buf = _buffer.toPtr();
                    uint32_t quad = (static_cast<uint32_t>(buf[0]) << 18)
                        | (static_cast<uint32_t>(buf[1]) << 12)
                        | (static_cast<uint32_t>(remain == 3 ? buf[2] : 0) << 6);

                    tail[tailLen++] = static_cast<uint8_t>((quad >> 16) & 0xFF);
                    if (remain == 3) {
                        tail[tailLen++] = static_cast<uint8_t>((quad >> 8) & 0xFF);
                    }
                }
            } else {
                size_t remain = _buffer.size();
                if (remain > 0) {
                    const uint8_t* buf = _buffer.toPtr();
                    uint32_t triple = static_cast<uint32_t>(buf[0]) << 16;
                    if (remain == 2) {
                        triple |= static_cast<uint32_t>(buf[1]) << 8;
                    }

                    tail[tailLen++] = BASE64_CHARS[(triple >> 18) & 0x3F];
                    tail[tailLen++] = BASE64_CHARS[(triple >> 12) & 0x3F];
                    tail[tailLen++] = (remain == 2) ? BASE64_CHARS[(triple >> 6) & 0x3F] : '=';
                    tail[tailLen++] = '=';

                    if (_mode == EB64M_ENCODE_BR) {
                        _lineCol += 4;
                    }
                }

                if (_mode == EB64M_ENCODE_BR && _lineCol > 0) {
                    tail[tailLen++] = '\n';
                    _lineCol = 0;
                }
            }

            _buffer.store(tail, tailLen);
            _finished = true;
        }

        size_t remain = _buffer.size();
        size_t toWrite = (remain < out.size) ? remain : out.size;

        if (toWrite > 0) {
            std::memcpy(out.data, _buffer.toPtr(), toWrite);
            consumeFromBuffer(toWrite);
        }

        out = SByteSpan(out.data, toWrite);
        return toWrite;
    }

    /* Encodes the input data and writes it to the specified output string: a one-shot convenience
     * wrapper over push()/finish(), for a caller that has the whole input in memory already and
     * doesn't need the streaming interface. out is sized to a safe upper bound up front (a plain
     * ceiling-division estimate, not pushEncode()'s own exact line-break simulation -- there's no
     * need to duplicate that here, since this is a one-time allocation immediately shrunk back
     * down to the real result afterward), then shrunk down to the exact result. */
    bool CBase64::encode(CString& out, const SReadOnlyByteSpan& in, bool breakLines) {
        size_t groups = (in.size + 2) / 3; // ceiling division -- includes a padded final group.
        size_t bound = groups * 4;
        if (breakLines) {
            bound += groups + 1; // generous over-estimate: at most one newline per group, plus a
                                  // final closing one -- the real rate is one per 16 groups.
        }

        if (!out.resize(bound)) {
            return false;
        }

        CBase64 encoder(breakLines ? EB64M_ENCODE_BR : EB64M_ENCODE);
        SByteSpan outSpan(reinterpret_cast<uint8_t*>(out.toPtr()), bound);

        size_t written = encoder.push(in, outSpan);
        if (encoder.state() == ERET_OK) {
            SByteSpan tail(reinterpret_cast<uint8_t*>(out.toPtr()) + written, bound - written);
            written += encoder.finish(tail);
        }

        if (encoder.state() != ERET_OK) {
            out.clear();
            return false;
        }

        out.resize(written);
        return true;
    }

    /* Decodes the input data and writes it to the specified output buffer: encode()'s decode-mode
     * counterpart. out is sized to a safe upper bound up front (in's whole length can only ever
     * over-estimate the real output size, since whitespace/'=' padding contribute no output
     * bytes), then shrunk down to the exact result. */
    bool CBase64::decode(CBuffer& out, const CString& in) {
        size_t bound = (in.size() * 3) / 4 + 3;

        if (!out.resize(bound)) {
            return false;
        }

        CBase64 decoder(EB64M_DECODE);
        SByteSpan outSpan(out.toPtr(), bound);
        SReadOnlyByteSpan inSpan(reinterpret_cast<const uint8_t*>(in.toPtr()), in.size());

        size_t written = decoder.push(inSpan, outSpan);
        if (decoder.state() == ERET_OK) {
            SByteSpan tail(out.toPtr() + written, bound - written);
            written += decoder.finish(tail);
        }

        if (decoder.state() != ERET_OK) {
            out.clear();
            return false;
        }

        out.resize(written);
        return true;
    }
} // namespace certpp
