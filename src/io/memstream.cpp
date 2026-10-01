#include "memstream.hpp"

namespace certpp {

    MemStream::MemStream(SizeType initialCap)
        : _flags(0), _span(nullptr, 0), _pos(0), _cap(0)
    {
        _flags = FLAG_INIT;

        // --> Reserve the initial capacity if specified.
        if (initialCap) {
            reserve(initialCap);
        }
    }

    ERetCode MemStream::trimExcess() {
        if (_cap == _span.size) {
            return ERET_ALREADY;
        }

        if (!_span.size) {
            if (_span.data) {
                delete[] _span.data;
            }

            _span = SByteSpan(nullptr, 0);
            _cap = 0;
            _pos = 0;

            return ERET_OK;
        }
        
        uint8_t* p = new uint8_t[_span.size];
        if (!p) {
            return ERET_NOMEM;
        }

        std::memcpy(p, _span.data, _span.size);
        delete[] _span.data;

        _span.data = p;
        _cap = _span.size;

        if (_pos > _cap) {
            _pos = _cap;
        }

        return ERET_OK;
    }

    ERetCode MemStream::reserve(SizeType newCap) {
        if (!_flags) {
            return ERET_BADREQ;
        }

        if (newCap <= _cap) {
            return ERET_ALREADY;
        }

        // --> Align the new capacity to the SIZE_ALIGN boundary.
        SizeType m = newCap % SIZE_ALIGN;
        if (m) {
            newCap += SIZE_ALIGN - m;
        }

        // --
        uint8_t* p = new uint8_t[newCap];
        if (!p) {
            return ERET_NOMEM;
        }

        if (_span.data) {
            std::memcpy(p, _span.data, _span.size);
            delete[] _span.data;
        }

        _span.data = p;
        _cap = newCap;

        if (_pos > _cap) {
            _pos = _cap;
        }

        return ERET_OK;
    }

    ERetCode MemStream::length(SizeType newLen) {
        if (!_flags) {
            return ERET_BADREQ;
        }

        if (newLen == _span.size) {
            return ERET_ALREADY;
        }

        if (newLen > _cap) {
            ERetCode ret = reserve(newLen);

            if (ret != ERET_OK) {
                return ret;
            }
        }

        _span.size = newLen;
        if (_pos > _span.size) {
            _pos = _span.size;
        }

        return ERET_OK;
    }

    ERetCode MemStream::seek(OffsetType offset, ESeekMode mode) {
        if (!_flags) {
            return ERET_BADREQ;
        }

        uint64_t newPos = _pos;

        switch (mode) {
        case ESEEK_SET: {
            if (offset < 0) {
                offset = 0;
            }

            newPos = offset;
            break;
        }

        case ESEEK_CUR: {
            if (offset >= 0) {
                newPos = _pos + offset;

                // --> Check for overflow.
                if (newPos < _pos) {
                    newPos = _span.size;
                }
            }

            else {
                uint64_t abs = uint64_t(-offset);
                if (abs >= _pos) {
                    newPos = 0;
                }

                else {
                    newPos = _pos - abs;
                }
            }
            
            break;
        }

        case ESEEK_END: {
            if (offset >= 0) {
                newPos = _span.size;
                break;
            }

            uint64_t abs = uint64_t(-offset);
            if (abs >= _span.size) {
                newPos = 0;
            }

            else {
                newPos = _span.size - abs;
            }

            break;
        }
        }

        _pos = newPos;
        return ERET_OK;
    }

    size_t MemStream::read(uint8_t* buf, size_t len) {
        if (!_flags) {
            return 0;
        }

        if (!len || !buf) {
            return 0;
        }

        const SizeType avail = _span.size - _pos;
        if (!avail) {
            return 0;
        }

        if (len > avail) {
            len = avail;
        }

        memcpy(buf, _span.data + _pos, len);
        _pos += len;

        return len;
    }

    size_t MemStream::write(const uint8_t* buf, size_t len) {
        if (!_flags) {
            return 0;
        }

        if (!len || !buf) {
            return 0;
        }

        SizeType avail = _cap - _pos;
        if (avail < len) {
            if (reserve(_pos + len) != ERET_OK) {
                return 0;
            }

            avail = _cap - _pos;
        }

        memcpy(_span.data + _pos, buf, len);
        _pos += len;

        // --> Update the stream size if the current position exceeds it.
        if (_span.size < _pos) {
            _span.size = _pos;
        }

        return len;
    }

    ERetCode MemStream::flush() {
        if (!_flags) {
            return ERET_BADREQ;
        }

        return ERET_OK;
    }

    ERetCode MemStream::close() {
        if (!_flags) {
            return ERET_BADREQ;
        }

        if (_span.data) {
            delete[] _span.data;
        }

        _flags = 0;
        _span.data = nullptr;
        _span.size = 0;
        _pos = 0;
        _cap = 0;

        return ERET_OK;
    }
}