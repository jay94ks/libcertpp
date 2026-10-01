#include <certpp/io/buffer.hpp>

namespace certpp {

    /* Resizes the buffer to the specified size. */
    bool CBuffer::resize(size_t size) {
        if (size == _size) {
            return true;
        }

        if (!size) {
            if (_data) {
                delete[] _data;
                _data = nullptr;
            }

            _size = 0;
            return true;
        }

        uint8_t* p = new uint8_t[size];
        if (!p) {
            return false;
        }

        if (_data) {
            size_t len = (size < _size) ? size : _size;
            std::memcpy(p, _data, len);
            delete[] _data;
        }

        _data = p;
        _size = size;
        return true;
    }

    /* Stores the given data into the buffer. */
    bool CBuffer::store(const uint8_t* data, size_t size) {
        if (!resize(size)) {
            return false;
        }

        if (size && data) {
            std::memcpy(_data, data, size);
        }

        return true;
    }

    
}