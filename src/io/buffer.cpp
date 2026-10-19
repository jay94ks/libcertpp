#include <certpp/io/buffer.hpp>
#include <certpp/utils/secure.hpp>

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

    /* Resizes the protected buffer, preserving its common prefix. */
    bool CSecureBuffer::resize(size_t size) {
        if (size == _size) {
            return true;
        }

        if (size == 0) {
            if (_data) {
                (void)CSecure::dealloc(_data);
                _data = nullptr;
            }

            _size = 0;
            return true;
        }

        uint8_t* replacement = static_cast<uint8_t*>(CSecure::alloc(size));
        if (!replacement) {
            return false;
        }

        if (_data) {
            const size_t preserved = size < _size ? size : _size;
            std::memcpy(replacement, _data, preserved);
            (void)CSecure::dealloc(_data);
        }

        _data = replacement;
        _size = size;
        return true;
    }

    /* Stores the given data in protected storage. */
    bool CSecureBuffer::store(const uint8_t* data, size_t size) {
        if (!resize(size)) {
            return false;
        }

        if (size && data) {
            std::memcpy(_data, data, size);
        }

        return true;
    }

} // namespace certpp
