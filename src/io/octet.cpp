#include <certpp/io/octet.hpp>
#include <cstring>

namespace certpp {

    /* Store the given data into the octet. */
    bool COctet::store(const uint8_t* data, size_t size) {
        if (!data || size == 0) {
            return false;
        }

        if (size != _size || !_data) {
            uint8_t* p = new uint8_t[size];
            if (!p) {
                return false;
            }

            std::memcpy(p, data, size);
            if (_data) {
                delete[] _data;
            }

            _data = p;
            _size = size;
        }

        else {
            std::memcpy(_data, data, size);
        }

        return true;
    }

    /* Clears the octet, releasing any allocated memory and resetting its size to zero. */
    void COctet::clear() {
        if (_data) {
            delete[] _data;
            _data = nullptr;
        }

        _size = 0;
    }

}