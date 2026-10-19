#include <certpp/io/octet.hpp>
#include <certpp/utils/secure.hpp>
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

    /* Zeroizes the stored bytes, then clears. */
    void COctet::secureClear() {
        if (_data && _size) {
            // --> CSecure::zero() rather than memset: a memset whose result is never read is a
            // dead store the optimizer is entitled to delete, and here the result is never read
            // by construction -- the next statement frees the block.
            CSecure::zero(SByteSpan(_data, _size));
        }

        clear();
    }

    /* Clears the octet, releasing any allocated memory and resetting its size to zero. */
    void COctet::clear() {
        if (_data) {
            delete[] _data;
            _data = nullptr;
        }

        _size = 0;
    }

    /* Stores the given data in protected storage. */
    bool CSecureOctet::store(const uint8_t* data, size_t size) {
        if (!data || size == 0) {
            return false;
        }

        if (size != _size || !_data) {
            uint8_t* replacement = static_cast<uint8_t*>(CSecure::alloc(size));
            if (!replacement) {
                return false;
            }

            std::memcpy(replacement, data, size);
            if (_data) {
                (void)CSecure::dealloc(_data);
            }

            _data = replacement;
            _size = size;
        }
        else {
            std::memmove(_data, data, size);
        }

        return true;
    }

    /* Wipes and releases the protected allocation. */
    void CSecureOctet::clear() {
        if (_data) {
            (void)CSecure::dealloc(_data);
            _data = nullptr;
        }

        _size = 0;
    }

} // namespace certpp
