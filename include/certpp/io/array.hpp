#ifndef __INCLUDE_CERTPP_IO_ARRAY_HPP__
#define __INCLUDE_CERTPP_IO_ARRAY_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <new>
#include <utility>

namespace certpp {

    /**
     * Specifies the type of array.
     */
    enum EArrayType : uint8_t {
        EARRAY_NONE     = 0,
        EARRAY_STATIC   = 0x01 & 0x03,
        EARRAY_DYNAMIC  = 0x02 & 0x03,
        EARRAY_FIXED    = 0x80,

        /**
         * Mask to extract the array type (static or dynamic) from the type field.
         */
        EARRAY_TYPE_MASK = 0x03,

        /**
         * Represents a static array with a fixed size.
         * Note that, non-fixed static arrays (EARRAY_STATIC) are transformed to dynamic on resize()/reserve().
         * This ensures that static arrays maintain a consistent size when written to.
         */
        EARRAY_STATIC_FIXED     = EARRAY_STATIC | EARRAY_FIXED,

        /**
         * Represents a dynamic array with a fixed size.
         */
        EARRAY_DYNAMIC_FIXED    = EARRAY_DYNAMIC | EARRAY_FIXED,
    };

    /**
     * Represents an array of elements of type T.
     */
    template<typename T>
    class TArray {
    public:
        /**
         * The type of the current TArray instance.
         */
        using SelfType = TArray<T>;

    private:
        T* _data;
        size_t _size;
        size_t _cap;
        uint8_t _type;

    public:
        /**
         * Constructs an empty array of the specified type.
         *
         * @param type The type of the array.
         */
        TArray(EArrayType type = EARRAY_NONE)
            : _data(nullptr), _size(0), _cap(0), _type(type) {}

        /**
         * Copy constructor for the array.
         *
         * @param other The array to copy from.
         */
        inline TArray(const SelfType& other)
            : _data(nullptr), _size(0), _cap(0), _type(other._type)
        {
            if (other._size > 0) {
                reserve(other._size);

                for (size_t i = 0; i < other._size; ++i) {
                    new(&_data[i]) T(other._data[i]);
                }

                _size = other._size;
            }
        }

        /**
         * Constructs an array by copying elements from a span.
         *
         * @param span The span containing elements to copy.
         */
        inline TArray(const TSpan<T>& span)
            : _data(nullptr), _size(0), _cap(0), _type(EARRAY_NONE)
        {
            if (span.size > 0) {
                reserve(span.size);

                for (size_t i = 0; i < span.size; ++i) {
                    new(&_data[i]) T(span[i]);
                }

                _size = span.size;
            }
        }

        /**
         * Constructs an array by copying elements from a read-only span.
         *
         * @param span The read-only span containing elements to copy.
         */
        inline TArray(const TReadOnlySpan<T>& span)
            : _data(nullptr), _size(0), _cap(0), _type(EARRAY_NONE)
        {
            if (span.size > 0) {
                reserve(span.size);

                for (size_t i = 0; i < span.size; ++i) {
                    new(&_data[i]) T(span[i]);
                }

                _size = span.size;
            }
        }

        /**
         * Move constructor for the array.
         *
         * @param other The array to move from.
         */
        inline TArray(SelfType&& other) noexcept
            : _data(other._data), _size(other._size), _cap(other._cap), _type(other._type)
        {
            other._data = nullptr;
            other._size = 0;
            other._cap = 0;
            other._type = EARRAY_NONE;
        }

        /**
         * Destructor for the array.
         * Clears the array and trims excess capacity.
         */
        ~TArray() {
            clear();
            trimExcess();
        }

        /**
         * Copy assignment operator for the array.
         *
         * @param other The array to copy from.
         * @return A reference to the current array.
         */
        inline SelfType& operator=(const SelfType& other) {
            if (this != &other) {
                clear();

                if (other._size > 0) {
                    reserve(other._size);

                    for (size_t i = 0; i < other._size; ++i) {
                        new(&_data[i]) T(other._data[i]);
                    }

                    _size = other._size;
                }

                _type = other._type;
            }

            return *this;
        }

        /**
         * Move assignment operator for the array.
         *
         * @param other The array to move from.
         * @return A reference to the current array.
         */
        inline SelfType& operator=(SelfType&& other) noexcept {
            if (this != &other) {
                swap(_size, other._size);
                swap(_cap, other._cap);
                swap(_type, other._type);
                swap(_data, other._data);
            }

            return *this;
        }

        /**
         * Assigns elements from a span to the array.
         *
         * @param span The span containing elements to assign.
         * @return A reference to the current array.
         */
        inline SelfType& operator=(const TSpan<T>& span) {
            clear();

            if (span.size > 0) {
                reserve(span.size);

                for (size_t i = 0; i < span.size; ++i) {
                    new(&_data[i]) T(span[i]);
                }

                _size = span.size;
            }

            return *this;
        }

        /**
         * Wraps the array around an existing static buffer.
         *
         * @param array The array to modify.
         * @param p The pointer to the static buffer.
         * @param size The size of the static buffer.
         * @param fixed Whether the wrapped array should also be marked fixed (rejecting reserve()/trimExcess()).
         */
        static void wrap(SelfType& array, T* p, size_t size, bool fixed = false) {
            array.clear();
            array.trimExcess();

            array._data = p;
            array._size = size;
            array._cap = size;
            array._type = EARRAY_STATIC | (fixed ? EARRAY_FIXED : 0);
        }

        /**
         * Marks the array as fixed.
         */
        inline void markFixed() {
            if (_type == EARRAY_NONE) {
                return;
            }

            // --> EARRAY_FIXED (0x80) and EARRAY_TYPE_MASK (0x03, the STATIC/DYNAMIC sub-type)
            // are disjoint bits, so this only needs to OR the flag in -- unlike reserve()/
            // trimExcess()'s "replace the sub-type" pattern (`(_type & ~EARRAY_TYPE_MASK) | ...`),
            // masking out EARRAY_TYPE_MASK here would wipe out the STATIC/DYNAMIC bits for no
            // reason, leaving type() unable to report which sub-type the array actually is.
            _type = EArrayType(_type | EARRAY_FIXED);
        }

    public:
        /**
         * Checks if the array contains any elements.
         */
        inline operator bool() const {
            return _type != EARRAY_NONE && _size > 0;
        }

        /**
         * Checks if the array is empty.
         */
        inline bool operator!() const {
            return _type == EARRAY_NONE || _size == 0;
        }

        /**
         * Checks if the array is empty.
         */
        inline bool empty() const {
            return _type == EARRAY_NONE || _size == 0;
        }

        /**
         * Provides access to the element at the specified index.
         *
         * @param index The index of the element to access.
         * @return A reference to the element at the specified index.
         */
        inline T& operator[](size_t index) {
            return _data[index];
        }

        /**
         * Provides access to the element at the specified index (const version).
         *
         * @param index The index of the element to access.
         * @return A const reference to the element at the specified index.
         */
        inline const T& operator[](size_t index) const {
            return _data[index];
        }

        /**
         * Returns an iterator to the beginning of the array.
         */
        inline T* begin() const {
            return _data;
        }

        /**
         * Returns an iterator to the end of the array.
         */
        inline T* end() const {
            return _data + _size;
        }

        /**
         * Returns the capacity of the array.
         */
        inline size_t capacity() const {
            return _cap;
        }

        /**
         * Returns the type of the array.
         */
        inline EArrayType type() const {
            return EArrayType(_type);
        }

        /**
         * Returns the number of elements in the array.
         */
        inline size_t size() const {
            return _size;
        }

        /**
         * Clears the array by destroying all elements.
         */
        inline void clear() {
            for (size_t i = 0; i < _size; ++i) {
                _data[i].~T();
            }

            _size = 0;
        }

        /**
         * Reserves memory for at least the specified capacity.
         *
         * @param cap The desired capacity.
         * @return True if the reservation was successful, false otherwise.
         */
        inline bool reserve(size_t cap) {
            if (cap <= _cap) {
                return true;
            }

            // --> Cannot reserve memory for a fixed-size array.
            if (_type & EARRAY_FIXED) {
                return false;
            }

            T* p = (T*) new(std::nothrow) uint8_t[cap * sizeof(T)];
            if (!p) {
                return false;
            }

            if (_data) {
                for (size_t i = 0; i < _size; ++i) {
                    new (p + i) T(std::move(_data[i]));
                }

                for (size_t i = 0; i < _size; ++i) {
                    _data[i].~T();
                }

                // --> Only delete the old data if the array is not static.
                if ((_type & EARRAY_TYPE_MASK) != EARRAY_STATIC) {
                    delete[] ((uint8_t*)_data);
                }
            }

            // --> Once the array owns freshly-allocated heap memory, it's a dynamic array --
            // whether it started as EARRAY_STATIC (aliasing a caller's buffer it doesn't own) or
            // EARRAY_NONE (no previous allocation at all, e.g. a freshly default-constructed
            // TArray<T>()). Checking only for EARRAY_STATIC here (and only inside the `if (_data)`
            // above, so it never ran on an EARRAY_NONE array's very first reserve(), since that
            // starts with _data == nullptr) left a default-constructed array's type stuck at
            // EARRAY_NONE forever, even after add()ing real elements -- which made empty()/
            // operator bool() (both of which treat EARRAY_NONE as empty regardless of size)
            // permanently wrong for the single most common way to use this class.
            if ((_type & EARRAY_TYPE_MASK) != EARRAY_DYNAMIC) {
                _type = EArrayType((_type & ~EARRAY_TYPE_MASK) | EARRAY_DYNAMIC);
            }

            _data = p;
            _cap = cap;
            return true;
        }

        /**
         * Resizes the array to the specified size.
         *
         * @param size The desired size.
         * @return True if the resize was successful, false otherwise.
         */
        inline bool resize(size_t size) {
            // --> Growing needs either room already, or a successful reserve() to make room --
            // but reserve() itself always fails on a fixed array, so short-circuit around calling
            // it in that case. (Note: `(_type & EARRAY_FIXED) || !reserve(size)`, not
            // `!(_type & EARRAY_FIXED) && !reserve(size)` -- the latter inverts the fixed check,
            // so growing a fixed array would skip this early return entirely and fall through to
            // placement-new past the end of `_cap`, a buffer overflow.)
            if (_size < size && ((_type & EARRAY_FIXED) || !reserve(size))) {
                return false;
            }

            // --> Construct new elements if the array is being expanded.
            if (_size < size) {
                for (size_t i = _size; i < size; ++i) {
                    new (_data + i) T();
                }
            }

            // --> Destroy elements if the array is being shrunk.
            else if (_size > size) {
                for (size_t i = size; i < _size; ++i) {
                    _data[i].~T();
                }
            }

            _size = size;
            return true;
        }

        /**
         * Trims the excess capacity of the array, reducing it to match the current size.
         *
         * @return True if the trim was successful, false otherwise.
         */
        inline bool trimExcess() {
            if (_type & EARRAY_FIXED) {
                return false;
            }

            if (_size == _cap) {
                return true;
            }

            // --> If the array is empty, release its memory and reset its state.
            if (_size == 0) {
                if ((_type & EARRAY_TYPE_MASK) != EARRAY_STATIC) {
                    delete[] ((uint8_t*)_data);
                }

                _type = EARRAY_NONE;
                _data = nullptr;

                _cap = 0;
                _size = 0;
                return true;
            }

            T* p = (T*) new(std::nothrow) uint8_t[_size * sizeof(T)];
            if (!p) {
                return false;
            }

            for (size_t i = 0; i < _size; ++i) {
                new (p + i) T(std::move(_data[i]));
            }

            for (size_t i = 0; i < _size; ++i) {
                _data[i].~T();
            }

            if ((_type & EARRAY_TYPE_MASK) != EARRAY_STATIC) {
                delete[] ((uint8_t*)_data);
            }

            // --> If the array was previously static, it is now dynamic.
            if ((_type & EARRAY_TYPE_MASK) == EARRAY_STATIC) {
                _type = EArrayType((_type & ~EARRAY_TYPE_MASK) | EARRAY_DYNAMIC);
            }

            _data = p;
            _cap = _size;
            return true;
        }

        /**
         * Adds a new element to the end of the array.
         *
         * @param value The value to be added to the array.
         * @return True if the addition was successful, false otherwise.
         */
        inline bool add(const T& value) {
            if (!resize(_size + 1)) {
                return false;
            }

            _data[_size - 1] = value;
            return true;
        }

        /**
         * Adds a new element to the end of the array using move semantics.
         *
         * @param value The value to be added to the array.
         * @return True if the addition was successful, false otherwise.
         */
        inline bool add(T&& value) {
            if (!resize(_size + 1)) {
                return false;
            }

            _data[_size - 1] = std::move(value);
            return true;
        }

        /**
         * Removes the element at the specified index from the array.
         *
         * @param index The index of the element to be removed.
         * @return True if the removal was successful, false otherwise.
         */
        inline bool remove(size_t index) {
            if (index >= _size) {
                return false;
            }

            _data[index].~T();

            for (size_t i = index; i < _size - 1; ++i) {
                new (_data + i) T(std::move(_data[i + 1]));
                _data[i + 1].~T();
            }

            --_size;
            return true;
        }

        /**
         * Removes a range of elements from the array starting at the specified index.
         *
         * @param index The starting index of the elements to be removed.
         * @param count The number of elements to be removed.
         * @return The number of elements actually removed.
         */
        inline size_t remove(size_t index, size_t count) {
            if (index >= _size) {
                return 0;
            }

            const size_t absMax = _size - index;
            if (count > absMax) {
                count = absMax;
            }

            // --> Destroy the elements to be removed.
            for (size_t i = index; i < index + count; ++i) {
                _data[i].~T();
            }

            // --> Move the elements after the removed ones to fill the gap.
            for (size_t i = index + count; i < _size; ++i) {
                new (_data + i - count) T(std::move(_data[i]));
                _data[i].~T();
            }

            _size -= count;
            return count;
        }

        /**
         * Inserts a new element at the specified index using copy semantics.
         *
         * @param index The index at which the element should be inserted.
         * @param value The value to be inserted.
         * @return True if the insertion was successful, false otherwise.
         */
        inline bool insert(size_t index, const T& value) {
            if (index > _size) {
                return false;
            }

            const size_t oldSize = _size;
            if (!resize(_size + 1)) {
                return false;
            }

            if (oldSize > index) {
                // --> resize() default-constructed a fresh slot at the new last position;
                // destroy it before reusing that memory, then shift [index, oldSize) up by one,
                // moving from the back forward so each destination is only ever
                // placement-constructed after being vacated -- by this destroy (the first
                // iteration) or by the previous iteration's own move-then-destroy of its source
                // (every iteration after that).
                _data[_size - 1].~T();

                for (size_t i = _size - 1; i > index; --i) {
                    new (_data + i) T(std::move(_data[i - 1]));
                    _data[i - 1].~T();
                }
            }

            // --> index's slot is vacated either way at this point: by the shift above (its last
            // iteration destroys _data[index]), or -- when index == oldSize, a pure append -- by
            // resize()'s fresh default object, which the shift above never ran, so it's still
            // alive here and must be destroyed before reuse.
            if (index == oldSize) {
                _data[index].~T();
            }

            new (_data + index) T(value);
            return true;
        }

        /**
         * Inserts a new element at the specified index using move semantics.
         *
         * @param index The index at which the element should be inserted.
         * @param value The value to be inserted.
         * @return True if the insertion was successful, false otherwise.
         */
        inline bool insert(size_t index, T&& value) {
            if (index > _size) {
                return false;
            }

            const size_t oldSize = _size;
            if (!resize(_size + 1)) {
                return false;
            }

            if (oldSize > index) {
                // --> See the const T& overload's comment for why this destroy-then-shift order
                // is needed.
                _data[_size - 1].~T();

                for (size_t i = _size - 1; i > index; --i) {
                    new (_data + i) T(std::move(_data[i - 1]));
                    _data[i - 1].~T();
                }
            }

            if (index == oldSize) {
                _data[index].~T();
            }

            new (_data + index) T(std::move(value));
            return true;
        }

        /**
         * Removes the last element from the array and stores it in the provided reference.
         *
         * @param value A reference to store the removed element.
         * @return True if an element was removed, false if the array was empty.
         */
        inline bool pop(T& value) {
            if (_size == 0) {
                return false;
            }

            value = std::move(_data[_size - 1]);
            _data[_size - 1].~T();

            --_size;
            return true;
        }

        /**
         * Removes the last element from the array without storing it.
         *
         * @return True if an element was removed, false if the array was empty.
         */
        inline bool pop() {
            if (_size == 0) {
                return false;
            }

            _data[_size - 1].~T();

            --_size;
            return true;
        }
    };
}

#endif
