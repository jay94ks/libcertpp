#ifndef __INCLUDE_CERTPP_STRING_HPP__
#define __INCLUDE_CERTPP_STRING_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <cstring>
#include <cctype>
#include <cwchar>
#include <algorithm>
#include <utility>

namespace certpp {

    template<typename T>
    class TStringFunctions {
    public:
        /**
         * Fills the given data array with default-constructed values of type T.
         * @param data The data array to fill with default-constructed values.
         * @param size The number of elements in the data array to fill.
         */
        static inline void fillZero(T* data, size_t size) {
            std::memset(data, 0, size * sizeof(T));
        }

        /**
         * Copies the contents from the source array to the destination array.
         * @param dest The destination array where the contents will be copied.
         * @param src The source array from which the contents will be copied.
         * @param size The number of elements to copy.
         */
        static inline void copy(T* dest, const T* src, size_t size) {
            std::memcpy(dest, src, size * sizeof(T));
        }

        /**
         * Moves the contents from the source array to the destination array.
         * @param dest The destination array where the contents will be moved.
         * @param src The source array from which the contents will be moved.
         * @param size The number of elements to move.
         */
        static inline void move(T* dest, T* src, size_t size) {
            std::memmove(dest, src, size * sizeof(T));
        }

        /**
         * Compares two arrays of type T for equality.
         * @param lhs The left-hand side array.
         * @param rhs The right-hand side array.
         * @param size The number of elements to compare.
         * @return 0 if the arrays are equal, a non-zero value otherwise.
         */
        static inline int32_t cmp(const T* lhs, const T* rhs, size_t size) {
            if (!lhs || !rhs || !size) {
                return 0;
            }

            return std::memcmp(lhs, rhs, size * sizeof(T));
        }

        /**
         * Compares two arrays of type T for equality, ignoring case.
         * @param lhs The left-hand side array.
         * @param rhs The right-hand side array.
         * @param size The number of elements to compare.
         * @return 0 if the arrays are equal (ignoring case), a non-zero value otherwise.
         */
        static inline int32_t caseCmp(const T* lhs, const T* rhs, size_t size) {
            if (!lhs || !rhs || !size) {
                return 0;
            }

            for (size_t i = 0; i < size; ++i) {
                T l = lhs[i];
                T r = rhs[i];

                if (l >= 'A' && l <= 'Z') {
                    l = l - 'A' + 'a';
                }

                if (r >= 'A' && r <= 'Z') {
                    r = r - 'A' + 'a';
                }

                if (l != r) {
                    return int32_t(l) - int32_t(r);
                }
            }

            return 0;
        }

        /**
         * Finds the first occurrence of the specified character in the given string.
         * Returns a pointer to the character if found, or nullptr if not found.
         * @param str The string to search for the character.
         * @param size The size of the string.
         * @param ch The character to find.
         * @return A pointer to the character if found, or nullptr if not found.
         */
        static inline const T* chr(const T* str, size_t size, T ch) {
            if (!str || !size) {
                return nullptr;
            }

            while (size-- > 0) {
                if (*str == ch) {
                    return str;
                }

                ++str;
            }

            return nullptr;
        }

        /**
         * Finds the last occurrence of the specified character in the given string.
         * Returns a pointer to the character if found, or nullptr if not found.
         * @param str The string to search for the character.
         * @param size The size of the string.
         * @param ch The character to find.
         * @return A pointer to the character if found, or nullptr if not found.
         */
        static inline const T* rchr(const T* str, size_t size, T ch) {
            if (!str || !size) {
                return nullptr;
            }

            while (size > 0) {
                --size;

                if (str[size] == ch) {
                    return &str[size];
                }
            }

            return nullptr;
        }

        /**
         * Finds the first occurrence of the specified character in the given string.
         * Returns the offset of the character if found, or -1 if not found.
         * @param str The string to search for the character.
         * @param size The size of the string.
         * @param ch The character to find.
         * @return The offset of the character if found, or -1 if not found.
         */
        static inline offset_t find(const T* str, size_t size, T ch) {
            if (!str) {
                return -1; // --> Offset is out of bounds or string is null.
            }

            if (const T* found = chr(str, size, ch)) {
                // --> Plain pointer subtraction (not an intptr_t byte-address difference): the
                // standard already divides by sizeof(T) for us, giving the element index rather
                // than a byte offset -- these only coincide when sizeof(T) == 1 (char).
                return offset_t(found - str);
            }

            return -1;
        }

        /**
         * Finds the last occurrence of the specified character in the given string.
         * Returns the offset of the character if found, or -1 if not found.
         * @param str The string to search for the character.
         * @param size The size of the string.
         * @param ch The character to find.
         * @return The offset of the character if found, or -1 if not found.
         */
        static inline offset_t findLast(const T* str, size_t size, T ch) {
            if (!str) {
                return -1; // --> Offset is out of bounds or string is null.
            }

            if (const T* found = rchr(str, size, ch)) {
                // --> See find()'s comment: plain pointer subtraction, not an intptr_t byte
                // difference.
                return offset_t(found - str);
            }

            return -1;
        }

        /**
         * Counts the number of characters in the given string up to the specified size.
         * @param str The string to count characters in.
         * @param size The maximum number of characters to count.
         * @return The number of characters in the string up to the specified size.
         */
        static inline size_t countOf(const T* str, size_t size = size_t(-1)) {
            if (!str || !size) {
                return 0;
            }
            
            size_t n = 0;
            while (size) {
                if (str[n] == T()) {
                    break;
                }

                ++n;
                --size;
            }

            return n;
        }

        /**
         * Checks if the given character is a whitespace character.
         * @param ch The character to check.
         * @return True if the character is a whitespace character, false otherwise.
         */
        static inline bool isSpace(T ch) {
            return std::isspace(static_cast<unsigned char>(ch));
        }

        /**
         * Converts the given character to lowercase.
         * @param ch The character to convert to lowercase.
         * @return The lowercase version of the character.
         */
        static inline T toLower(T ch) {
            return static_cast<T>(std::tolower(static_cast<unsigned char>(ch)));
        }

        /**
         * Converts the given character to uppercase.
         * @param ch The character to convert to uppercase.
         * @return The uppercase version of the character.
         */
        static inline T toUpper(T ch) {
            return static_cast<T>(std::toupper(static_cast<unsigned char>(ch)));
        }
    };

    /**
     * A template class representing a string of characters of type T.
     * By default, T is char, but it can be specialized for other character types.
     * @tparam T The character type of the string. Defaults to char.
     */
    template<typename T = char>
    class TString {
    private:
        /**
         * The default capacity increment used when resizing the TString.
         */
        static constexpr size_t CAP_INC = 64;

        /**
         * The null character of type T.
         */
        static constexpr T NUL = T();

    public:
        /**
         * The type of the current TString instance.
         */
        using SelfType = TString<T>;

        /**
         * The type representing the string functions for the current character type.
         */
        using Functions = TStringFunctions<T>;

    private:
        T*  _data;
        size_t _size;       // --> This does not include the null terminator.
        size_t _capacity;

    public:
        /**
         * Default constructor initializes an empty TString.
         */
        TString() : _data(), _size(0), _capacity(0) { }

        /**
         * Copy constructor.
         * @param other The TString instance to copy from.
         */
        TString(const SelfType& other) : _data(nullptr), _size(0), _capacity(0) {
            append(other);
        }

        /**
         * Move constructor.
         * @param other The TString instance to move from.
         */
        TString(SelfType&& other) : _data(other._data), _size(other._size), _capacity(other._capacity) {
            other._data = nullptr;
            other._size = 0;
            other._capacity = 0;
        }

        /**
         * Constructs a TString from a null-terminated C-style string.
         * @param cStr The null-terminated string to copy from.
         */
        TString(const T* cStr) : _data(nullptr), _size(0), _capacity(0) {
            append(cStr);
        }

        /**
         * Constructs a TString from a character array with a specified limit. The array is
         * not required to be null-terminated; up to limit characters are copied.
         * @param data Pointer to the character array to copy from.
         * @param limit The maximum number of characters to copy.
         */
        TString(const T* data, size_t limit) : _data(nullptr), _size(0), _capacity(0) {
            if (data && limit) {
                append(data, limit);
            }
        }

        /**
         * Template copy constructor for converting between different character types.
         * @param cStr The TString instance of a different character type to copy from.
         */
        template<typename U>
        TString(const TString<U>& cStr);

        /**
         * Destructor.
         * Clears the TString and releases any allocated memory.
         */
        ~TString() {
            clear();
        }

    public:
        /**
         * Returns the capacity of the TString.
         */
        inline size_t capacity() const { return _capacity; }

        /**
         * Returns the size of the TString.
         */
        inline size_t size() const { return _size; }

        /**
         * Checks if the TString is empty.
         */
        inline bool empty() const { return _size == 0; }

        /**
         * Returns a pointer to the underlying character array.
         * This can be null when empty.
         */
        inline const T* toPtr() const { return _data; }

        /**
         * Returns a mutable pointer to the underlying character array.
         * This can be null when empty.
         */
        inline T* toPtr() { return _data; }

        /**
         * Returns a reference to the underlying character array as a span.
         * This can be empty when the TString is empty.
         */
        inline TSpan<T> toSpan() { return TSpan<T>(_data, _size); }

        /**
         * Returns a const reference to the underlying character array as a span.
         * This can be empty when the TString is empty.
         */
        inline TReadOnlySpan<T> toSpan() const { return TReadOnlySpan<T>(_data, _size); }

        /**
         * Conversion operator to bool.
         * Returns true if the TString is not empty, false otherwise.
         */
        inline operator bool() const { return !empty(); }

        /**
         * Logical NOT operator.
         * Returns true if the TString is empty, false otherwise.
         */
        inline bool operator!() const { return empty(); }

        /**
         * Subscript operator for accessing characters by index.
         * @param index The index of the character to access.
         * @return The character at the specified index.
         */
        inline T operator[](size_t index) const { return _data[index]; }

        /**
         * Copy assignment operator.
         * @param other The TString instance to copy from.
         */
        inline SelfType operator=(const SelfType& other) {
            if (this != &other) {
                clear();
                append(other);
            }

            return *this;
        }

        /**
         * Move assignment operator.
         * @param other The TString instance to move from.
         */
        inline SelfType operator=(SelfType&& other) {
            if (this != &other) {
                swap(_data, other._data);
                swap(_size, other._size);
                swap(_capacity, other._capacity);
            }

            return *this;
        }

        /**
         * Assignment operator for C-style strings.
         * @param cStr The C-style string to assign from.
         */
        inline SelfType operator=(const T* cStr) {
            clear();
            append(cStr);
            return *this;
        }

        /**
         * Reserves capacity for the TString.
         * Returns true if the reservation was successful, false otherwise.
         * @param capacity The desired capacity to reserve.
         */
        inline bool reserve(size_t capacity) {
            const size_t rem = capacity % CAP_INC;
            if (rem != 0) {
                capacity += CAP_INC - rem;
            }

            if (_capacity >= capacity) {
                return true;
            }

            T* p = new T[capacity];
            if (!p) {
                return false; // --> No memory available for the requested capacity.
            }

            if (_data) {
                if (_size) {
                    Functions::copy(p, _data, _size);
                }

                delete[] _data;
            }

            // --> Set the null terminator for the new capacity.
            p[_size] = T();
            
            // --
            _data = p;
            _capacity = capacity;
            return true;
        }

        /**
         * Trims the excess capacity of the TString.
         * Returns true if the TString's capacity is minimal after the call (whether or not
         * there was anything to trim), false only on actual allocation failure.
         */
        inline bool trimExcess() {
            // --> An empty string needs no storage at all, regardless of prior capacity.
            if (!_size) {
                if (_data) {
                    delete[] _data;

                    _data = nullptr;
                    _capacity = 0;
                }

                return true;
            }

            if (_capacity <= _size + 1) {
                return true; // --> Already at minimal capacity.
            }

            const size_t requiredCap = _size + 1;
            T* p = new T[requiredCap];
            if (!p) {
                return false; // --> No memory available for the required capacity.
            }

            if (_data) {
                if (_size) {
                    Functions::copy(p, _data, _size);
                }

                delete[] _data;
            }

            // --> Set the null terminator for the new capacity.
            p[_size] = T();

            // --
            _data = p;
            _capacity = requiredCap;
            return true;
        }

        /**
         * Resizes the TString to the specified size.
         * Returns true if the resizing was successful, false otherwise.
         * @param size The new size to resize the TString to.
         */
        inline bool resize(size_t size) {
            if (size == _size) {
                return true; // --> No resizing needed.
            }

            const size_t requiredCap = size + 1;
            if (requiredCap > _capacity && !reserve(requiredCap)) {
                return false; // --> Failed to reserve the required capacity.
            }

            _size = size;
            _data[_size] = T(); // --> Set the null terminator.
            return true;
        }

        /**
         * Clears the TString, setting its size to zero.
         * Returns true if the clearing was successful, false otherwise.
         */
        inline bool clear() {
            _size = 0;

            if (_data) {
                _data[0] = T(); // --> Set the null terminator.
            }

            return true;
        }

        /**
         * Appends the specified string to the TString.
         * Returns the current instance.
         * @param str The string to append.
         * @param limit The maximum number of characters to append from the string.
         * @return The current instance after appending.
         */
        inline SelfType& append(const T* str, size_t limit = size_t(-1)) {
            const size_t len = Functions::countOf(str, limit);
            if (!len) {
                return *this; // --> Nothing to append.
            }

            if (!resize(_size + len)) {
                return *this; // --> Failed to resize for the new content.
            }
            
            Functions::copy(_data + _size - len, str, len); // --> Append the new content.
            return *this; // --> Return the current instance after appending.
        }

        /**
         * Appends the specified TString to the current TString.
         * Returns the current instance.
         * @param other The TString to append.
         * @return The current instance after appending.
         */
        inline SelfType& append(const SelfType& other) {
            if (other.empty()) {
                return *this; // --> Nothing to append.
            }

            size_t otherSize = other.size();
            if (!resize(_size + otherSize)) {
                return *this; // --> Failed to resize for the new content.
            }

            Functions::copy(_data + _size - otherSize, other.toPtr(), otherSize); // --> Append the new content.
            return *this; // --> Return the current instance after appending.
        }

        /**
         * Appends the specified TString of a different character type to the current TString.
         * Returns the current instance.
         * @tparam U The character type of the TString to append.
         * @param other The TString to append.
         * @return The current instance after appending.
         */
        template<typename U>
        inline SelfType& append(const TString<U>& other);

        /**
         * Appends the specified character to the TString.
         * Returns the current instance.
         * @param ch The character to append.
         */
        inline SelfType& append(T ch) {
            if (!resize(_size + 1)) {
                return *this; // --> Failed to resize for the new content.
            }

            _data[_size - 1] = ch; // --> Append the new character.
            return *this; // --> Return the current instance after appending.
        }

        /**
         * Erases a portion of the TString starting from the specified position.
         * Returns the current instance.
         * @param start The starting position to begin erasing.
         * @param count The number of characters to erase. If not specified, erases until the end.
         * @return The current instance after erasing.
         */
        inline SelfType& erase(size_t start, size_t count = size_t(-1)) {
            if (!_data || start >= _size) {
                return *this; // --> Start position is out of bounds.
            }

            const size_t absMax = _size - start;

            if (count > absMax) {
                count = absMax; // --> Adjust count to erase until the end if necessary.
            }

            if (count) {
                Functions::move(
                    _data + start, 
                    _data + start + count, 
                    _size - start - count); // --> Shift the remaining characters.

                _size -= count; // --> Update the size after erasing.
                _data[_size] = T(); // --> Null-terminate the string.
            }

            return *this; // --> Return the current instance after erasing.
        }

        /**
         * Finds the first occurrence of the specified character starting from the given position.
         * Returns the offset of the character if found, or -1 if not found.
         * @param ch The character to find.
         * @param skipBefore The count to skip from the beginning when searching for the character.
         * @return The offset of the character if found, or -1 if not found.
         */
        inline offset_t find(T ch, size_t skipBefore = 0) const {
            if (!_data || skipBefore >= _size) {
                return -1; // --> Offset is out of bounds.
            }

            const offset_t o = Functions::find(_data + skipBefore, _size - skipBefore, ch);
            if (o >= 0) {
                return static_cast<offset_t>(o + skipBefore);
            }

            return -1; // --> Character not found.
        }

        /**
         * Finds the first occurrence of the specified substring starting from the given position.
         * Returns the offset of the substring if found, or -1 if not found.
         * @param str The substring to find.
         * @param skipBefore The count to skip from the beginning when searching for the substring.
         * @return The offset of the substring if found, or -1 if not found.
         */
        inline offset_t find(const T* str, size_t skipBefore = 0) const {
            if (!_data || !str || skipBefore >= _size) {
                return -1; // --> Offset is out of bounds.
            }

            const size_t lenStr = Functions::countOf(str);
            const size_t left = _size - skipBefore;
            if (lenStr > left) {
                return -1; // --> Substring not found because it is longer than the remaining characters.
            }

            size_t off = 0;
            while (off + lenStr <= left) {
                offset_t cur = Functions::find(_data + off + skipBefore, left - off, str[0]);
                if (cur < 0) {
                    break;
                }

                const size_t abs = static_cast<size_t>(cur) + off;
                if (abs + lenStr > left) {
                    break; // --> Substring not found within the remaining characters.
                }

                if (Functions::cmp(_data + abs + skipBefore, str, lenStr) == 0) {
                    return static_cast<offset_t>(abs + skipBefore); // --> Substring found.
                }

                off = abs + 1; // --> Move past the current match attempt.
            }

            return -1; // --> Substring not found.
        }

        /**
         * Finds the last occurrence of the specified character starting from the given position from the end.
         * Returns the offset of the character if found, or -1 if not found.
         * @param ch The character to find.
         * @param skipFromEnd The count to skip from the end when searching for the character.
         * @return The offset of the character if found, or -1 if not found.
         */
        inline offset_t findLast(T ch, size_t skipFromEnd = 0) const {
            if (!_data || skipFromEnd >= _size) {
                return -1; // --> Offset is out of bounds.
            }

            return Functions::findLast(_data, _size - skipFromEnd, ch);
        }

        /**
         * Finds the last occurrence of the specified substring starting from the given position from the end.
         * Returns the offset of the substring if found, or -1 if not found.
         * @param str The substring to find.
         * @param skipBefore The count to skip from the beginning when searching for the substring.
         * @return The offset of the substring if found, or -1 if not found.
         */
        inline offset_t findLast(const T* str, size_t skipBefore = 0) const {
            if (!_data || !str || skipBefore >= _size) {
                return -1; // --> Offset is out of bounds.
            }

            const size_t lenStr = Functions::countOf(str);

            if (lenStr == 0 || lenStr > _size - skipBefore) {
                return -1; // --> Substring not found if it's empty or too long.
            }

            size_t off = _size - skipBefore - lenStr;
            while (true) {
                if (Functions::cmp(_data + off + skipBefore, str, lenStr) == 0) {
                    return static_cast<offset_t>(off + skipBefore); // --> Substring found.
                }

                if (off == 0) {
                    break; // --> Reached the beginning without finding the substring.
                }

                --off; // --> Move backward.
            }

            return -1; // --> Substring not found.
        }

        /**
         * Returns a substring of the current TString starting from the specified position with the given length.
         * If the start position is out of bounds, an empty TString is returned.
         * If the requested length exceeds the available size, it is adjusted accordingly.
         * @param start The starting position of the substring.
         * @param length The length of the substring.
         * @return A TString representing the substring.
         */
        inline SelfType subString(size_t start, size_t length) const {
            if (!_data || start >= _size) {
                return SelfType(); // --> Return an empty TString if the start is out of bounds.
            }

            if (start + length > _size) {
                length = _size - start; // --> Adjust the length if it exceeds the available size.
            }

            return SelfType(_data + start, length); // --> Return the substring.
        }
        
        /**
         * Returns a substring of the current TString starting from the specified position to the end.
         * If the start position is out of bounds, an empty TString is returned.
         * @param start The starting position of the substring.
         * @return A TString representing the substring from the start position to the end.
         */
        inline SelfType subString(size_t start) const {
            if (!_data || start >= _size) {
                return SelfType(); // --> Return an empty TString if the start is out of bounds.
            }

            return SelfType(_data + start, _size - start); // --> Return the substring from the start position to the end.
        }

        /**
         * Returns a trimmed version of the current TString, removing leading and trailing whitespace characters.
         * If the current TString is empty, an empty TString is returned.
         * @return A TString representing the trimmed version of the current TString.
         */
        inline SelfType trim() const {
            if (!_data || _size == 0) {
                return SelfType(); // --> Return an empty TString if the current instance is empty.
            }

            size_t start = 0;
            size_t end = _size - 1;

            while (start < _size && Functions::isSpace(_data[start])) {
                ++start; // --> Skip leading whitespace characters.
            }

            while (end > start && Functions::isSpace(_data[end])) {
                --end; // --> Skip trailing whitespace characters.
            }

            return subString(start, end - start + 1); // --> Return the trimmed substring.
        }

        /**
         * Trims the current TString in place, removing leading and trailing whitespace characters.
         * If the current TString is empty, the current instance remains unchanged.
         * @return The current instance after trimming.
         */
        inline SelfType& trimSelf() {
            if (!_data || _size == 0) {
                return *this; // --> Return the current instance if it is empty.
            }

            *this = trim();
            return *this;
        }

        /**
         * Returns a lowercase version of the current TString.
         * If the current TString is empty, an empty TString is returned.
         * @return A TString representing the lowercase version of the current TString.
         */
        inline SelfType toLower() const {
            if (!_data || _size == 0) {
                return SelfType(); // --> Return an empty TString if the current instance is empty.
            }

            SelfType result;

            result.resize(_size);
            for (size_t i = 0; i < _size; ++i) {
                result._data[i] = Functions::toLower(_data[i]);
            }

            return result;
        }

        /**
         * Returns an uppercase version of the current TString.
         * If the current TString is empty, an empty TString is returned.
         * @return A TString representing the uppercase version of the current TString.
         */
        inline SelfType toUpper() const {
            if (!_data || _size == 0) {
                return SelfType(); // --> Return an empty TString if the current instance is empty.
            }

            SelfType result;

            result.resize(_size);
            for (size_t i = 0; i < _size; ++i) {
                result._data[i] = Functions::toUpper(_data[i]);
            }

            return result;
        }

        /**
         * Reverses the current TString in place.
         * If the current TString is empty, the current instance is returned.
         * @return The current instance after reversing.
         */
        inline SelfType& reverse() {
            if (!_data || _size == 0) {
                return *this; // --> Return the current instance if it is empty.
            }
            
            size_t half = _size >> 1;
            for (size_t i = 0; i < half; i++) {
                T temp = _data[i];
                _data[i] = _data[_size - 1 - i];
                _data[_size - 1 - i] = temp;
            }

            return *this;
        }
        
        /**
         * Compares the current TString with another TString.
         * @param other The TString to compare with.
         * @return A negative value if the current TString is less than other, a positive value
         * if greater, 0 if equal (magnitude beyond the sign isn't meaningful).
         */
        inline int32_t compare(const SelfType& other) const {
            if (_size == other._size) {
                if (!_size) {
                    return 0; // Both are empty.
                }

                return Functions::cmp(_data, other._data, _size);
            }

            if (!_size) {
                return -1; // Current TString is empty, other is non-empty.
            }

            if (!other._size) {
                return 1; // Current TString is non-empty, other is empty.
            }

            const size_t min = _size < other._size ? _size : other._size;
            const int32_t dV = Functions::cmp(_data, other._data, min);

            if (dV != 0) {
                return dV;
            }

            return _size < other._size ? -1 : 1;
        }

        /**
         * Compares the current TString with another TString, ignoring ASCII case (i.e. 'A'-'Z'
         * are folded to 'a'-'z' before comparing; non-ASCII/non-letter characters compare as-is).
         * @param other The TString to compare with.
         * @return A negative value if the current TString is less than other, a positive value
         * if greater, 0 if equal (the same "sign only" contract as compare()).
         */
        inline int32_t compareIgnoreCase(const SelfType& other) const {
            if (_size == other._size) {
                if (!_size) {
                    return 0; // Both are empty.
                }

                return Functions::caseCmp(_data, other._data, _size);
            }

            if (!_size) {
                return -1; // Current TString is empty, other is non-empty.
            }

            if (!other._size) {
                return 1; // Current TString is non-empty, other is empty.
            }

            const size_t min = _size < other._size ? _size : other._size;
            const int32_t dV = Functions::caseCmp(_data, other._data, min);

            if (dV != 0) {
                return dV;
            }

            return _size < other._size ? -1 : 1;
        }

        /**
         * Compares the current TString with a raw character array, optionally limited to at
         * most limit characters (a null terminator within that limit still ends the comparand,
         * same as countOf()).
         * @param data The raw character array to compare with; may be null.
         * @param limit The maximum number of characters of data to consider. Defaults to
         * unlimited, i.e. data is treated as a full null-terminated string.
         * @return A negative value if the current TString is less than data, a positive value
         * if greater, 0 if equal (the same "sign only" contract as compare(const SelfType&)).
         */
        inline int32_t compare(const T* data, size_t limit = size_t(-1)) const {
            // --> Determine data's actual (bounded) length first -- limit alone isn't data's
            // length when defaulted to size_t(-1), so it can't be used directly as one below.
            const size_t dataLen = Functions::countOf(data, limit);

            if (dataLen == 0) {
                return _size == 0 ? 0 : 1; // If the other data is empty, compare based on current TString.
            }

            if (_size == 0) {
                return -1; // Current TString is empty, other is non-empty.
            }

            const size_t min = _size < dataLen ? _size : dataLen;
            const int32_t dV = Functions::cmp(_data, data, min);

            if (dV != 0) {
                return dV;
            }

            if (_size != dataLen) {
                return _size < dataLen ? -1 : 1;
            }

            return 0; // Both are equal.
        }

        /**
         * Compares the current TString with a raw character array, ignoring ASCII case; see
         * compareIgnoreCase(const SelfType&) and compare(const T*, limit) for the exact rules.
         * @param data The raw character array to compare with; may be null.
         * @param limit The maximum number of characters of data to consider. Defaults to
         * unlimited, i.e. data is treated as a full null-terminated string.
         * @return A negative value if the current TString is less than data, a positive value
         * if greater, 0 if equal (the same "sign only" contract as compare()).
         */
        inline int32_t compareIgnoreCase(const T* data, size_t limit = size_t(-1)) const {
            const size_t dataLen = Functions::countOf(data, limit);

            if (dataLen == 0) {
                return _size == 0 ? 0 : 1;
            }

            if (_size == 0) {
                return -1;
            }

            const size_t min = _size < dataLen ? _size : dataLen;
            const int32_t dV = Functions::caseCmp(_data, data, min);

            if (dV != 0) {
                return dV;
            }

            if (_size != dataLen) {
                return _size < dataLen ? -1 : 1;
            }

            return 0; // Both are equal.
        }

        /**
         * Checks if the current TString is equal to another TString.
         * @param other The other TString to compare with.
         * @return true if both TStrings are equal, false otherwise.
         */
        inline bool operator==(const SelfType& other) const {
            return compare(other) == 0;
        }

        /**
         * Checks if the current TString is not equal to another TString.
         * @param other The other TString to compare with.
         * @return true if both TStrings are not equal, false otherwise.
         */
        inline bool operator!=(const SelfType& other) const {
            return compare(other) != 0;
        }

        /**
         * Appends another TString to the current TString.
         * @param other The TString to append.
         * @return A reference to the current TString after appending.
         */
        inline SelfType& operator+=(const SelfType& other) {
            append(other);
            return *this;
        }

        /**
         * Appends a C-style string to the current TString.
         * @param data The C-style string to append.
         * @return A reference to the current TString after appending.
         */
        inline SelfType& operator+=(const T* data) {
            append(data);
            return *this;
        }

        /**
         * Converts the current TString to a TString of a different character type.
         * @tparam U The destination character type.
         * @return A TString of the destination character type.
         */
        template<typename U>
        inline TString<U> convertTo() const;
    };

    /**
     * Alias for TString<char>.
     */
    using CString = TString<char>;

    /**
     * Alias for TString<wchar_t>.
     */
    using CWideString = TString<wchar_t>;

    /**
     * A template class for converting strings between different character types.
     * @tparam TDest The destination character type.
     * @tparam TSrc The source character type.
     */
    template<typename TDest, typename TSrc>
    class TStringConverter {
    public:
        /**
         * Measures the length of the source string span.
         * @param src The source string span.
         * @return The length of the source string span.
         */
        inline size_t measure(const TReadOnlySpan<TSrc>& src) {
            return 0;   // --> not supported for generic types
        }

        /**
         * Converts a source string span to a destination string span.
         * @param dst The destination string span.
         * @param src The source string span.
         * @return The number of characters converted.
         */
        inline size_t convert(const TSpan<TDest>& dst, const TReadOnlySpan<TSrc>& src) {
            return 0;   // --> not supported for generic types
        }
    };

    /**
     * Specialization of TStringConverter for converting between the same character type.
     * Provides optimized methods for copying strings without any actual conversion.
     */
    template<typename TChar>
    class TStringConverter<TChar, TChar> {
    public:
        /**
         * Measures the length of the source string span.
         * @param src The source string span.
         * @return The length of the source string span.
         */
        inline size_t measure(const TReadOnlySpan<TChar>& src) {
            return src.size;
        }

        /**
         * Converts a source string span to a destination string span.
         * @param dst The destination string span.
         * @param src The source string span.
         * @return The number of characters converted.
         */
        inline size_t convert(const TSpan<TChar>& dst, const TReadOnlySpan<TChar>& src) {
            const size_t n = std::min(dst.size, src.size);
            std::memcpy(dst.data, src.data, n * sizeof(TChar));
            return n;
        }
    };

    /**
     * Specialization of TStringConverter for converting from char to wchar_t.
     * Provides methods for converting C-style strings and TString instances from char to wchar_t.
     */
    template<>
    class TStringConverter<wchar_t, char> {
    private:
        mbstate_t _state;

    public:
        /**
         * Constructor for TStringConverter<wchar_t, char>.
         * Initializes the conversion state.
         */
        TStringConverter() {
            std::memset(&_state, 0, sizeof(_state));
        }

    public:
        /**
         * Measures the length of the source string span.
         * @param src The source string span.
         * @return The length of the source string span, or 0 if src is empty or contains an
         * invalid multibyte sequence for the current locale.
         */
        inline size_t measure(const TReadOnlySpan<char>& src) {
            if (src.empty()) {
                return 0;
            }

            const char* srcPtr = &src[0];
            const size_t len = std::mbsrtowcs(nullptr, &srcPtr, 0, &_state);
            return len == static_cast<size_t>(-1) ? 0 : len;
        }

        /**
         * Converts a source string span to a destination string span.
         * @param dst The destination string span.
         * @param src The source string span.
         * @return The number of characters converted, or 0 if src is empty or contains an
         * invalid multibyte sequence for the current locale.
         */
        inline size_t convert(const TSpan<wchar_t>& dst, const TReadOnlySpan<char>& src) {
            if (src.empty()) {
                return 0;
            }

            const char* srcPtr = &src[0];
            const size_t n = std::mbsrtowcs(dst.data, &srcPtr, dst.size, &_state);
            return n == static_cast<size_t>(-1) ? 0 : n;
        }
    };

    /**
     * Specialization of TStringConverter for converting from wchar_t to char.
     * Provides methods for converting C-style strings and TString instances from wchar_t to char.
     */
    template<>
    class TStringConverter<char, wchar_t> {
    private:
        mbstate_t _state;

    public:
        TStringConverter() {
            std::memset(&_state, 0, sizeof(_state));
        }

    public:
        /**
         * Measures the length of the source string span.
         * @param src The source string span.
         * @return The length of the source string span, or 0 if src is empty or contains a
         * wide character that isn't representable in the current locale.
         */
        inline size_t measure(const TReadOnlySpan<wchar_t>& src) {
            if (src.empty()) {
                return 0;
            }

            const wchar_t* srcPtr = &src[0];
            const size_t len = std::wcsrtombs(nullptr, &srcPtr, 0, &_state);
            return len == static_cast<size_t>(-1) ? 0 : len;
        }

        /**
         * Converts a source string span to a destination string span.
         * @param dst The destination string span.
         * @param src The source string span.
         * @return The number of characters converted, or 0 if src is empty or contains a
         * wide character that isn't representable in the current locale.
         */
        inline size_t convert(const TSpan<char>& dst, const TReadOnlySpan<wchar_t>& src) {
            if (src.empty()) {
                return 0;
            }

            const wchar_t* srcPtr = &src[0];
            const size_t n = std::wcsrtombs(dst.data, &srcPtr, dst.size, &_state);
            return n == static_cast<size_t>(-1) ? 0 : n;
        }
    };
    
    /**
     * Template copy constructor for converting between different character types.
     * @tparam U The source character type.
     * @param cStr The TString instance of a different character type to copy from.
     */
    template<typename T>
    template<typename U>
    TString<T>::TString(const TString<U>& cStr) : _data(nullptr), _size(0), _capacity(0) {
        append(cStr.convertTo<T>());
    }

    /**
     * Appends the specified TString of a different character type to the current TString.
     * Returns the current instance.
     * @tparam U The character type of the TString to append.
     * @param other The TString to append.
     * @return The current instance after appending.
     */
    template<typename T>
    template<typename U>
    inline TString<T>& TString<T>::append(const TString<U>& other) {
        return append(other.convertTo<T>());
    }

    /**
     * Converts the current TString to a TString of a different character type.
     * @tparam U The destination character type.
     * @return A TString of the destination character type.
     */
    template<typename T>
    template<typename U>
    inline TString<U> TString<T>::convertTo() const {
        if (!_data || _size == 0) {
            return TString<U>();
        }
            
        // --> TStringConverter<TDest, TSrc>: converting FROM T TO U, so TDest=U, TSrc=T.
        TStringConverter<U, T> conv;
        TString<U> ret;

        TReadOnlySpan<T> src(_data, _size);
        const size_t len = conv.measure(src);

        // --> resize the return string to the required length.
        if (!len || !ret.resize(len)) {
            return TString<U>();
        }

        conv.convert(ret.toSpan(), src);
        return ret;
    }

    /**
     * Interface for string encoding conversions.
     * @tparam TChar The character type for this encoding.
     */
    template<typename TChar>
    class IStringEncoding {
    public:
        virtual ~IStringEncoding() = default;

    public:
        /**
         * Measures the number of bytes required to encode the source string span.
         * @param src The source string span.
         * @return The number of bytes required for encoding.
         */
        virtual size_t measure(const TReadOnlySpan<TChar>& src) = 0;

        /**
         * Encodes the source string span into the destination byte span.
         * @param dst The destination byte span.
         * @param src The source string span.
         * @return The number of bytes written to the destination span, or 0 if encoding fails.
         */
        virtual size_t encodeTo(const SByteSpan& dst, const TReadOnlySpan<TChar>& src) = 0;

        /**
         * Decodes the source byte span into the destination string span.
         * @param dst The destination string span.
         * @param src The source byte span.
         * @return The number of characters written to the destination span, or 0 if decoding fails.
         */
        virtual size_t decodeFrom(TSpan<TChar>& dst, const SReadOnlyByteSpan& src) = 0;
    };

    /**
     * Interface for C-style string encoding conversions.
     */
    template<typename TChar>
    class CERTPP_API TUtf8Encoding {
    public:
        /**
         * Retrieves the string encoding instance for the specified character type.
         * @return A reference to the string encoding instance.
         */
        static IStringEncoding<TChar>& get();
    };

    /**
     * Interface for ASCII string encoding conversions.
     */
    template<typename TChar>
    class CERTPP_API TAsciiEncoding {
    public:
        /**
         * Retrieves the string encoding instance for the specified character type.
         * @return A reference to the string encoding instance.
         */
        static IStringEncoding<TChar>& get();
    };

} // namespace certpp

#endif