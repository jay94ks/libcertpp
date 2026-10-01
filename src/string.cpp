#include <certpp/string.hpp>
#include <cwchar>
#include <cstring>
#include <locale>
#include <codecvt>
#include <type_traits>

namespace certpp {

    /**
     * UTF-8 encoding implementation for narrow characters (char). char is treated as holding
     * text in the process's current locale encoding (matching TStringConverter<wchar_t, char>'s
     * convention elsewhere in this header), not as already being UTF-8 -- so this actually
     * transcodes native <-> UTF-8 via an intermediate wide representation, rather than just
     * copying bytes.
     *
     * Uses mbsrtowcs()/wcsrtombs() directly for the native <-> wide leg, the same primitives
     * TStringConverter<wchar_t, char> already relies on, rather than std::codecvt_byname: on
     * this toolchain, codecvt_byname("") resolves the OS's system codepage directly regardless
     * of a prior setlocale() call (confirmed by a locale-set-to-UTF8 test decoding as the system
     * ANSI codepage instead), and re-querying setlocale()'s current name and feeding it back
     * into codecvt_byname triggered an internal UCRT assertion in mbstowcs.cpp instead. Plain
     * mbsrtowcs()/wcsrtombs() were already verified correct for Korean/Japanese/Latin text under
     * a UTF-8 locale (see tests/string.cpp's TStringConverter tests).
     *
     * Like mbsrtowcs() itself, this requires src to be null-terminated at src.size (true for
     * any TString<char>'s own buffer, the realistic caller).
     */
    class Utf8EncodingForChar : public IStringEncoding<char> {
    private:
        /* Converts a null-terminated native-locale string to wide. Returns false on an invalid
         * multibyte sequence for the current locale. */
        static bool nativeToWide(const char* src, std::wstring& outWide) {
            std::mbstate_t state{};
            const char* srcPtr = src;
            size_t len = std::mbsrtowcs(nullptr, &srcPtr, 0, &state);
            if (len == static_cast<size_t>(-1)) {
                return false;
            }

            outWide.assign(len, L'\0');
            if (len) {
                std::memset(&state, 0, sizeof(state));
                srcPtr = src;
                std::mbsrtowcs(&outWide[0], &srcPtr, len, &state);
            }

            return true;
        }

        /* Converts a wide string to native-locale bytes. Returns false if wide contains a
         * character not representable in the current locale. */
        static bool wideToNative(const std::wstring& wide, std::string& outNative) {
            std::mbstate_t state{};
            const wchar_t* srcPtr = wide.c_str();
            size_t len = std::wcsrtombs(nullptr, &srcPtr, 0, &state);
            if (len == static_cast<size_t>(-1)) {
                return false;
            }

            outNative.assign(len, '\0');
            if (len) {
                std::memset(&state, 0, sizeof(state));
                srcPtr = wide.c_str();
                std::wcsrtombs(&outNative[0], &srcPtr, len, &state);
            }

            return true;
        }

    public:
        /**
         * Measures the number of bytes required to encode the source string span.
         * @param src The source string span.
         * @return The number of bytes required for encoding.
         */
        virtual size_t measure(const TReadOnlySpan<char>& src) override {
            if (src.empty()) {
                return 0;
            }

            std::wstring wide;
            if (!nativeToWide(&src[0], wide)) {
                return 0;
            }

            std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8Conv;
            return utf8Conv.to_bytes(wide).size();
        }

        /**
         * Encodes the source string span into the destination byte span.
         * @param dst The destination byte span.
         * @param src The source string span.
         * @return The number of bytes written to the destination span, or 0 if encoding fails.
         */
        virtual size_t encodeTo(const SByteSpan& dst, const TReadOnlySpan<char>& src) override {
            if (src.empty()) {
                return 0;
            }

            std::wstring wide;
            if (!nativeToWide(&src[0], wide)) {
                return 0;
            }

            std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8Conv;
            std::string bytes = utf8Conv.to_bytes(wide);

            auto min = std::min(bytes.size(), dst.size);
            if (min) {
                std::memcpy(dst.data, bytes.data(), min * sizeof(char));
            }

            return min;
        }

        /**
         * Decodes the source byte span into the destination string span.
         * @param dst The destination string span.
         * @param src The source byte span.
         * @return The number of characters written to the destination span, or 0 if decoding fails.
         */
        virtual size_t decodeFrom(TSpan<char>& dst, const SReadOnlyByteSpan& src) override {
            if (src.empty()) {
                return 0;
            }

            const char* srcStr = reinterpret_cast<const char*>(&src[0]);

            std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8Conv;
            std::wstring wide = utf8Conv.from_bytes(srcStr, srcStr + src.size);

            // --> Convert back to native-locale bytes (the destination's representation), not
            // a raw copy of the wide buffer -- dst is char-typed, wide is wchar_t-typed.
            std::string native;
            if (!wideToNative(wide, native)) {
                return 0;
            }

            auto min = std::min(native.size(), dst.size);
            if (min) {
                std::memcpy(dst.data, native.data(), min * sizeof(char));
            }

            return min;
        }
    };

    /**
     * UTF-8 encoding implementation for wide characters (wchar_t). Locale-independent: uses
     * std::codecvt_utf8<wchar_t> directly rather than a named locale.
     */
    class Utf8EncodingForWChar : public IStringEncoding<wchar_t> {
    public:
        virtual size_t measure(const TReadOnlySpan<wchar_t>& src) override {
            if (src.empty()) {
                return 0;
            }

            std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
            return conv.to_bytes(&src[0], &src[0] + src.size).size();
        }

        /**
         * Encodes the source wide string span into the destination byte span.
         * @param dst The destination byte span.
         * @param src The source wide string span.
         * @return The number of bytes written to the destination span, or 0 if encoding fails.
         */
        virtual size_t encodeTo(const SByteSpan& dst, const TReadOnlySpan<wchar_t>& src) override {
            if (src.empty()) {
                return 0;
            }

            std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;

            auto bytes = conv.to_bytes(&src[0], &src[0] + src.size);
            auto min = std::min(bytes.size(), dst.size);
            if (min) {
                std::memcpy(dst.data, &bytes[0], min * sizeof(char));
            }

            return min;
        }

        /**
         * Decodes the source byte span into the destination wide string span.
         * @param dst The destination wide string span.
         * @param src The source byte span.
         * @return The number of wide characters written to the destination span, or 0 if decoding fails.
         */
        virtual size_t decodeFrom(TSpan<wchar_t>& dst, const SReadOnlyByteSpan& src) override {
            if (src.empty()) {
                return 0;
            }

            const char* srcStr = reinterpret_cast<const char*>(&src[0]);

            std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
            std::wstring wide = conv.from_bytes(srcStr, srcStr + src.size);

            auto min = std::min(wide.size(), dst.size);
            if (min) {
                std::memcpy(dst.data, &wide[0], min * sizeof(wchar_t));
            }

            return min;
        }
    };

    /**
     * Retrieves the UTF-8 encoding instance for the specified character type.
     */
    template<>
    IStringEncoding<char>& TUtf8Encoding<char>::get() {
        static Utf8EncodingForChar instance;
        return instance;
    }

    /**
     * Retrieves the UTF-8 encoding instance for the specified character type.
     */
    template<>
    IStringEncoding<wchar_t>& TUtf8Encoding<wchar_t>::get() {
        static Utf8EncodingForWChar instance;
        return instance;
    }

    /**
     * ASCII encoding implementation for char.
     */
    class CAsciiEncodingForChar : public IStringEncoding<char> {
    private:
        /* True if value is in the 7-bit ASCII range (0-127). Deliberately not isascii(): that
         * (and every other <ctype.h> classification function) is only defined for arguments
         * representable as unsigned char or equal to EOF. */
        static inline bool isAsciiChar(char value) {
            return static_cast<unsigned char>(value) <= 127;
        }

    public:
        /**
         * Measures the number of bytes required to encode the source string span.
         * @param src The source string span.
         * @return The number of bytes required for encoding.
         */
        virtual size_t measure(const TReadOnlySpan<char>& src) override {
            return src.size;
        }

        /**
         * Encodes the source string span into the destination byte span.
         * @param dst The destination byte span.
         * @param src The source string span.
         * @return The number of bytes written to the destination span, or 0 if encoding fails.
         */
        virtual size_t encodeTo(const SByteSpan& dst, const TReadOnlySpan<char>& src) override {
            auto min = std::min(src.size, dst.size);
            if (min) {
                for (size_t i = 0; i < min; ++i) {
                    if (!isAsciiChar(src[i])) {
                        dst.data[i] = ' ';
                        continue;
                    }

                    dst.data[i] = static_cast<uint8_t>(src[i]);
                }
            }

            return min;
        }

        /**
         * Decodes the source byte span into the destination string span.
         * @param dst The destination string span.
         * @param src The source byte span.
         * @return The number of characters written to the destination span, or 0 if decoding fails.
         */
        virtual size_t decodeFrom(TSpan<char>& dst, const SReadOnlyByteSpan& src) override {
            auto min = std::min(src.size, dst.size);
            if (min) {
                for (size_t i = 0; i < min; ++i) {
                    if (!isAsciiChar(src.data[i])) {
                        dst[i] = ' ';
                        continue;
                    }

                    dst[i] = static_cast<char>(src.data[i]);
                }
            }

            return min;
        }
    };

    /**
     * ASCII encoding for wchar_t.
     */
    class CAsciiEncodingForWChar : public IStringEncoding<wchar_t> {
    private:
        /* True if value is in the 7-bit ASCII range (0-127), for wchar_t -- deliberately not
         * isascii(): wchar_t values routinely exceed 255 (e.g. Hiragana 0x3053), which is
         * undefined behavior for isascii() and can read out of bounds on CRT implementations
         * that index a lookup table directly by the argument. */
        static inline bool isAsciiChar(wchar_t value) {
            return static_cast<std::make_unsigned<wchar_t>::type>(value) <= 127;
        }

    public:
        /**
         * Measures the number of bytes required to encode the source wide string span.
         * @param src The source wide string span.
         * @return The number of bytes required for encoding.
         */
        virtual size_t measure(const TReadOnlySpan<wchar_t>& src) override {
            return src.size;
        }

        /**
         * Encodes the source wide string span into the destination byte span.
         * @param dst The destination byte span.
         * @param src The source wide string span.
         * @return The number of bytes written to the destination span, or 0 if encoding fails.
         */
        virtual size_t encodeTo(const SByteSpan& dst, const TReadOnlySpan<wchar_t>& src) override {
            auto min = std::min(src.size, dst.size);
            if (min) {
                for (size_t i = 0; i < min; ++i) {
                    if (!isAsciiChar(src[i])) {
                        dst.data[i] = ' ';
                        continue;
                    }

                    dst.data[i] = static_cast<uint8_t>(src[i]);
                }
            }

            return min;
        }

        /**
         * Decodes the source byte span into the destination wide string span.
         * @param dst The destination wide string span.
         * @param src The source byte span.
         * @return The number of wide characters written to the destination span, or 0 if decoding fails.
         */
        virtual size_t decodeFrom(TSpan<wchar_t>& dst, const SReadOnlyByteSpan& src) override {
            auto min = std::min(src.size, dst.size);
            if (min) {
                for (size_t i = 0; i < min; ++i) {
                    if (!isAsciiChar(src[i])) {
                        dst.data[i] = L' ';
                        continue;
                    }

                    dst.data[i] = static_cast<wchar_t>(src[i]);
                }
            }

            return min;
        }
    };

    template<>
    IStringEncoding<char>& TAsciiEncoding<char>::get() {
        static CAsciiEncodingForChar instance;
        return instance;
    }

    template<>
    IStringEncoding<wchar_t>& TAsciiEncoding<wchar_t>::get() {
        static CAsciiEncodingForWChar instance;
        return instance;
    }

}
