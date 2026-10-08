#include <certpp/utils/json.hpp>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

namespace certpp {
namespace utils {

    static bool isNumberToken(const std::string &token);

    static bool isJsonDigit(char ch) {
        return ch >= '0' && ch <= '9';
    }

    static void appendJsonString(std::string &out, const std::string &value) {
        static const char hex[] = "0123456789abcdef";
        out += '"';
        for (unsigned char ch : value) {
            switch (ch) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (ch < 0x20) {
                        out += "\\u00";
                        out += hex[ch >> 4];
                        out += hex[ch & 0x0f];
                    } else {
                        out += static_cast<char>(ch);
                    }
                    break;
            }
        }
        out += '"';
    }

    static void appendBsonUInt32(std::vector<uint8_t> &out, uint32_t value) {
        for (size_t i = 0; i < 4; ++i) {
            out.push_back(static_cast<uint8_t>(value >> (i * 8)));
        }
    }

    static void appendBsonUInt64(std::vector<uint8_t> &out, uint64_t value) {
        for (size_t i = 0; i < 8; ++i) {
            out.push_back(static_cast<uint8_t>(value >> (i * 8)));
        }
    }

    static bool readBsonUInt32(const uint8_t *data, size_t size, size_t offset,
                               uint32_t &value) {
        if (offset > size || size - offset < 4) {
            return false;
        }
        value = 0;
        for (size_t i = 0; i < 4; ++i) {
            value |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
        }
        return true;
    }

    static bool readBsonUInt64(const uint8_t *data, size_t size, size_t offset,
                               uint64_t &value) {
        if (offset > size || size - offset < 8) {
            return false;
        }
        value = 0;
        for (size_t i = 0; i < 8; ++i) {
            value |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
        }
        return true;
    }

    static bool readBsonCString(const uint8_t *data, size_t end, size_t &offset,
                                std::string &value) {
        if (offset > end) {
            return false;
        }

        size_t start = offset;
        while (offset < end && data[offset] != 0) {
            ++offset;
        }
        if (offset == end) {
            return false;
        }

        value.assign(reinterpret_cast<const char *>(data + start), offset - start);
        ++offset;
        return true;
    }

    static bool parseBsonDocument(const uint8_t *data, size_t size, bool asArray,
                                  size_t depth, CJsonPtr &value);

    /**
     * Represents a JSON boolean value.
     */
    class CJson::Bool : public CJson {
    private:
        bool _value; /**< The boolean value. */

    public:
        /**
         * Constructs a JSON boolean value.
         * @param value The boolean value.
         */
        Bool(bool value) : CJson(EJSON_BOOL), _value(value) {}

        /**
         * Returns the boolean value.
         * @return The boolean value.
         */
        inline bool value() const { return _value; }

        /**
         * Sets the boolean value.
         * @param value The new boolean value.
         */
        inline void value(bool value) { _value = value; }
    };

    /**
     * Represents a JSON string value.
     */
    class CJson::String : public CJson {
    private:
        std::string _value; /**< The string value. */

    public:
        /**
         * Constructs a JSON string value.
         * @param value The string value.
         */
        String(const std::string &value) : CJson(EJSON_STRING), _value(value) {}

        /**
         * Returns the string value.
         * @return The string value.
         */
        inline const std::string &value() const { return _value; }

        /**
         * Sets the string value.
         * @param value The new string value.
         */
        inline void value(const std::string &value) { _value = value; }
    };

    /**
     * Represents a JSON number value.
     */
    class CJson::Number : public CJson {
    private:
        double _value; /**< The number value. */

    public:
        /**
         * Constructs a JSON number value.
         * @param value The number value.
         */
        Number(double value) : CJson(EJSON_NUMBER), _value(value) {}

        /**
         * Returns the number value.
         * @return The number value.
         */
        inline double value() const { return _value; }

        /**
         * Sets the number value.
         * @param value The new number value.
         */
        inline void value(double value) { _value = value; }
    };

    /**
     * Represents a JSON array value.
     */
    class CJson::Array : public CJson {
    private:
        std::vector<CJsonPtr> _values; /**< The array values. */

    public:
        /**
         * Constructs a JSON array value.
         * @param values The array values.
         */
        Array(const std::vector<CJsonPtr> &values) : CJson(EJSON_ARRAY), _values(values) {}

        /**
         * Returns the array values.
         * @return The array values.
         */
        inline const std::vector<CJsonPtr> &value() const { return _values; }

        /**
         * Returns the array values (non-const version).
         * @return The array values.
         */
        inline std::vector<CJsonPtr> &value() { return _values; }
    };

    /**
     * Represents a JSON object value.
     */
    class CJson::Object : public CJson {
    private:
        std::map<std::string, CJsonPtr> _values; /**< The object values. */

    public:
        /**
         * Constructs a JSON object value.
         * @param values The object values.
         */
        Object(const std::map<std::string, CJsonPtr> &values) : CJson(EJSON_OBJECT), _values(values) {}

        /**
         * Returns the object values.
         * @return The object values.
         */
        inline const std::map<std::string, CJsonPtr> &value() const { return _values; }

        /**
         * Returns the object values (non-const version).
         * @return The object values.
         */
        inline std::map<std::string, CJsonPtr> &value() { return _values; }
    };


    /**
     * Wraps a boolean value into a JSON boolean value.
     */
    CJsonPtr CJson::wrap(bool value) {
        return std::make_shared<Bool>(value);
    }

    /**
     * Wraps a string value into a JSON string value.
     */
    CJsonPtr CJson::wrap(const std::string &value) {
        return std::make_shared<String>(value);
    }

    /**
     * Wraps a number value into a JSON number value.
     */
    CJsonPtr CJson::wrap(double value) {
        return std::make_shared<Number>(value);
    }

    /**
     * Creates a JSON array value.
     */
    CJsonPtr CJson::makeArray() {
        return std::make_shared<Array>(std::vector<CJsonPtr>{});
    }

    /**
     * Creates a JSON object value.
     */
    CJsonPtr CJson::makeObject() {
        return std::make_shared<Object>(std::map<std::string, CJsonPtr>{});
    }

    /**
     * Converts the JSON value to a boolean.
     */
    bool CJson::asBool(bool def) const {
        if (_type == EJSON_BOOL) {
            return static_cast<const Bool *>(this)->value();
        }

        if (_type == EJSON_NUMBER) {
            return static_cast<const Number *>(this)->value() != 0;
        }

        if (_type == EJSON_STRING) {
            return !static_cast<const String *>(this)->value().empty();
        }

        else if (_type == EJSON_NULL) {
            return false;
        }

        if (_type == EJSON_ARRAY) {
            return !static_cast<const Array *>(this)->value().empty();
        }

        if (_type == EJSON_OBJECT) {
            return !static_cast<const Object *>(this)->value().empty();
        }

        return def;
    }

    /**
     * Converts the JSON value to a number.
     */
    double CJson::asNumber(double def) const {
        if (_type == EJSON_NUMBER) {
            return static_cast<const Number *>(this)->value();
        }

        if (_type == EJSON_BOOL) {
            return static_cast<const Bool *>(this)->value() ? 1.0 : 0.0;
        }

        if (_type == EJSON_STRING) {
            const auto &str = static_cast<const String *>(this)->value();
            if (!isNumberToken(str)) {
                return def;
            }

            double number = 0;
            auto result = std::from_chars(str.data(), str.data() + str.size(),
                                          number, std::chars_format::general);
            if (result.ec != std::errc() || result.ptr != str.data() + str.size()) {
                return def;
            }
            return number;
        }

        if (_type == EJSON_NULL) {
            return 0.0;
        }

        return def;
    }

    /**
     * Converts the JSON value to a string.
     */
    std::string CJson::asString(const std::string &def) const {
        if (_type == EJSON_STRING) {
            return static_cast<const String *>(this)->value();
        }

        if (_type == EJSON_BOOL) {
            return static_cast<const Bool *>(this)->value() ? "true" : "false";
        }

        if (_type == EJSON_NUMBER) {
            return std::to_string(static_cast<const Number *>(this)->value());
        }

        if (_type == EJSON_NULL) {
            return "null";
        }

        if (_type == EJSON_ARRAY) {
            return "[array]";
        }

        if (_type == EJSON_OBJECT) {
            return "{object}";
        }

        return def;
    }

    /**
     * Retrieves the JSON value at the specified index in an array.
     */
    CJson::KeyedValue CJson::byIndex(size_t index) const {
        KeyedValue result;

        if (_type == EJSON_ARRAY) {
            const auto &arr = static_cast<const Array *>(this)->value();
            if (index < arr.size()) {
                result.key = std::to_string(index);
                result.value = arr[index];
            }
        }

        else if (_type == EJSON_OBJECT) {
            const auto &obj = static_cast<const Object *>(this)->value();

            // --> Attempt to find the object element with the key corresponding to the index.
            auto it = obj.find(std::to_string(index));
            if (it != obj.end()) {
                result.key = it->first;
                result.value = it->second;
            }
        }

        return result;
    }

    /**
     * Retrieves the JSON value associated with the specified key in an object.
     */
    CJson::KeyedValue CJson::byKey(const std::string &key) const {
        KeyedValue result;

        if (_type == EJSON_OBJECT) {
            const auto &obj = static_cast<const Object *>(this)->value();
            auto it = obj.find(key);
            if (it != obj.end()) {
                result.key = it->first;
                result.value = it->second;
            }
        }

        return result;
    }

    /**
     * Sets the JSON value at the specified index in an array.
     */
    bool CJson::byIndex(size_t index, CJsonPtr value) {
        if (_type == EJSON_ARRAY) {
            auto &arr = static_cast<Array *>(this)->value();
            if (index < arr.size()) {
                arr[index] = value;
                return true;
            }
        }

        else if (_type == EJSON_OBJECT) {
            auto &obj = static_cast<Object *>(this)->value();
            auto it = obj.find(std::to_string(index));
            if (it != obj.end()) {
                it->second = value;
                return true;
            }

            // --> If the key corresponding to the index does not exist, add it to the object.
            obj[std::to_string(index)] = value;
            return true;
        }

        return false;
    }

    /**
     * Sets the JSON value associated with the specified key in an object.
     */
    bool CJson::byKey(const std::string &key, CJsonPtr value) {
        if (_type == EJSON_OBJECT) {
            auto &obj = static_cast<Object *>(this)->value();
            obj[key] = value;
            return true;
        }

        else if (_type == EJSON_ARRAY) {
            // --> If the key is a numeric string, attempt to convert it to an index and set the corresponding array element.
            try {
                size_t index = std::stoul(key);
                auto &arr = static_cast<Array *>(this)->value();

                // --> Check if the index is within the bounds of the array.
                if (index < arr.size()) {
                    arr[index] = value;
                    return true;
                }

                else if (index == arr.size()) {
                    arr.push_back(value);
                    return true;
                }
            } catch (const std::exception &) {
                // --> If the key is not a valid numeric string, do nothing.
            }
        }

        return false;
    }

    /**
     * Converts the JSON value to its string representation.
     */
    std::string CJson::toString(size_t maxDepth) const {
        if (maxDepth == 0) {
            return "null";
        }

        std::string buf;
        switch (_type) {
            case EJSON_NULL:
                buf = "null";
                break;

            case EJSON_BOOL:
                buf = asBool() ? "true" : "false";
                break;

            case EJSON_NUMBER:
            {
                double number = asNumber();
                if (!std::isfinite(number)) {
                    buf = "null";
                    break;
                }
                char numberBuffer[64];
                auto result = std::to_chars(numberBuffer, numberBuffer + sizeof(numberBuffer),
                                             number, std::chars_format::general,
                                             std::numeric_limits<double>::max_digits10);
                if (result.ec != std::errc()) {
                    return "";
                }
                buf.assign(numberBuffer, result.ptr);
                break;
            }

            case EJSON_STRING: {
                appendJsonString(buf, asString());
                break;
            }

            case EJSON_ARRAY: {
                const auto &arr = static_cast<const Array *>(this)->value();
                buf = "[";

                for (size_t i = 0; i < arr.size(); ++i) {
                    if (i > 0) {
                        buf += ", ";
                    }

                    buf += arr[i] ? arr[i]->toString(maxDepth - 1) : "null";
                }

                buf += "]";
                break;
            }

            case EJSON_OBJECT: {
                const auto &obj = static_cast<const Object *>(this)->value();
                buf = "{";

                size_t count = 0;
                for (const auto &pair : obj) {
                    if (count++ > 0) {
                        buf += ", ";
                    }

                    appendJsonString(buf, pair.first);
                    buf += ": ";
                    buf += pair.second ? pair.second->toString(maxDepth - 1) : "null";
                }

                buf += "}";
                break;
            }

            default:
                break;
        }

        return buf;
    }

    /* Appends one BSON element, using a BSON document for nested containers. */
    bool CJson::appendBsonElement(std::vector<uint8_t> &out, const std::string &key,
                                  const CJsonPtr &value, size_t depth) {
        if (key.find('\0') != std::string::npos) {
            return false;
        }

        EJsonType type = value ? value->type() : EJSON_NULL;
        uint8_t bsonType;
        switch (type) {
            case EJSON_NULL: bsonType = 0x0a; break;
            case EJSON_BOOL: bsonType = 0x08; break;
            case EJSON_NUMBER: bsonType = 0x01; break;
            case EJSON_STRING: bsonType = 0x02; break;
            case EJSON_ARRAY: bsonType = 0x04; break;
            case EJSON_OBJECT: bsonType = 0x03; break;
            default: return false;
        }

        out.push_back(bsonType);
        out.insert(out.end(), key.begin(), key.end());
        out.push_back(0);

        if (!value || type == EJSON_NULL) {
            return true;
        }

        if (type == EJSON_BOOL) {
            out.push_back(value->asBool() ? 1 : 0);
            return true;
        }

        if (type == EJSON_NUMBER) {
            double number = value->asNumber();
            uint64_t bits;
            std::memcpy(&bits, &number, sizeof(bits));
            appendBsonUInt64(out, bits);
            return true;
        }

        if (type == EJSON_STRING) {
            const std::string text = value->asString();
            if (text.size() >= static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
                return false;
            }
            appendBsonUInt32(out, static_cast<uint32_t>(text.size() + 1));
            out.insert(out.end(), text.begin(), text.end());
            out.push_back(0);
            return true;
        }

        return value->appendBsonDocument(out, depth + 1);
    }

    /* Appends a BSON document for this object or array. */
    bool CJson::appendBsonDocument(std::vector<uint8_t> &out, size_t depth) const {
        static constexpr size_t MAX_BSON_DEPTH = 100;
        if (depth > MAX_BSON_DEPTH ||
            (_type != EJSON_OBJECT && _type != EJSON_ARRAY)) {
            return false;
        }

        size_t lengthOffset = out.size();
        appendBsonUInt32(out, 0);

        if (_type == EJSON_OBJECT) {
            const auto &object = static_cast<const Object *>(this)->value();
            for (const auto &entry : object) {
                if (!appendBsonElement(out, entry.first, entry.second, depth)) {
                    return false;
                }
            }
        } else {
            const auto &array = static_cast<const Array *>(this)->value();
            for (size_t i = 0; i < array.size(); ++i) {
                if (!appendBsonElement(out, std::to_string(i), array[i], depth)) {
                    return false;
                }
            }
        }

        out.push_back(0);
        size_t documentLength = out.size() - lengthOffset;
        if (documentLength > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
            return false;
        }
        uint32_t length = static_cast<uint32_t>(documentLength);
        for (size_t i = 0; i < 4; ++i) {
            out[lengthOffset + i] = static_cast<uint8_t>(length >> (i * 8));
        }
        return true;
    }

    /**
     * Converts the JSON value to its BSON representation.
     */
    bool CJson::toBson(CBuffer &buffer) const {
        if (_type != EJSON_OBJECT && _type != EJSON_ARRAY) {
            return false;
        }

        try {
            std::vector<uint8_t> encoded;
            if (!appendBsonDocument(encoded, 0)) {
                return false;
            }
            return buffer.store(encoded.data(), encoded.size());
        } catch (const std::bad_alloc &) {
            return false;
        }
    }

    /**
     * Tokenizes a JSON string into individual tokens.
     * @param json The JSON string to tokenize.
     * @param tokens A vector to store the resulting tokens.
     * @return True if tokenization is successful, false otherwise.
     */
    bool tokenizeJson(const std::string &json, std::vector<std::string> &tokens) {
        std::string_view sv(json);

        std::string buf;
        char quato = '\0';
        bool escape = false;

        for (char ch: sv) {
            if (quato) {
                if (escape) {
                    escape = false;
                    buf += ch;
                    continue;
                }

                if (ch == '\\') {
                    escape = true;
                    buf += ch;
                    continue;
                }

                if (ch == quato) {
                    quato = '\0';
                    buf += ch;

                    tokens.push_back(buf);
                    buf.clear();
                    continue;
                }

                buf += ch;
                continue;
            }

            if (ch == '"') {
                quato = ch;
                buf += ch;
                continue;
            }

            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
                if (!buf.empty()) {
                    tokens.push_back(buf);
                    buf.clear();
                }
                continue;
            }

            if (ch == ',' || ch == ':' || ch == '{' || ch == '}' || ch == '[' || ch == ']') {
                if (!buf.empty()) {
                    tokens.push_back(buf);
                    buf.clear();
                }

                tokens.push_back(std::string(1, ch));
                continue;
            }

            buf += ch;
        }

        if (quato != '\0' || escape) {
            return false;
        }

        if (!buf.empty()) {
            tokens.push_back(buf);
        }

        return !tokens.empty();
    }

    /**
     * Converts a single JSON token into a JSON value.
     * @param token The JSON token to convert.
     * @return A shared pointer to the resulting JSON value, or nullptr if conversion fails.
     */
    static bool parseJsonHex4(const std::string &token, size_t pos, unsigned int &codepoint) {
        if (pos + 3 >= token.size() - 1) {
            return false;
        }

        codepoint = 0;
        for (size_t i = 0; i < 4; ++i) {
            char ch = token[pos + i];
            codepoint <<= 4;
            if (ch >= '0' && ch <= '9') {
                codepoint |= static_cast<unsigned int>(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                codepoint |= static_cast<unsigned int>(ch - 'a' + 10);
            } else if (ch >= 'A' && ch <= 'F') {
                codepoint |= static_cast<unsigned int>(ch - 'A' + 10);
            } else {
                return false;
            }
        }
        return true;
    }

    static void appendJsonUtf8(std::string &out, unsigned int codepoint) {
        if (codepoint <= 0x7f) {
            out += static_cast<char>(codepoint);
        } else if (codepoint <= 0x7ff) {
            out += static_cast<char>(0xc0 | (codepoint >> 6));
            out += static_cast<char>(0x80 | (codepoint & 0x3f));
        } else if (codepoint <= 0xffff) {
            out += static_cast<char>(0xe0 | (codepoint >> 12));
            out += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (codepoint & 0x3f));
        } else {
            out += static_cast<char>(0xf0 | (codepoint >> 18));
            out += static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f));
            out += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (codepoint & 0x3f));
        }
    }

    CJsonPtr parseStringToken(const std::string &token) {
        if (token.size() < 2 || token.front() != '"' || token.back() != '"') {
            return nullptr;
        }

        std::string buf;

        for (size_t i = 1; i + 1 < token.size(); ++i) {
            char ch = token[i];
            if (ch == '\\') {
                if (++i + 1 >= token.size()) {
                    return nullptr;
                }
                switch (token[i]) {
                    case '"': buf += '"'; break;
                    case '\'': buf += '\''; break;
                    case '/': buf += '/'; break;
                    case '\\': buf += '\\'; break;
                    case 'b': buf += '\b'; break;
                    case 'f': buf += '\f'; break;
                    case 'n': buf += '\n'; break;
                    case 'r': buf += '\r'; break;
                    case 't': buf += '\t'; break;
                    case 'u': {
                        unsigned int codepoint;
                        if (!parseJsonHex4(token, i + 1, codepoint)) {
                            return nullptr;
                        }
                        i += 4;

                        if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                            if (i + 6 >= token.size() - 1 ||
                                token[i + 1] != '\\' || token[i + 2] != 'u') {
                                return nullptr;
                            }
                            unsigned int lowSurrogate;
                            if (!parseJsonHex4(token, i + 3, lowSurrogate) ||
                                lowSurrogate < 0xdc00 || lowSurrogate > 0xdfff) {
                                return nullptr;
                            }
                            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) +
                                        (lowSurrogate - 0xdc00);
                            i += 6;
                        } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
                            return nullptr;
                        }

                        appendJsonUtf8(buf, codepoint);
                        break;
                    }
                    default:
                        return nullptr;
                }
                continue;
            }

            if (static_cast<unsigned char>(ch) < 0x20) {
                return nullptr;
            }
            buf += ch;
        }

        return CJson::wrap(buf);
    }

    /**
     * Checks if a given token represents a number.
     * @param token The token to check.
     * @return True if the token represents a number, false otherwise.
     */
    static bool isNumberToken(const std::string &token) {
        if (token.empty()) {
            return false;
        }

        size_t i = 0;
        if (token[i] == '-') {
            ++i;
        }

        if (i == token.size()) {
            return false;
        }

        if (token[i] == '0') {
            ++i;
            if (i < token.size() && isJsonDigit(token[i])) {
                return false;
            }
        } else {
            if (token[i] < '1' || token[i] > '9') {
                return false;
            }
            while (i < token.size() && isJsonDigit(token[i])) {
                ++i;
            }
        }

        if (i < token.size() && token[i] == '.') {
            ++i;
            size_t fractionStart = i;
            while (i < token.size() && isJsonDigit(token[i])) {
                ++i;
            }
            if (i == fractionStart) {
                return false;
            }
        }

        if (i < token.size() && (token[i] == 'e' || token[i] == 'E')) {
            ++i;
            if (i < token.size() && (token[i] == '+' || token[i] == '-')) {
                ++i;
            }
            size_t exponentStart = i;
            while (i < token.size() && isJsonDigit(token[i])) {
                ++i;
            }
            if (i == exponentStart) {
                return false;
            }
        }

        return i == token.size();
    }

    /* Parses one value from the token stream, advancing index on success. */
    static bool parseJsonValue(const std::vector<std::string> &tokens, size_t &index,
                               CJsonPtr &value) {
        if (index >= tokens.size()) {
            return false;
        }

        const std::string &token = tokens[index++];
        if (token == "{") {
            value = CJson::makeObject();
            if (index < tokens.size() && tokens[index] == "}") {
                ++index;
                return true;
            }

            while (index < tokens.size()) {
                const std::string &keyToken = tokens[index++];
                if (keyToken.size() < 2 ||
                    keyToken.front() != '"' ||
                    keyToken.back() != keyToken.front()) {
                    return false;
                }

                CJsonPtr key = parseStringToken(keyToken);
                if (!key || index >= tokens.size() || tokens[index++] != ":") {
                    return false;
                }

                CJsonPtr member;
                if (!parseJsonValue(tokens, index, member) ||
                    !value->byKey(key->asString(), member)) {
                    return false;
                }

                if (index >= tokens.size()) {
                    return false;
                }
                if (tokens[index] == "}") {
                    ++index;
                    return true;
                }
                if (tokens[index++] != ",") {
                    return false;
                }
            }
            return false;
        }

        if (token == "[") {
            value = CJson::makeArray();
            if (index < tokens.size() && tokens[index] == "]") {
                ++index;
                return true;
            }

            size_t itemIndex = 0;
            while (index < tokens.size()) {
                CJsonPtr item;
                if (!parseJsonValue(tokens, index, item) ||
                    !value->byKey(std::to_string(itemIndex++), item)) {
                    return false;
                }

                if (index >= tokens.size()) {
                    return false;
                }
                if (tokens[index] == "]") {
                    ++index;
                    return true;
                }
                if (tokens[index++] != ",") {
                    return false;
                }
            }
            return false;
        }

        if (token.size() >= 2 &&
            token.front() == '"' &&
            token.back() == token.front()) {
            value = parseStringToken(token);
            return value != nullptr;
        }

        if (token == "true" || token == "false") {
            value = CJson::wrap(token == "true");
            return true;
        }

        if (token == "null") {
            value = std::make_shared<CJson>();
            return true;
        }

        if (isNumberToken(token)) {
            double number = 0;
            auto result = std::from_chars(token.data(), token.data() + token.size(),
                                          number, std::chars_format::general);
            if (result.ec != std::errc() || result.ptr != token.data() + token.size()) {
                return false;
            }
            value = CJson::wrap(number);
            return true;
        }

        return false;
    }

    static bool parseBsonDocument(const uint8_t *data, size_t size, bool asArray,
                                  size_t depth, CJsonPtr &value) {
        static constexpr size_t MAX_BSON_DEPTH = 100;
        if (!data || size < 5 ||
            size > static_cast<size_t>(std::numeric_limits<int32_t>::max()) ||
            depth > MAX_BSON_DEPTH) {
            return false;
        }

        uint32_t declaredLength;
        if (!readBsonUInt32(data, size, 0, declaredLength) ||
            declaredLength != size || data[size - 1] != 0) {
            return false;
        }

        value = asArray ? CJson::makeArray() : CJson::makeObject();
        size_t offset = 4;
        const size_t contentEnd = size - 1;
        size_t arrayIndex = 0;

        while (offset < contentEnd) {
            uint8_t bsonType = data[offset++];
            std::string key;
            if (bsonType == 0 || !readBsonCString(data, contentEnd, offset, key)) {
                return false;
            }

            if (asArray && key != std::to_string(arrayIndex)) {
                return false;
            }
            if (!asArray && value->byKey(key).value) {
                return false;
            }

            CJsonPtr element;
            switch (bsonType) {
                case 0x01: {
                    uint64_t bits;
                    if (!readBsonUInt64(data, contentEnd, offset, bits)) {
                        return false;
                    }
                    double number;
                    std::memcpy(&number, &bits, sizeof(number));
                    element = CJson::wrap(number);
                    offset += 8;
                    break;
                }

                case 0x02: {
                    uint32_t textLength;
                    if (!readBsonUInt32(data, contentEnd, offset, textLength) ||
                        textLength == 0 || textLength > contentEnd - offset - 4) {
                        return false;
                    }
                    size_t textOffset = offset + 4;
                    if (data[textOffset + textLength - 1] != 0) {
                        return false;
                    }
                    element = CJson::wrap(std::string(
                        reinterpret_cast<const char *>(data + textOffset), textLength - 1));
                    offset = textOffset + textLength;
                    break;
                }

                case 0x03:
                case 0x04: {
                    uint32_t nestedLength;
                    if (!readBsonUInt32(data, contentEnd, offset, nestedLength) ||
                        nestedLength < 5 || nestedLength > contentEnd - offset) {
                        return false;
                    }
                    bool nestedIsArray = bsonType == 0x04;
                    if (!parseBsonDocument(data + offset, nestedLength, nestedIsArray,
                                           depth + 1, element)) {
                        return false;
                    }
                    offset += nestedLength;
                    break;
                }

                case 0x08:
                    if (offset >= contentEnd || data[offset] > 1) {
                        return false;
                    }
                    element = CJson::wrap(data[offset++] != 0);
                    break;

                case 0x0a:
                    element = std::make_shared<CJson>();
                    break;

                case 0x10: {
                    uint32_t bits;
                    if (!readBsonUInt32(data, contentEnd, offset, bits)) {
                        return false;
                    }
                    int32_t number;
                    std::memcpy(&number, &bits, sizeof(number));
                    element = CJson::wrap(static_cast<double>(number));
                    offset += 4;
                    break;
                }

                case 0x12: {
                    uint64_t bits;
                    if (!readBsonUInt64(data, contentEnd, offset, bits)) {
                        return false;
                    }
                    int64_t number;
                    std::memcpy(&number, &bits, sizeof(number));
                    element = CJson::wrap(static_cast<double>(number));
                    offset += 8;
                    break;
                }

                default:
                    return false;
            }

            if (asArray) {
                if (!value->byKey(std::to_string(arrayIndex++), element)) {
                    return false;
                }
            } else if (!value->byKey(key, element)) {
                return false;
            }
        }

        return offset == contentEnd;
    }

    /**
     * Parses a JSON string and returns a shared pointer to the resulting JSON value.
     * @param json The JSON string to parse.
     * @return A shared pointer to the parsed JSON value, or nullptr if parsing fails.
     */
    CERTPP_API CJsonPtr parseJson(const std::string &json) {
        std::vector<std::string> tokens;

        // --> Tokenize the JSON string into individual tokens.
        if (!tokenizeJson(json, tokens)) {
            return nullptr;
        }

        size_t index = 0;
        CJsonPtr result;
        if (!parseJsonValue(tokens, index, result) || index != tokens.size()) {
            return nullptr;
        }
        return result;
    }

    /**
     * Parses a BSON byte span and returns a shared pointer to the resulting JSON value.
     */
    CERTPP_API CJsonPtr parseBson(const SByteSpan &span, bool asArray) {
        if (!span.data || span.size < 5) {
            return nullptr;
        }

        try {
            CJsonPtr result;
            if (!parseBsonDocument(span.data, span.size, asArray, 0, result)) {
                return nullptr;
            }
            return result;
        } catch (const std::bad_alloc &) {
            return nullptr;
        }
    }

} // namespace utils
} // namespace certpp