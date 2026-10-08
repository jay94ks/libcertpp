#ifndef __INCLUDE_CERTPP_UTILS_JSON_HPP__
#define __INCLUDE_CERTPP_UTILS_JSON_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/buffer.hpp>

namespace certpp {
namespace utils {

    /**
     * Represents the type of a JSON value.
     */
    enum EJsonType {
        EJSON_NULL = 0, /**< Represents a JSON null value. */
        EJSON_BOOL,     /**< Represents a JSON boolean value. */
        EJSON_NUMBER,   /**< Represents a JSON number value. */
        EJSON_STRING,   /**< Represents a JSON string value. */
        EJSON_ARRAY,    /**< Represents a JSON array value. */
        EJSON_OBJECT,   /**< Represents a JSON object value. */
    };

    /* Forward declaration of the JSON value class. */
    class CJson;

    /**
     * Defines a shared pointer type for the JSON value class.
     */
    using CJsonPtr = std::shared_ptr<CJson>;

    /**
     * Represents the base structure for a JSON value.
     */
    class CERTPP_API CJson {
    private:
        EJsonType _type; /**< The type of the JSON value. */

    private:
        class Bool;
        class String;
        class Number;
        class Array;
        class Object;
        bool appendBsonDocument(std::vector<uint8_t> &out, size_t depth) const;
        static bool appendBsonElement(std::vector<uint8_t> &out, const std::string &key,
                                      const CJsonPtr &value, size_t depth);

    public:
        /**
         * Wraps a boolean value into a JSON boolean value.
         * @param value The boolean value.
         * @return A shared pointer to the JSON boolean value.
         */
        static CJsonPtr wrap(bool value);

        /**
         * Wraps a string value into a JSON string value.
         * @param value The string value.
         * @return A shared pointer to the JSON string value.
         */
        static CJsonPtr wrap(const std::string &value);

        /**
         * Wraps a number value into a JSON number value.
         * @param value The number value.
         * @return A shared pointer to the JSON number value.
         */
        static CJsonPtr wrap(double value);

        /**
         * Creates a JSON array value.
         * @return A shared pointer to the JSON array value.
         */
        static CJsonPtr makeArray();

        /**
         * Creates a JSON object value.
         * @return A shared pointer to the JSON object value.
         */
        static CJsonPtr makeObject();

    public:
        /**
         * Constructs a JSON value base with the specified type.
         * @param type The type of the JSON value.
         */
        CJson(EJsonType type = EJSON_NULL) : _type(type) {}

        /**
         * Destroys the JSON value base.
         */
        virtual ~CJson() = default;

        /**
         * Returns the type of the JSON value.
         * @return The type of the JSON value.
         */
        EJsonType type() const { return _type; }

        /**
         * Checks if the JSON value is null.
         * @return True if the JSON value is null, false otherwise.
         */
        inline bool isNull() const { return _type == EJSON_NULL; }

        /**
         * Converts the JSON value to a boolean.
         * @param def The default value to return if the JSON value cannot be converted to a boolean.
         * @return The boolean representation of the JSON value.
         */
        bool asBool(bool def = false) const;

        /**
         * Converts the JSON value to a number.
         * @param def The default value to return if the JSON value cannot be converted to a number.
         * @return The numeric representation of the JSON value.
         */
        double asNumber(double def = 0.0) const;

        /**
         * Converts the JSON value to a string.
         * @param def The default value to return if the JSON value cannot be converted to a string.
         * @return The string representation of the JSON value.
         */
        std::string asString(const std::string &def = "") const;

        /**
         * Represents a key-value pair retrieved from a JSON array or object.
         */
        struct KeyedValue {
            std::string key;
            CJsonPtr value;
        };

        /**
         * Retrieves the JSON value at the specified index in an array.
         * @param index The index of the element to retrieve.
         * @return A shared pointer to the JSON value at the specified index, or nullptr if the index is out of bounds or the value is not an array.
         */
        KeyedValue byIndex(size_t index) const;

        /**
         * Retrieves the JSON value associated with the specified key in an object.
         * @param key The key of the element to retrieve.
         * @return A shared pointer to the JSON value associated with the specified key, or nullptr if the key does not exist or the value is not an object.
         */
        KeyedValue byKey(const std::string &key) const;

        /**
         * Sets the JSON value at the specified index in an array.
         * @param index The index of the element to set.
         * @param value The JSON value to set at the specified index.
         * @return True if the value was successfully set, false otherwise.
         */
        bool byIndex(size_t index, CJsonPtr value);

        /**
         * Sets the JSON value associated with the specified key in an object.
         * @param key The key of the element to set.
         * @param value The JSON value to associate with the key.
         * @return True if the value was successfully set, false otherwise.
         */
        bool byKey(const std::string &key, CJsonPtr value);

        /**
         * Converts the JSON value to its string representation.
         * @return The string representation of the JSON value.
         */
        std::string toString(size_t maxDepth = 10) const;

        /**
         * Converts the JSON value to its BSON representation.
         * @param buffer The buffer to store the BSON representation.
         * @return True if an object or array was encoded successfully, false otherwise. BSON documents cannot have a scalar root.
         */
        bool toBson(CBuffer& buffer) const;
    };

    /**
     * Parses a JSON string and returns a shared pointer to the resulting JSON value.
     * @param json The JSON string to parse.
     * @return A shared pointer to the parsed JSON value, or nullptr if parsing fails.
     */
    CERTPP_API CJsonPtr parseJson(const std::string &json);

    /**
     * Parses a BSON byte span and returns a shared pointer to the resulting JSON value.
     * @param span The BSON byte span to parse.
     * @param asArray Whether to interpret the BSON data as an array.
     * @return A shared pointer to the parsed JSON value, or nullptr if parsing fails or the BSON contains an unsupported type.
     */
    CERTPP_API CJsonPtr parseBson(const SByteSpan& span, bool asArray = false);

} // namespace utils
} // namespace certpp

#endif