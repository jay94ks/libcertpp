#include <certpp/name.hpp>
#include <cstring>

namespace certpp {

    /**
     * Keys corresponding to each name type.
     */
    const char* CName::TYPE_KEYS[ENAME_MAX] = {
        "",
        "CN",
        "OU",
        "O",
        "L",
        "ST",
        "C",
        "organizationIdentifier",
        "serialNumber",
        "title",
        "givenName",
        "surname",
        "pseudonym",
        "dnQualifier",
        "DC"
    };

    /**
     * Labels corresponding to each name type.
     */
    const char* CName::TYPE_LABELS[ENAME_MAX] = {
        "",
        "Common Name",
        "Organizational Unit",
        "Organization",
        "Locality",
        "State or Province",
        "Country",
        "Organization Identifier",
        "Serial Number",
        "Title",
        "Given Name",
        "Surname",
        "Pseudonym",
        "DN Qualifier",
        "Domain Component"
    };

    /**
     * DN attribute-type OBJECT IDENTIFIER arcs corresponding to each name type.
     */
    const CName::SAttributeOid CName::TYPE_OIDS[ENAME_MAX] = {
        {  0, { 0, 0, 0, 0 } },                                     // ENAME_NONE (unused)
        {  4, { 2, 5, 4, 3  } },                                    // ENAME_CN        -- commonName
        {  4, { 2, 5, 4, 11 } },                                    // ENAME_OU        -- organizationalUnitName
        {  4, { 2, 5, 4, 10 } },                                    // ENAME_O         -- organizationName
        {  4, { 2, 5, 4, 7  } },                                    // ENAME_L         -- localityName
        {  4, { 2, 5, 4, 8  } },                                    // ENAME_ST        -- stateOrProvinceName
        {  4, { 2, 5, 4, 6  } },                                    // ENAME_C         -- countryName
        {  4, { 2, 5, 4, 97 } },                                    // ENAME_OI        -- organizationIdentifier
        {  4, { 2, 5, 4, 5  } },                                    // ENAME_SERIAL    -- serialNumber
        {  4, { 2, 5, 4, 12 } },                                    // ENAME_TITLE     -- title
        {  4, { 2, 5, 4, 42 } },                                    // ENAME_GN        -- givenName
        {  4, { 2, 5, 4, 4  } },                                    // ENAME_SURNAME   -- surname
        {  4, { 2, 5, 4, 65 } },                                    // ENAME_PSEUDONYM -- pseudonym
        {  4, { 2, 5, 4, 46 } },                                    // ENAME_DNQ       -- dnQualifier
        /* --> domainComponent is 0.9.2342.19200300.100.1.25, which is 7 arcs. An earlier
         * version of this table claimed 10 and padded the end with zeros, so a DC encoded
         * here did not match the same DC decoded from a certificate, and a certificate's DC
         * would not have round-tripped through CName. The 7 is checked against the true OID
         * by tests/oid.cpp, which compares every DN entry this table holds. */
        {  7, { 0, 9, 2342, 19200300, 100, 1, 25 } },               // ENAME_DC        -- domainComponent
    };

    /* Retrieves the DN attribute-type OID arcs corresponding to a given name type. */
    bool CName::attributeOid(ENameType type, TSpan<uint32_t> outArcs, size_t& outArcCount) {
        outArcCount = 0;

        if (type <= ENAME_NONE || type >= ENAME_MAX) {
            return false;
        }

        const SAttributeOid& entry = TYPE_OIDS[type];
        if (!entry.count || outArcs.size < entry.count) {
            return false;
        }

        // --> memcpy rather than an element-wise loop: the arcs are a flat uint32_t block.
        std::memcpy(outArcs.data, entry.arcs, sizeof(uint32_t) * entry.count);

        outArcCount = entry.count;
        return true;
    }

    /* Retrieves the name type corresponding to a given DN attribute-type OID's arc values. */
    ENameType CName::attributeTypeOf(TReadOnlySpan<uint32_t> arcs) {
        if (!arcs.size || arcs.size > MAX_OID_ARCS) {
            return ENAME_NONE;
        }

        for (int i = 1; i < ENAME_MAX; ++i) {
            const SAttributeOid& entry = TYPE_OIDS[i];

            if (entry.count != arcs.size) {
                continue;
            }

            if (std::memcmp(arcs.data, entry.arcs, sizeof(uint32_t) * entry.count) == 0) {
                return ENameType(i);
            }
        }

        return ENAME_NONE;
    }

    /**
     * Resets the name component with the specified type and string data.
     * Frees any previously allocated memory and allocates new memory for the new data.
     */
    bool CName::reset(ENameType type, const char* str, size_t limit) {
        if (_data) {
            delete[] _data;
            _data = nullptr;
        }

        _len = 0;
        _hash = 0;
        _type = ENAME_NONE;

        // --> If the type is ENAME_NONE, no further processing is needed.
        if (type == ENAME_NONE) {
            return true;
        }

        // --> If the string is null or the limit is zero, the reset cannot proceed.
        if (!str || !limit) {
            return false;
        }

        // --> Calculate the length of the string up to the specified limit.
        size_t len = 0;
        size_t asciiLen = 0;

        while (len < limit) {
            if (str[len] == '\0') {
                break;
            }

            if (static_cast<unsigned char>(str[len]) > 127) {
                ++asciiLen;
            }

            ++len;
        }

        // --> If the calculated length is zero, the reset cannot proceed.
        if (len == 0) {
            return false;
        }

        const size_t fullLen = len + asciiLen;
        char* p = new char[fullLen + 1];
        if (!p) {
            return false;
        }
        
        // --> Reset the memory to zero before copying the new data.
        std::memset(p, 0, fullLen + 1);

        // --> Copy the string data to the newly allocated memory, escaping non-ASCII characters.
        size_t cursor = 0;
        uint16_t flags = 0;

        for (size_t i = 0; i < len; ++i) {
            const char cur = str[i];

            if (static_cast<unsigned char>(cur) > 127) {
                p[cursor++] = '\\';

                // --> Mark the name component as containing escaped non-ASCII characters.
                flags |= FLAG_ESCAPED;
            }

            p[cursor++] = cur;
        }

        _data = p;
        _len = cursor;

        // --> Compute the Djb hash for the new name component data.
        _hash = CDjb::computeAsLower(TReadOnlySpan<char>(_data, _len));
        _type = uint16_t(type) | flags;

        return true;            
    }

    /* Determines the type of the given key. */
    ENameType CName::typeOf(const char* key) {
        if (!key) {
            return ENAME_NONE;
        }

        using SFunc = TStringFunctions<char>;
        for (int i = 1; i < ENAME_MAX; ++i) {
            const size_t len = std::strlen(TYPE_KEYS[i]);

            // --> Compare the type key with the provided key, ignoring case -- len + 1 so the
            // table key's own NUL takes part, which is what makes this a whole-key match rather
            // than a prefix one. Comparing only len bytes let any key that merely *starts* with
            // a table entry resolve to it, so "organizationIdentifier" came back as ENAME_O.
            if (SFunc::caseCmp(TYPE_KEYS[i], key, len + 1) == 0) {
                return ENameType(i);
            }
        }

        return ENAME_NONE;
    }

    /* Compares the current name component with another name component. */
    int32_t CName::compare(const CName& other) const {
        if (type() != other.type()) {
            return int32_t(type()) - int32_t(other.type());
        }

        if (type() == ENAME_NONE) {
            return 0;
        }

        size_t min = (_len < other._len) ? _len : other._len;
        int32_t dV = TStringFunctions<char>::cmp(_data, other._data, min);

        if (dV != 0) {
            return dV;
        }

        return int32_t(_len) - int32_t(other._len);
    }

    /* Compares the current name component with another name component for equality. */
    bool CName::equals(const CName& other) const {
        if (type() != other.type() || _hash != other._hash || _len != other._len) {
            return false;
        }

        // --> If the type is ENAME_NONE, the name component is considered empty and equal to another empty component.
        if (type() == ENAME_NONE) {
            return true;
        }

        // --> Compare the actual data of the name components for equality.
        return TStringFunctions<char>::cmp(_data, other._data, _len) == 0;
    }

    /* Converts the name component to a string representation. */
    void CName::toString(CString& out, bool escaped) const {
        out.clear();

        if (empty()) {
            return;
        }

        if (escaped || !(_type & FLAG_ESCAPED)) {
            out.append(_data, _len);
            return;
        }

        // --> Handle escaped non-ASCII characters by skipping the escape character.
        const char* src = _data;
        const char* end = _data + _len;

        while (src < end && *src) {
            if (*src == '\\') {
                ++src; // --> Skip the escape marker; the escaped character itself follows it.
                continue;
            }

            out.append(src, 1);
            ++src;
        }
    }
    
    /**
     * Converts the name component to a wide string representation.
     */
    void CName::toString(CWideString& out, bool escaped) const {
        out.clear();

        if (empty()) {
            return;
        }

        if (escaped || !(_type & FLAG_ESCAPED)) {
            out.append(CString(_data, _len));
            return;
        }

        CWideString v (CString(_data, _len));
        for (size_t i = 0; i < v.size(); ++i) {
            if (v[i] == L'\\') {
                ++i; // --> Skip the escape marker; the escaped character itself follows it.

                if (i >= v.size()) {
                    break;
                }
            }

            out.append(v[i]);
        }
    }

    /* Attempts to parse a distinguished name from a string. */
    bool CDistinguishedName::tryParse(CDistinguishedName& out, const CString& s) {
        // --> initialize the output distinguished name to an empty state -- unconditionally, so
        // that every failure path (including an empty/null input) leaves out empty, not just the
        // ones reached after this point.
        out = CDistinguishedName();

        if (!s) {
            return false;
        }

        offset_t pos = 0;
        bool ret = true;

        while (pos >= 0) {
            offset_t comma = s.find(',', pos);

            const size_t start = pos;
            const size_t n = comma < 0 ? s.size() : comma;

            // --
            const CString comp = s.subString(start, n - start);
            const offset_t eq = comp.find('=');

            if (eq < 0) {
                // --> Invalid component format, missing '='.
                ret = false;
                break;
            }

            CString key = comp.subString(0, eq); // --> Extract the key part of the component.
            
            // --> Trim any leading and trailing whitespace from the key.
            if (key.trimSelf().size() <= 0) {
                // --> Invalid component format, empty key after trimming.
                ret = false;
                break;
            }

            ENameType type = CName::typeOf(key.toPtr());
            if (type == ENAME_NONE || type >= ENAME_MAX) {
                // --> Invalid component format, unrecognized or out-of-range key type.
                ret = false;
                break;
            }

            CString value = comp.subString(eq + 1); // --> Extract the value part of the component.
            value.trimSelf();

            CName name(type, value.toPtr());
            if (!out.trySet(name, true)) {
                // --> Failed to set the name component in the distinguished name.
                ret = false;
                break;
            }

            // --> move to next, or terminate the loop if this was the last component (comma < 0
            // means "no more commas found" -- without this, comma + 1 would wrap back to 0 and
            // the loop would reprocess the same (last) component forever).
            pos = comma < 0 ? -1 : comma + 1;
        }

        // --> clear the output distinguished name if parsing failed.
        if (ret == false) {
            out = CDistinguishedName();
        }

        return ret;
    }

    /* Attempts to parse a distinguished name from a wide string. */
    bool CDistinguishedName::tryParse(CDistinguishedName& out, const CWideString& s) {
        // --> initialize the output distinguished name to an empty state -- unconditionally; see
        // the narrow overload's comment for why this must happen before the empty/null check.
        out = CDistinguishedName();

        if (!s) {
            return false;
        }

        offset_t pos = 0;
        bool ret = true;

        while (pos >= 0) {
            offset_t comma = s.find(L',', pos);

            const size_t start = pos;
            const size_t n = comma < 0 ? s.size() : comma;

            // --
            const CWideString comp = s.subString(start, n - start);
            const offset_t eq = comp.find(L'=');

            if (eq < 0) {
                // --> Invalid component format, missing '='.
                ret = false;
                break;
            }

            CWideString key = comp.subString(0, eq); // --> Extract the key part of the component.

            // --> Trim any leading and trailing whitespace from the key.
            if (key.trimSelf().size() <= 0) {
                // --> Invalid component format, empty key after trimming.
                ret = false;
                break;
            }

            // --> typeOf() only understands narrow keys; the recognized keys ("CN", "OU", ...)
            // are themselves pure ASCII, so converting the (trimmed) key to narrow is lossless
            // for any key that could actually match.
            const CString narrowKey = key.convertTo<char>();
            ENameType type = CName::typeOf(narrowKey.toPtr());
            if (type == ENAME_NONE || type >= ENAME_MAX) {
                // --> Invalid component format, unrecognized or out-of-range key type.
                ret = false;
                break;
            }

            CWideString value = comp.subString(eq + 1); // --> Extract the value part of the component.
            value.trimSelf();

            // --> CName only stores narrow (possibly-escaped) bytes; convert through the same
            // locale-dependent path CName::toString(CWideString&, bool) uses in reverse.
            const CString narrowValue = value.convertTo<char>();
            CName name(type, narrowValue.toPtr(), narrowValue.size());
            if (!out.trySet(name, true)) {
                // --> Failed to set the name component in the distinguished name.
                ret = false;
                break;
            }

            // --> move to next, or terminate the loop if this was the last component.
            pos = comma < 0 ? -1 : comma + 1;
        }

        // --> clear the output distinguished name if parsing failed.
        if (ret == false) {
            out = CDistinguishedName();
        }

        return ret;
    }

    /* Attempts to set a name component in the distinguished name. */
    bool CDistinguishedName::trySet(const CName& value, bool overwrite) {
        ENameType type = value.type();

        if (has(type) && !overwrite) {
            return false;
        }

        // --> Set or overwrite the name component in the distinguished name.
        _components[type] = value;
        return true;
    }

    /* Attempts to retrieve a name component from the distinguished name. */
    bool CDistinguishedName::tryGet(ENameType type, CName& out) const {
        auto it = _components.find(type);
        if (it == _components.end()) {
            return false;
        }

        out = it->second;
        return true;
    }

    /* Compares the current distinguished name with another distinguished name. */
    int32_t CDistinguishedName::compare(const CDistinguishedName& other) const {
        if (empty()) {
            if (other.empty()) {
                return 0;
            }

            return 1;
        }

        if (other.empty()) {
            return -1;
        }

        // --
        uint32_t k1 = 0, k2 = 0;

        // --> Identify the keys present in the current distinguished name.
        for (const auto& [key, name] : _components) {
            k1 |= (1u << key);
        }

        // --> Identify the keys present in the other distinguished name.
        for (const auto& [key, name] : other._components) {
            k2 |= (1u << key);
        }

        // --> Compare the keys present in both distinguished names.
        uint32_t common = k1 & k2;
        for (uint32_t i = 0; i < ENAME_MAX; ++i) {
            if (!(common & (1 << i))) {
                continue;
            }
        
            CName left, right;
            tryGet(ENameType(i), left);
            other.tryGet(ENameType(i), right);

            // --
            int32_t dK = left.compare(right);
            if (dK != 0) {
                return dK;
            }
        }

        // --> Determine the remaining keys in both distinguished names.
        const uint32_t rk1 = k1 & ~common;
        const uint32_t rk2 = k2 & ~common;

        // --> Compare the remaining keys in both distinguished names.
        if (rk1 || rk2) {
            for (uint32_t i = 0; i < ENAME_MAX; ++i) {
                if (rk1 & (1u << i)) {
                    return 1;
                }

                if (rk2 & (1u << i)) {
                    return -1;
                }
            }
        }

        return 0;
    }

    /* Converts the distinguished name to a string representation. */
    void CDistinguishedName::toString(CString& out, bool escaped) const {
        out.clear();

        for (const auto& [key, name] : _components) {
            if (!out.empty()) {
                out.append(", ");
            }
            
            const char* keyStr = CName::keyOf(key);

            // --> Append the key and its corresponding name component to the output string.
            out.append(keyStr);
            out.append("=");

            CString nameStr;
            name.toString(nameStr, escaped);
            out.append(nameStr);
        }
    }

    /* Converts the distinguished name to a wide string representation. */
    void CDistinguishedName::toString(CWideString& out, bool escaped) const {
        out.clear();

        for (const auto& [key, name] : _components) {
            if (!out.empty()) {
                out.append(L", ");
            }
            
            CString keyStr = CName::keyOf(key);

            // --> Append the key and its corresponding name component to the output wide string.
            out.append(keyStr);
            out.append(L"=");

            CWideString nameStr;
            name.toString(nameStr, escaped);
            out.append(nameStr);
        }
    }
    
} // namespace certpp
