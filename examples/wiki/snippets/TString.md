CString is the alias a caller names (CWideString for wchar_t). size() excludes the terminator, find() returns an offset_t that is negative when there is no match, and the growing calls report allocation failure with a bool.

```cpp
// given: const CString& subject
CString line("CN=");
line.append(subject);

const offset_t eq = line.find('=');
if (eq < 0) {
    return;
}

CString value = line.subString(static_cast<size_t>(eq) + 1);
if (value.empty()) {
    return;
}

if (value.compareIgnoreCase(value.toUpper()) != 0) {
    return;
}

// convertTo() transcodes through TStringConverter rather than truncating each unit.
CWideString wide = value.convertTo<wchar_t>();
if (wide.empty()) {
    return;
}
```
