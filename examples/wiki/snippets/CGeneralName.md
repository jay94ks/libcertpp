The CHOICE every name-bearing extension uses, and which constructor to pick matters: a text alternative takes a CString, but iPAddress takes raw address octets (4 or 16 of them) through the COctet constructor -- handing dotted-quad text to the CString one would encode the text.

```cpp
// given: CSanExtensionBuilder& san, const COctet& addressOctets
san.addName(CGeneralName(EGNAME_DNS, CString("example.com")));
san.addName(CGeneralName(EGNAME_URI, CString("https://example.com/")));

if (addressOctets.size() != 4 && addressOctets.size() != 16) {
    return;
}
san.addName(CGeneralName(EGNAME_IP_ADDRESS, addressOctets));

IExtensionPtr ext = san.build();
if (!ext) {
    return; // one of the names above could not be encoded (non-ASCII in an IA5String, say)
}
// ext is a SubjectAlternativeName ready for CCertBuilder::extensions
```
