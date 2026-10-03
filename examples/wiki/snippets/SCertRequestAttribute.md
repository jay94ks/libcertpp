One PKCS#10 attribute, with `values` meaning the same bytes in both directions -- the content octets of the attribute's values SET, without that SET's own tag and length -- so an attribute read off one request goes straight into a builder for another.

```cpp
// given: const CCertRequest& request, CCertRequestBuilder& builder
for (const SCertRequestAttribute& attr : request.attributes()) {
    if (attr.oid == CString(CCertRequest::OID_EXTENSION_REQUEST)) {
        // builder.extensions writes this attribute itself; a second copy is rejected
        continue;
    }
    builder.attributes.add(attr);
}

// A new attribute has the same shape: DER elements, not bare text. This is one UTF8String
// inside the values SET, which is how PKCS#9's unstructuredName is encoded.
const uint8_t unstructuredName[] = { 0x0c, 0x03, 'a', 'b', 'c' };
builder.attributes.add(SCertRequestAttribute(
    CString("1.2.840.113549.1.9.2"),
    COctet(unstructuredName, sizeof(unstructuredName))
));
```
