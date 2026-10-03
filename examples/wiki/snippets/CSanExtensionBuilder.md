Attaches the identities a TLS leaf is actually valid for, both DNS names and an IP address -- an iPAddress entry is raw address octets in a COctet, not text. The criticality is conditional: when the subject DN carries no common name, SubjectAltName is the certificate's only identity and RFC 5280 4.2.1.6 requires it to be critical.

```cpp
// given: CCertBuilder& builder
CSanExtensionBuilder san;
san.addName(CGeneralName(EGNAME_DNS, CString("example.com")));
san.addName(CGeneralName(EGNAME_DNS, CString("www.example.com")));

const uint8_t ipv4[4] = { 192, 0, 2, 10 };
san.addName(CGeneralName(EGNAME_IP_ADDRESS, COctet(ipv4, sizeof(ipv4))));

IExtensionPtr ext = san.build();
if (!ext) {
    return; // non-ASCII text in a dNSName or URI can't be encoded as IA5String
}

CName commonName;
if (!builder.subject.tryGet(ENAME_CN, commonName)) {
    ext->critical(true);
}

builder.extensions.add(ext);
```
