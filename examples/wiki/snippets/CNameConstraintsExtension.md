Applies a CA's name constraints to a name it is about to be trusted for. Excluded subtrees are checked first and win over any permitted subtree that also matches; and a subtree carrying a non-zero minimum or any maximum must not be honoured at all, because RFC 5280 4.2.1.10 forbids both fields outright.

```cpp
// given: const CCert& caCert, const CString& dnsName
auto nc = caCert.extension<CNameConstraintsExtension>();
if (!nc) {
    return; // an unconstrained CA: it may certify any name at all
}

for (const CGeneralSubtree& subtree : nc->excludedSubtrees()) {
    if (subtree.base().type() == EGNAME_DNS
        && subtree.base().text().compare(dnsName.toPtr()) == 0) {
        return; // excluded, regardless of what permittedSubtrees() says about it
    }
}

for (const CGeneralSubtree& subtree : nc->permittedSubtrees()) {
    if (subtree.minimum() != 0 || subtree.hasMaximum()) {
        return; // a subtree using the forbidden fields: reject the certificate
    }

    if (subtree.base().type() == EGNAME_DNS
        && subtree.base().text().compare(dnsName.toPtr()) == 0) {
        // permitted (a full matcher also walks DNS suffixes, not just exact bases)
        return;
    }
}

// A non-empty permittedSubtrees() that matched nothing excludes the name.
```
