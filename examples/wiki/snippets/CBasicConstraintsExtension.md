Decides whether a candidate issuer is allowed to sit where it does in a path. An absent pathLenConstraint means "any number of intermediates may follow", not zero -- so hasPathLenConstraint() must be consulted before pathLenConstraint() is believed.

```cpp
// given: const CCert& caCert, size_t intermediatesBelow
auto bc = caCert.extension<CBasicConstraintsExtension>();
if (!bc || !bc->isCa()) {
    return; // absent, or cA false: this certificate may not sign other certificates at all
}

if (!bc->hasPathLenConstraint()) {
    return; // unconstrained depth; nothing further to check here
}

if (int64_t(intermediatesBelow) > bc->pathLenConstraint()) {
    return; // too many non-self-issued intermediates follow this CA: the path is invalid
}

// caCert may certify the subordinate CA beneath it
```
