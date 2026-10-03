Collects certificates and orders them into a chain. buildChain() orders by who issued whom and verifies nothing at all; verifyLinks() adds each link's signature and is still not path validation -- dates, basicConstraints, revocation and trust-anchor choice stay with the caller.

```cpp
// given: const CCert& leaf, const CCert& intermediate, const CCert& root
CCertCollection col;
size_t leafIndex = 0, index = 0;
if (col.add(leaf, leafIndex) != ERET_OK
    || col.add(intermediate, index) != ERET_OK
    || col.add(root, index) != ERET_OK)
{
    return;
}

TArray<size_t> chain;
if (col.buildChain(leafIndex, chain) != ECHAINRES_OK) {
    return; // chain still holds the partial walk assembled before the problem
}

if (col.verifyLinks(chain) != ERET_OK) {
    return;
}
// every link's signature holds -- a chain rooted in an attacker's own CA gets this far too
```
