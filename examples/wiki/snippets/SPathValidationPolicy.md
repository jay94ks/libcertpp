Supplies the application-specific part of path validation: the evaluation time and the leaf usage expected by this protocol. Leaving these implicit is how an otherwise valid chain is accidentally accepted for the wrong purpose.

```cpp
SPathValidationPolicy policy;
policy.validationTime = SDateTime::now(true);
policy.requiredLeafKeyUsages = EKUSE_DIGITAL_SIGNATURE;
policy.requiredExtendedKeyPurpose = COid(CEkuExtension::OID_SERVER_AUTH);
policy.maxDepth = 8;
policy.requireRevocation = false; // revocation is checked by a separate deployment service
```
