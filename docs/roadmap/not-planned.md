# Not planned

[한국어](not-planned.ko.md)

← [Roadmap](../PLANS.md)

- **Live revocation and full RFC 5280 policy-tree processing.**
  `CPathValidator` performs the documented core path checks against an explicit
  `CTrustStore`, but returns `EPATH_REVOCATION_UNAVAILABLE` or
  `EPATH_POLICY_PROCESSING_UNAVAILABLE` when either additional capability is
  requested. Applications that require them must integrate a revocation-state
  source or a fuller policy engine.

Current measurements live in [Performance](../concepts/performance.md), and
completed performance milestones live in [History](../HISTORY.md). Superseded
interim investigations are not maintained as roadmap items.
