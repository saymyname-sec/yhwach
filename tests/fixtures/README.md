# Fixtures

Each fixture is one engagement snapshot + one expected planner outcome. Format is documented in `tests/README.md`.

## Layout

```
tests/fixtures/
  <name>.yaml          # synthetic or hand-crafted scenario
  labs/
    <labname>/         # snapshots pulled from real (authorized) engagements
      <host>.yaml      # one file per host per lab
```

## Rules

- Synthetic fixtures may use example IPs (RFC1918, RFC5737). No real-world IPs.
- Lab-derived fixtures scrub all identifying data: real hostnames, credentials, personal names, external IPs.
- Every fixture must satisfy `authorized_only: true` at the rule level.
- Fixtures are the regression corpus. Do not delete; deprecate.
