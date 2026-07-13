# quack_oauth Telemetry

`quack_oauth` collects **anonymous, privacy-preserving usage telemetry** so we
can see which capabilities are used, on which platforms, and where they load —
and prioritise accordingly. It is **on by default** and **trivial to turn off**.

Telemetry is emitted through the shared
[`DataZooDE/posthog-telemetry`](https://github.com/DataZooDE/posthog-telemetry)
library and follows the cross-product **`telemetry_schema: 2`** envelope
(`posthog-telemetry/TELEMETRY-SCHEMA.md`). It uses the same key, the same
library, and the same opt-out paths as `../erpl` and `../erpl-web`. Ingestion is
the EU PostHog cloud.

## How to turn it off

Any one of these fully short-circuits telemetry — when disabled, **nothing
leaves the machine** (the opt-out is enforced at the transport, not just at the
call sites):

```sql
SET quack_oauth_telemetry_enabled = false;   -- DuckDB setting (per session)
```

```bash
export DATAZOO_DISABLE_TELEMETRY=1            -- environment (1|true|yes)
```

The setting also has an environment default: `QUACK_OAUTH_TELEMETRY_ENABLED=0`
starts the extension with telemetry already off.

## The guarantee: bounded, enumerated, non-PII

Every property we send is **either** a constant drawn from a small,
code-controlled enumeration **or** a pure number (durations, counts). The
library additionally clamps every outgoing string to a fixed byte cap as a
backstop.

We **never** send: tokens, access/refresh/ID tokens, client secrets, secret
names, issuer / audience / JWKS URLs, principal or user identifiers, claims, SQL
text, function arguments, or OAuth/OIDC **error messages**. The only function
identifiers transmitted are the fixed, code-controlled `quack_oauth_*` names
listed below — never their inputs or outputs.

## What is collected

### Envelope (attached to every event)

`product` (`quack_oauth`), `product_version`, `product_edition` (`oss`),
`telemetry_schema` (`2`), `duckdb_version`, `os`, `arch`, `platform`, `is_ci`,
`is_container`, a per-process `$session_id`, and — once associated — the
`deployment` group. `distinct_id` is the SHA-256 of a machine id: a **stable,
pseudonymous** identifier, not tied to any personal data.

### Events

| Event | When | Properties (beyond the envelope) |
|---|---|---|
| `extension_loaded` | the `quack_oauth` extension loads | — |
| `function_executed` | a `quack_oauth_*` function runs — **aggregated** per function per session (not per row) | `function_name`, `call_count`, `duration_ms_p50` |

`quack_oauth` associates only the `deployment` group. It has no license key, so
no `account` group is associated.

### Instrumented functions (the `function_name` enumeration)

`quack_oauth_check_authorization`, `quack_oauth_check_token`,
`quack_oauth_acquire`, `quack_oauth_login`, `quack_oauth_logout`,
`quack_oauth_refresh`, `quack_oauth_device_login`, `quack_oauth_diagnose`,
`quack_oauth_audit_log`, `quack_oauth_current_principal`.

## Function-call aggregation

DuckDB function calls are recorded via `RecordFunctionCall(function_name)`, which
aggregates in-process into a single `function_executed` event per function per
session (carrying `call_count` and `duration_ms_p50`). Each capture site sits at
bind or at the top of the per-chunk callback — never on a per-row path — so a
large scan produces O(1) telemetry rows, not a firehose.

## Teardown safety

The telemetry worker discards any queued events at process exit rather than
draining them (no new HTTPS work starts from the `atexit` / static-teardown
path). This avoids the deterministic shutdown SIGSEGV described in
`DataZooDE/posthog-telemetry#4`.
