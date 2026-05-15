#pragma once

#include "duckdb/main/client_context.hpp"

#include "audit.hpp"

namespace duckdb {

// Fan an audit event out to three sinks:
//
//   1. The in-memory `AuditRing` in `QuackOauthState` -- always.
//   2. DuckDB's `Logger` (INFO for accept/allow, WARNING for reject/deny) --
//      always, with sensitive fields already redacted in the AuditEvent.
//   3. An operator-managed SQL table named by `audit_table` on the active
//      `quack_oauth_server` SECRET -- if set. INSERT is best-effort; a
//      failure (missing table, wrong schema) is logged at WARNING and
//      does NOT abort the calling auth function.
//
// The caller MUST set `event.timestamp_unix_s` before calling. The caller
// is also expected to be holding the QuackOauthState mutex (the ring push
// is not internally synchronised).
void EmitAuditEvent(ClientContext &context, const quack_oauth::AuditEvent &event);

} // namespace duckdb
