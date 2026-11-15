# Session isolation and host migration

The extension no longer accepts session ownership from SQL arguments. This is a
breaking security change for hosts using the legacy three-argument SQL callback.
That callback returns false (or NULL for NULL input), without validating tokens
or populating principals. There is no compatibility switch to restore it.

## Native host contract

Include `check_token_function.hpp` and link against the extension's native code.
Call `AuthenticateQuackOauthSession(context, session_id, token)` before accepting
a session. This function uses the normal configured token validator and returns
true only on successful validation. Configuration errors throw as before.

The host must:

1. Create a dedicated DuckDB connection for the session. Choose the session ID
   itself, independently of SQL submitted by a client.
2. Invoke the native API on that connection's ClientContext, outside a SQL
   callback. The API uses DuckDB's transaction wrapper to serialize context use.
3. Retain that connection for authorization checks and user queries. The
   authorization scalar requires the ID bound to that same connection. Checks
   on temporary or unrelated connections deny access.
4. Execute only the host's authorization check before allowing a user query.
   Do not expose the native authentication API through a SQL wrapper, and do not
   treat a client's own call to the authorization scalar as an enforcement hook.
5. Reauthenticate only with the same session ID. Failed reauthentication removes
   the old principal, including on configuration/transport failures. A different
   ID is rejected; create a fresh connection for another session.
6. Destroy the session connection on disconnect or expiration. Do not pool or
   reuse an authenticated ClientContext for a different user.

Current upstream quack's SQL callback interface does not implement this contract.
It needs a host integration change before successful OAuth sessions can resume.
This PR does not change that separate repository or claim end-to-end wire support.
Legacy E2E success tests and SQL templates that seed through the three-argument
callback are migration work, not expected passing tests for this version.

## State and visibility

JWKS and token-decision caches are shared only within a DatabaseInstance, with
existing mutex protection and bounds. Different databases cannot share their
cached validation results or JWKS settings.

Principals and the 64-event audit ring belong to ClientContext registered state.
`quack_oauth_current_principal()` returns at most the current connection's
principal. `quack_oauth_audit_log()` reports only events generated on that
connection, including ordinary token-validation events. Both retain their column
schemas. `quack_oauth_diagnose()` reports database cache statistics and local
principal/audit statistics. Session state is destroyed with the connection;
validation caches are destroyed with the database.

The one-argument token-checking scalar still validates tokens and records local
audit events, but never changes the authenticated principal. There is no SQL
operator override for enumerating other sessions. Existing persistent audit tables
and DuckDB logging are separate operator-managed sinks; their visibility is not
controlled by this change. This is not a general SQL sandbox or database-role
system: hosts remain responsible for limiting access to configuration, secrets,
logs, and privileged SQL operations.

## Verification boundary

The native regression driver uses the production authentication API, real local
DuckDB connections, and a synthetic loopback IdP. It verifies successful identity
binding and policy decisions before asserting isolation. It adds no SQL-callable
seeding or privilege bypass to the shipped extension. SQL tests additionally
exercise legacy denial and audit visibility through the standard interfaces.

These tests establish local extension behavior. They do not establish deployed
caller permissions or resolve the unverified separate-server query-access claim.
