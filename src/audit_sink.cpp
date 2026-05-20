#include "audit_sink.hpp"

#include <mutex>
#include <sstream>

#include "duckdb/common/types/value.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/prepared_statement.hpp"

// DuckDB 1.4 spells this `DUCKDB_LOG_WARN`; 1.5+ renamed it to
// `DUCKDB_LOG_WARNING`. Map the new spelling to the old one when only
// the latter is available.
#if !defined(DUCKDB_LOG_WARNING) && defined(DUCKDB_LOG_WARN)
#define DUCKDB_LOG_WARNING DUCKDB_LOG_WARN
#endif

#include "quack_oauth_state.hpp"
#include "secret_accessor.hpp"

namespace duckdb {

// Resolve the `audit_table` field on the active server SECRET. Empty
// when no SECRET is selected or the field is unset.
static string LookupAuditTable(ClientContext &context) {
	Value v;
	if (!context.TryGetCurrentSetting("quack_oauth_server_secret_name", v) || v.IsNull()) {
		return "";
	}
	auto accessor = TryOpenSecret(context, v.ToString(), "quack_oauth_server");
	return accessor.Get("audit_table");
}

// Quote an identifier (or qualified identifier) for safe SQL splicing.
// Same shape as policy_table.cpp's QuoteQualifiedIdentifier.
static string QuoteQualifiedIdentifier(const string &qualified) {
	string out;
	string segment;
	auto flush = [&](bool more) {
		out.push_back('"');
		for (char c : segment) {
			if (c == '"')
				out.push_back('"');
			out.push_back(c);
		}
		out.push_back('"');
		if (more)
			out.push_back('.');
		segment.clear();
	};
	for (char c : qualified) {
		if (c == '.')
			flush(true);
		else
			segment += c;
	}
	flush(false);
	return out;
}

static void InsertAuditRow(ClientContext &context, const string &table, const quack_oauth::AuditEvent &event) {
	Connection conn(*context.db);
	string sql = "INSERT INTO " + QuoteQualifiedIdentifier(table) +
	             " (timestamp_unix_s, event_type, subject, issuer, kid, token_hash, "
	             "action, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
	auto stmt = conn.Prepare(sql);
	if (stmt->HasError()) {
		DUCKDB_LOG_WARNING(context, "quack_oauth audit_table insert prepare failed: " + stmt->GetError());
		return;
	}
	auto result =
	    stmt->Execute(Value::BIGINT(event.timestamp_unix_s), Value(quack_oauth::AuditEventTypeName(event.event_type)),
	                  event.subject.empty() ? Value(LogicalType::VARCHAR) : Value(event.subject),
	                  event.issuer.empty() ? Value(LogicalType::VARCHAR) : Value(event.issuer),
	                  event.kid.empty() ? Value(LogicalType::VARCHAR) : Value(event.kid),
	                  event.token_hash.empty() ? Value(LogicalType::VARCHAR) : Value(event.token_hash),
	                  event.action.empty() ? Value(LogicalType::VARCHAR) : Value(event.action),
	                  event.reason.empty() ? Value(LogicalType::VARCHAR) : Value(event.reason));
	if (result->HasError()) {
		DUCKDB_LOG_WARNING(context, "quack_oauth audit_table insert failed: " + result->GetError());
	}
}

static bool IsDenialEvent(quack_oauth::AuditEventType t) {
	return t == quack_oauth::AuditEventType::TokenRejected || t == quack_oauth::AuditEventType::AuthzDeny;
}

void EmitAuditEvent(ClientContext &context, const quack_oauth::AuditEvent &event) {
	// Sink 1: in-memory ring.
	{
		auto &state = GetQuackOauthState();
		std::lock_guard<std::mutex> guard(state.mu);
		state.audit_ring.Push(event);
	}

	// Sink 2: DuckDB Logger. Denials at WARNING, accepts/allows at INFO.
	const auto line = quack_oauth::FormatAuditLine(event);
	if (IsDenialEvent(event.event_type)) {
		DUCKDB_LOG_WARNING(context, line);
	} else {
		DUCKDB_LOG_INFO(context, line);
	}

	// Sink 3: optional SQL table on the server SECRET. Best-effort.
	const auto audit_table = LookupAuditTable(context);
	if (!audit_table.empty()) {
		InsertAuditRow(context, audit_table, event);
	}
}

} // namespace duckdb
