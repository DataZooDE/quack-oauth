#include "policy_table.hpp"

#include <sstream>

#include "duckdb/common/types/value.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/materialized_query_result.hpp"

namespace duckdb {

// Quote an identifier (or qualified identifier) for inclusion in a SQL
// string. Splits on `.` so `schema.table` becomes `"schema"."table"`. Each
// segment has embedded double quotes escaped by doubling. This is the same
// quoting rule DuckDB uses internally.
static string QuoteQualifiedIdentifier(const string &qualified) {
	string out;
	string segment;
	auto flush = [&](bool more) {
		string quoted = "\"";
		for (char c : segment) {
			if (c == '"')
				quoted += "\"\"";
			else
				quoted += c;
		}
		quoted += "\"";
		out += quoted;
		if (more)
			out += ".";
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

std::optional<quack_oauth::PolicyDocument> LoadPolicyFromTable(ClientContext &context, const string &qualified_table) {
	if (qualified_table.empty())
		return std::nullopt;

	Connection conn(*context.db);
	std::ostringstream sql;
	sql << "SELECT priority, subject, any_scope, actions, allow FROM " << QuoteQualifiedIdentifier(qualified_table)
	    << " ORDER BY priority";

	auto result = conn.Query(sql.str());
	if (result->HasError())
		return std::nullopt;

	quack_oauth::PolicyDocument doc;
	for (auto &row : result->Collection().GetRows()) {
		const auto subject_v = row.GetValue(1);
		const auto any_scope_v = row.GetValue(2);
		const auto actions_v = row.GetValue(3);
		const auto allow_v = row.GetValue(4);

		if (allow_v.IsNull())
			return std::nullopt; // required NOT NULL

		quack_oauth::PolicyRule rule;
		rule.allow = BooleanValue::Get(allow_v);

		if (!subject_v.IsNull()) {
			rule.subject = StringValue::Get(subject_v);
		}

		if (!any_scope_v.IsNull()) {
			for (const auto &v : ListValue::GetChildren(any_scope_v)) {
				if (v.IsNull())
					continue;
				rule.any_scope.push_back(StringValue::Get(v));
			}
		}

		if (!actions_v.IsNull()) {
			for (const auto &v : ListValue::GetChildren(actions_v)) {
				if (v.IsNull())
					continue;
				const auto parsed = quack_oauth::ActionFromString(StringValue::Get(v));
				if (!parsed.has_value())
					return std::nullopt;
				rule.actions.push_back(*parsed);
			}
		}

		doc.rules.push_back(std::move(rule));
	}

	return doc;
}

} // namespace duckdb
