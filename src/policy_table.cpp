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

// Introspect the policy table's column set and decide which of the
// optional columns are present. Returns a struct with the indices
// (negative = not present) so the row walk can pick the right
// position by hand. We use `pragma_table_info` because it's stable
// across DuckDB versions and case-insensitive.
struct ColumnLayout {
	int priority_idx = -1;
	int subject_idx = -1;
	int any_scope_idx = -1;
	int actions_idx = -1;
	int object_pattern_idx = -1; // new (optional)
	int column_pattern_idx = -1; // new (optional)
	int allow_idx = -1;
};

static std::optional<ColumnLayout> DiscoverColumns(Connection &conn, const string &qualified_table) {
	std::ostringstream sql;
	sql << "SELECT lower(name) AS n FROM pragma_table_info('" << qualified_table << "') ORDER BY cid";
	auto result = conn.Query(sql.str());
	if (result->HasError())
		return std::nullopt;
	ColumnLayout layout;
	int i = 0;
	for (auto &row : result->Collection().GetRows()) {
		const auto v = row.GetValue(0);
		if (v.IsNull()) {
			++i;
			continue;
		}
		const auto name = StringValue::Get(v);
		if (name == "priority")
			layout.priority_idx = i;
		else if (name == "subject")
			layout.subject_idx = i;
		else if (name == "any_scope")
			layout.any_scope_idx = i;
		else if (name == "actions")
			layout.actions_idx = i;
		else if (name == "object_pattern")
			layout.object_pattern_idx = i;
		else if (name == "column_pattern")
			layout.column_pattern_idx = i;
		else if (name == "allow")
			layout.allow_idx = i;
		++i;
	}
	// Required columns must be present.
	if (layout.priority_idx < 0 || layout.allow_idx < 0)
		return std::nullopt;
	return layout;
}

// Lowercase + trim a glob pattern read from the policy table. Empty
// strings are treated as NULL (no constraint).
static std::optional<std::string> NormalisePattern(const Value &v) {
	if (v.IsNull())
		return std::nullopt;
	auto s = StringValue::Get(v);
	if (s.empty())
		return std::nullopt;
	std::string out;
	out.reserve(s.size());
	for (char c : s) {
		out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
	}
	return out;
}

std::optional<quack_oauth::PolicyDocument> LoadPolicyFromTable(ClientContext &context, const string &qualified_table) {
	if (qualified_table.empty())
		return std::nullopt;

	Connection conn(*context.db);
	const auto layout = DiscoverColumns(conn, qualified_table);
	if (!layout.has_value())
		return std::nullopt;

	// Always read all known column names in a stable order so the
	// row indices below are deterministic regardless of the source
	// table's column order.
	std::ostringstream sql;
	sql << "SELECT priority, subject, any_scope, actions, allow";
	if (layout->object_pattern_idx >= 0)
		sql << ", object_pattern";
	if (layout->column_pattern_idx >= 0)
		sql << ", column_pattern";
	sql << " FROM " << QuoteQualifiedIdentifier(qualified_table) << " ORDER BY priority";

	auto result = conn.Query(sql.str());
	if (result->HasError())
		return std::nullopt;

	const int obj_pos = (layout->object_pattern_idx >= 0) ? 5 : -1;
	const int col_pos = (layout->column_pattern_idx >= 0) ? (obj_pos >= 0 ? 6 : 5) : -1;

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

		if (obj_pos >= 0) {
			rule.object_pattern = NormalisePattern(row.GetValue(obj_pos));
		}
		if (col_pos >= 0) {
			rule.column_pattern = NormalisePattern(row.GetValue(col_pos));
		}

		doc.rules.push_back(std::move(rule));
	}

	return doc;
}

} // namespace duckdb
