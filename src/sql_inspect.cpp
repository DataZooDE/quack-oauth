#include "sql_inspect.hpp"

#include <algorithm>
#include <cctype>
#include <exception>
#include <string>

#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/sql_statement.hpp"
#include "duckdb/parser/tableref.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"
#include "duckdb/parser/tableref/joinref.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/parser/tableref/pivotref.hpp"
#include "duckdb/parser/tableref/expressionlistref.hpp"
#include "duckdb/parser/tableref/showref.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/group_by_node.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/statement/insert_statement.hpp"
#include "duckdb/parser/statement/update_statement.hpp"
#include "duckdb/parser/statement/delete_statement.hpp"
#include "duckdb/parser/statement/copy_statement.hpp"
#include "duckdb/parser/statement/pragma_statement.hpp"
#include "duckdb/parser/statement/merge_into_statement.hpp"
#include "duckdb/parser/statement/explain_statement.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/set_statement.hpp"
#include "duckdb/parser/statement/drop_statement.hpp"
#include "duckdb/parser/statement/alter_statement.hpp"
#include "duckdb/parser/statement/attach_statement.hpp"
#include "duckdb/parser/statement/detach_statement.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/constraints/check_constraint.hpp"
#include "duckdb/parser/parsed_data/create_view_info.hpp"
#include "duckdb/parser/parsed_data/create_macro_info.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "duckdb/parser/result_modifier.hpp"
#include "duckdb/parser/query_node.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/query_node/set_operation_node.hpp"
#include "duckdb/parser/query_node/cte_node.hpp"
#include "duckdb/parser/query_node/recursive_cte_node.hpp"
#include "duckdb/parser/expression/columnref_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parsed_data/copy_info.hpp"
#include "duckdb/parser/parsed_data/pragma_info.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb_compat/sql_ast.hpp"

namespace quack_oauth {

namespace {

std::string LowerAscii(std::string_view s) {
	std::string out(s);
	std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
	return out;
}

bool IsAllowedSystemView(const std::string &schema, const std::string &table) {
	// Catalog metadata only. The tables view exposes names and comments, not
	// settings, variables, secrets, prepared SQL, logs or attach paths.
	return schema == "information_schema" && table == "tables";
}

bool LooksLikeUnqualifiedSystemView(const std::string &table) {
	// DuckDB's default view names. Exact matching preserves user tables such
	// as duckdb_private while preventing a main.* grant from covering a
	// search-path-resolved system view.
	static const std::string names[] = {
	    "pragma_database_list", "sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema",
	    "duckdb_constraints", "duckdb_columns", "duckdb_databases", "duckdb_indexes", "duckdb_schemas",
	    "duckdb_tables", "duckdb_types", "duckdb_views", "duckdb_logs",
	    "pg_am", "pg_prepared_statements", "pg_attribute", "pg_attrdef", "pg_class", "pg_constraint",
	    "pg_collation", "pg_database", "pg_depend", "pg_description", "pg_enum", "pg_index",
	    "pg_indexes", "pg_namespace", "pg_proc", "pg_sequence", "pg_sequences", "pg_settings",
	    "pg_tables", "pg_tablespace", "pg_type", "pg_views",
	    "columns", "schemata", "tables", "character_sets", "referential_constraints",
	    "key_column_usage", "table_constraints", "constraint_column_usage", "constraint_table_usage",
	    "check_constraints", "views"};
	return std::find(std::begin(names), std::end(names), table) != std::end(names);
}

void AddNamedObject(AuthzRequest &req, std::string object) {
	if (std::find(req.objects.begin(), req.objects.end(), object) == req.objects.end())
		req.objects.push_back(std::move(object));
}

void AddObject(AuthzRequest &req, const std::string &catalog, const std::string &schema, const std::string &table) {
	if (table.empty()) {
		return;
	}
	// schema defaults to "main" if unset (DuckDB default).
	const auto sch = schema.empty() ? "main" : LowerAscii(schema);
	const auto tbl = LowerAscii(table);
	if (!catalog.empty()) {
		// Policy patterns currently use schema.table, so do not allow an
		// attached catalog to inherit the local table's grant.
		req.unsafe = true;
		if (req.error.empty()) req.error = "catalog-qualified object";
	}
	if (sch == "information_schema" || sch == "pg_catalog") {
		if (!IsAllowedSystemView(sch, tbl)) {
			req.unsafe = true;
			if (req.error.empty()) req.error = "system view is not allowlisted";
		}
		return;
	}
	if (sch == "main" && LooksLikeUnqualifiedSystemView(tbl)) {
		req.unsafe = true;
		if (req.error.empty()) req.error = "unqualified system view is not allowlisted";
		return;
	}
	AddNamedObject(req, sch + "." + tbl);
}

// Only functions that mirror ordinary catalog views are exempt. A prefix
// exemption also admits variables, logs and prepared SQL text.
bool IsExemptFunction(const std::string &name) {
	static const std::string allowed[] = {
	    "duckdb_tables", "duckdb_columns"};
	return std::find(std::begin(allowed), std::end(allowed), name) != std::end(allowed);
}

bool AllowedPragma(const std::string &name) {
	static const std::string allowed[] = {"version"};
	return std::find(std::begin(allowed), std::end(allowed), name) != std::end(allowed);
}

bool AllowedSetting(const std::string &name) {
	static const std::string allowed[] = {"threads"};
	return std::find(std::begin(allowed), std::end(allowed), name) != std::end(allowed);
}

// Surface a TABLE FUNCTION (read_csv, postgres_query, glob, read_parquet, …)
// as a policy-gated object under the reserved `fn:` namespace, so default-deny
// covers it and a rule can still allow a specific safe function. Table
// functions are NOT base tables, so schema-scoped isolation never gated them;
// left unsurfaced, `SELECT … FROM entitled, read_csv('http://…')` reaches the
// serving connection's secrets/attached catalogs unchecked (the F1 boundary
// failure). `fn:` cannot collide with a real `schema.table` object (no `:`
// there), so it is exempt from the system-object filter -- the metadata
// carve-out is `IsExemptFunction` above instead.
void AddFunctionObject(AuthzRequest &req, const std::string &name) {
	const auto lowered = LowerAscii(name.empty() ? "?" : name);
	if (IsExemptFunction(lowered)) {
		return;
	}
	const auto fn = "fn:" + lowered;
	if (std::find(req.objects.begin(), req.objects.end(), fn) == req.objects.end()) {
		req.objects.push_back(fn);
	}
}

void AddColumn(AuthzRequest &req, const std::string &col) {
	if (col.empty()) {
		return;
	}
	const auto c = LowerAscii(col);
	if (std::find(req.columns.begin(), req.columns.end(), c) == req.columns.end()) {
		req.columns.push_back(c);
	}
}

// Walk state. `req` is the result being built; `cte_names` holds the CTE
// aliases in scope for the CURRENT statement.
//
// A CTE reference parses as a plain `BaseTableRef` -- binding is what would
// resolve it to the CTE body, and we only parse. Left alone, `WITH c AS (…)
// SELECT * FROM c` surfaces `main.c`, an object that does not exist, so an
// object_pattern policy denies a legitimate query. We skip a base table whose
// bare (unqualified) name matches a CTE in scope; an explicitly qualified
// `main.c` is still gated, and the set is reset per statement so a later
// statement's real table of the same name is not waved through.
struct WalkCtx {
	AuthzRequest &req;
	std::vector<std::string> cte_names;

	bool IsCte(const std::string &name) const {
		return std::find(cte_names.begin(), cte_names.end(), name) != cte_names.end();
	}
};

void WalkTableRef(const duckdb::TableRef &ref, WalkCtx &ctx);

void WalkQueryNode(const duckdb::QueryNode &qn, WalkCtx &ctx);
void WalkStatement(const duckdb::SQLStatement &s, WalkCtx &ctx);

// True when DuckDB would bind this name as a replacement-scan FILE READ rather than a
// catalog table: DuckDB rebuilds the path from catalog.schema.table joined with dots
// (ReplacementScan::GetFullPath), so `main.csv` reads ./main.csv when no such table
// exists. Any part with a path character, or a qualified name whose table part is a
// known file suffix, is treated as a file read. The suffix list is best effort --
// extensions can register more (see README: disable replacement scans on the serving
// connection as the backstop).
static bool IsReplacementScanName(const std::string &catalog, const std::string &schema, const std::string &table) {
	for (const auto *part : {&catalog, &schema, &table}) {
		if (part->find_first_of("/\\:") != std::string::npos) {
			return true;
		}
	}
	if (table.find('.') != std::string::npos) {
		return true;
	}
	if (schema.empty() && catalog.empty()) {
		return false;
	}
	static const char *const suffixes[] = {"csv",  "tsv",     "txt",      "parquet", "json",  "jsonl",
	                                       "ndjson", "geojson", "geojsonl", "shp",     "gpkg",  "fgb",
	                                       "xlsx", "avro",    "arrow",    "db",      "ddb",   "duckdb",
	                                       "sqlite", "gz",    "zst"};
	const auto lowered = LowerAscii(table);
	for (const auto *suffix : suffixes) {
		if (lowered == suffix) {
			return true;
		}
	}
	return false;
}


void Unsafe(WalkCtx &ctx, const char *message) {
	ctx.req.unsafe = true;
	if (ctx.req.error.empty()) ctx.req.error = message;
}

template <class T> void WalkExpressions(const T &expressions, WalkCtx &ctx);

// Nonrecursive WITH binds sequentially. A body can see earlier aliases,
// never its own alias or a later one. The stack restores outer scope on exit.
struct CteScope {
	WalkCtx &ctx;
	size_t size;
	CteScope(WalkCtx &ctx, const std::string &alias) : ctx(ctx), size(ctx.cte_names.size()) {
		if (!alias.empty()) ctx.cte_names.push_back(alias);
	}
	CteScope(WalkCtx &ctx, const duckdb::CommonTableExpressionMap &map) : ctx(ctx), size(ctx.cte_names.size()) {
		for (const auto &kv : map.map) {
			if (!kv.second) Unsafe(ctx, "null CTE definition");
			else {
				const auto *query = duckdb_compat::CteQuery(*kv.second);
				if (!query) Unsafe(ctx, "null CTE query");
				else WalkQueryNode(*query, ctx);
			}
			ctx.cte_names.push_back(LowerAscii(duckdb_compat::Str(kv.first)));
		}
	}
	~CteScope() { ctx.cte_names.resize(size); }
};

void WalkExpression(const duckdb::ParsedExpression &expr, WalkCtx &ctx) {
	AuthzRequest &req = ctx.req;
	if (expr.GetExpressionClass() == duckdb::ExpressionClass::COLUMN_REF) {
		const auto &cr = expr.Cast<duckdb::ColumnRefExpression>();
		const auto &names = duckdb_compat::ColumnNames(cr);
		if (!names.empty()) {
			AddColumn(req, duckdb_compat::Str(names.back()));
		}
	} else if (expr.GetExpressionClass() == duckdb::ExpressionClass::STAR) {
		AddColumn(req, "*");
	} else if (expr.GetExpressionClass() == duckdb::ExpressionClass::SUBQUERY) {
		// A subquery in an expression position (scalar in SELECT, EXISTS/IN in
		// WHERE/HAVING, a correlated body). Its FROM tables are NOT enumerated
		// as expression children, so walk its query node explicitly — else
		// `SELECT (SELECT max(x) FROM other_tenant) FROM entitled` reaches
		// another tenant's rows unchecked (the F2 gap).
		const auto &sq = expr.Cast<duckdb::SubqueryExpression>();
		const auto &subquery = duckdb_compat::Subquery(sq);
		if (subquery && subquery->node) {
			WalkQueryNode(*subquery->node, ctx);
		} else Unsafe(ctx, "null expression subquery");
	} else if (expr.GetExpressionClass() == duckdb::ExpressionClass::FUNCTION) {
		const auto &fn = expr.Cast<duckdb::FunctionExpression>();
		const auto name = LowerAscii(duckdb_compat::FunctionName(fn));
		if (name == "current_setting" || name == "getvariable" || name == "nextval" || name == "currval")
			Unsafe(ctx, "state-reading or mutating scalar function");
	}
	duckdb::ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const duckdb::ParsedExpression &child) { WalkExpression(child, ctx); });
}

template <class T> void WalkExpressions(const T &expressions, WalkCtx &ctx) {
	for (const auto &expr : expressions) if (expr) WalkExpression(*expr, ctx);
}

template <class T> void WalkNamedExpressions(const T &expressions, WalkCtx &ctx) {
	for (const auto &entry : expressions) {
		if (entry.second) WalkExpression(*entry.second, ctx);
		else Unsafe(ctx, "null named expression");
	}
}

void WalkCopyInfo(const duckdb::CopyInfo &info, WalkCtx &ctx) {
	const auto target = duckdb_compat::AstTarget(info);
	AddObject(ctx.req, target[0], target[1], target[2]);
	if (info.select_statement) WalkQueryNode(*info.select_statement, ctx);
	if (info.file_path_expression) WalkExpression(*info.file_path_expression, ctx);
	WalkNamedExpressions(info.parsed_options, ctx);
}

void WalkModifiers(const duckdb::QueryNode &qn, WalkCtx &ctx) {
	for (const auto &modifier : qn.modifiers) {
		if (!modifier) { Unsafe(ctx, "null query modifier"); continue; }
		switch (modifier->type) {
		case duckdb::ResultModifierType::ORDER_MODIFIER: {
			const auto &order = modifier->Cast<duckdb::OrderModifier>();
			for (const auto &entry : order.orders) {
				if (entry.expression) WalkExpression(*entry.expression, ctx);
				else Unsafe(ctx, "null ORDER BY expression");
			}
			break;
		}
		case duckdb::ResultModifierType::LIMIT_MODIFIER: {
			const auto &limit = modifier->Cast<duckdb::LimitModifier>();
			if (limit.limit) WalkExpression(*limit.limit, ctx);
			if (limit.offset) WalkExpression(*limit.offset, ctx);
			break;
		}
		case duckdb::ResultModifierType::DISTINCT_MODIFIER:
			WalkExpressions(modifier->Cast<duckdb::DistinctModifier>().distinct_on_targets, ctx);
			break;
		case static_cast<duckdb::ResultModifierType>(4):
			duckdb_compat::VisitLegacyLimitPercent(*modifier, [&](const auto &limit) {
				if (limit.limit) WalkExpression(*limit.limit, ctx);
				if (limit.offset) WalkExpression(*limit.offset, ctx);
			});
			break;
		default:
			Unsafe(ctx, "unsupported query modifier");
			break;
		}
	}
}

template <class T> bool MergeOnlyUpdates(const T &node) {
	bool found = false;
	for (const auto &group : node.actions) for (const auto &action : group.second) {
		if (!action || action->action_type != duckdb::MergeActionType::MERGE_UPDATE) return false;
		found = true;
	}
	return found;
}

void WalkSetInfo(const duckdb::UpdateSetInfo *info, WalkCtx &ctx) {
	if (!info) return;
	WalkExpressions(info->expressions, ctx);
	if (info->condition) WalkExpression(*info->condition, ctx);
}

template <class T> void WalkInsert(const T &node, WalkCtx &ctx) {
	const auto target = duckdb_compat::AstTarget(node);
	AddObject(ctx.req, target[0], target[1], target[2]);
	if (node.select_statement && node.select_statement->node) WalkQueryNode(*node.select_statement->node, ctx);
	if (node.table_ref) WalkTableRef(*node.table_ref, ctx);
	WalkExpressions(node.returning_list, ctx);
	if (node.on_conflict_info) {
		WalkSetInfo(node.on_conflict_info->set_info.get(), ctx);
		if (node.on_conflict_info->condition) WalkExpression(*node.on_conflict_info->condition, ctx);
	}
}

template <class T> void WalkUpdate(const T &node, WalkCtx &ctx) {
	if (node.table) WalkTableRef(*node.table, ctx);
	if (node.from_table) WalkTableRef(*node.from_table, ctx);
	WalkSetInfo(node.set_info.get(), ctx);
	WalkExpressions(node.returning_list, ctx);
}

template <class T> void WalkDelete(const T &node, WalkCtx &ctx) {
	if (node.table) WalkTableRef(*node.table, ctx);
	for (const auto &ref : node.using_clauses) if (ref) WalkTableRef(*ref, ctx);
	if (node.condition) WalkExpression(*node.condition, ctx);
	WalkExpressions(node.returning_list, ctx);
}

template <class T> void WalkMerge(const T &node, WalkCtx &ctx) {
	if (node.target) WalkTableRef(*node.target, ctx);
	if (node.source) WalkTableRef(*node.source, ctx);
	if (node.join_condition) WalkExpression(*node.join_condition, ctx);
	for (const auto &group : node.actions) for (const auto &action : group.second) {
		if (!action) { Unsafe(ctx, "null MERGE action"); continue; }
		if (action->condition) WalkExpression(*action->condition, ctx);
		WalkSetInfo(action->update_info.get(), ctx);
		WalkExpressions(action->expressions, ctx);
	}
	WalkExpressions(node.returning_list, ctx);
}

void WalkQueryNode(const duckdb::QueryNode &qn, WalkCtx &ctx) {
	AuthzRequest &req = ctx.req;
	CteScope scope(ctx, qn.cte_map);
	WalkModifiers(qn, ctx);
	switch (qn.type) {
	case duckdb::QueryNodeType::SELECT_NODE: {
		const auto &sn = qn.Cast<duckdb::SelectNode>();
		if (sn.from_table) {
			WalkTableRef(*sn.from_table, ctx);
		}
		for (const auto &expr : sn.select_list) {
			if (expr) {
				WalkExpression(*expr, ctx);
			}
		}
		// Walk the remaining expression clauses too — a subquery reaching
		// another tenant hides in WHERE/HAVING/QUALIFY/GROUP BY just as easily
		// as in the SELECT list (F2). WalkExpression recurses into subqueries.
		if (sn.where_clause) {
			WalkExpression(*sn.where_clause, ctx);
		}
		if (sn.having) {
			WalkExpression(*sn.having, ctx);
		}
		if (sn.qualify) {
			WalkExpression(*sn.qualify, ctx);
		}
		for (const auto &g : sn.groups.group_expressions) {
			if (g) {
				WalkExpression(*g, ctx);
			}
		}
		break;
	}
	case duckdb::QueryNodeType::SET_OPERATION_NODE: {
		const auto &son = qn.Cast<duckdb::SetOperationNode>();
		duckdb_compat::ForEachSetChild(son, [&](const duckdb::QueryNode &child) { WalkQueryNode(child, ctx); });
		break;
	}
	case duckdb::QueryNodeType::CTE_NODE: {
		// A WITH clause can arrive as a CTENode wrapping the rest of the
		// query instead of being attached to a SelectNode's cte_map (the
		// shape the former DuckDB 1.4.x line always produced). If this node
		// type went unhandled, the whole select half would go unwalked --
		// every statement containing a WITH would collect zero objects,
		// which is not a fail-closed state: a zero-object request skips
		// every rule that carries an object_pattern (see policy.cpp), so an
		// object-scoped deny could be laundered through a CTE. Kept as
		// defence in depth: handle both shapes.
		const auto &cn = qn.Cast<duckdb::CTENode>();
		const auto cte_name = LowerAscii(duckdb_compat::Str(cn.ctename));
		if (cn.query) WalkQueryNode(*cn.query, ctx);
		else Unsafe(ctx, "null CTE body");
		CteScope alias_scope(ctx, cte_name);
		if (cn.child) WalkQueryNode(*cn.child, ctx);
		else Unsafe(ctx, "null CTE child");
		break;
	}
	case duckdb::QueryNodeType::RECURSIVE_CTE_NODE: {
		const auto &rn = qn.Cast<duckdb::RecursiveCTENode>();
		const auto cte_name = LowerAscii(duckdb_compat::Str(rn.ctename));
		if (rn.left) WalkQueryNode(*rn.left, ctx);
		else Unsafe(ctx, "null recursive CTE seed");
		CteScope alias_scope(ctx, cte_name);
		if (rn.right) WalkQueryNode(*rn.right, ctx);
		else Unsafe(ctx, "null recursive CTE arm");
		break;
	}
	case duckdb::QueryNodeType::BOUND_SUBQUERY_NODE:
		break;
	default:
		if (duckdb_compat::VisitDmlQuery(qn,
		    [&](const auto &node) { if (req.action != Action::Update) Unsafe(ctx, "UPDATE hidden in query"); WalkUpdate(node, ctx); },
		    [&](const auto &node) { if (req.action != Action::Delete) Unsafe(ctx, "DELETE hidden in query"); WalkDelete(node, ctx); },
		    [&](const auto &node) { if (req.action != Action::Insert) Unsafe(ctx, "INSERT hidden in query"); WalkInsert(node, ctx); },
		    [&](const auto &node) { if (req.action != Action::Update || !MergeOnlyUpdates(node)) Unsafe(ctx, "MERGE hidden in query"); WalkMerge(node, ctx); },
		    [&](const auto &node) {
			if (req.action != Action::CopyTo) Unsafe(ctx, "COPY hidden in query");
			if (!node.info) { Unsafe(ctx, "null COPY info"); return; }
			WalkCopyInfo(*node.info, ctx);
		})) break;
		Unsafe(ctx, "unsupported query node");
		break;
	}
}

void WalkTableRef(const duckdb::TableRef &ref, WalkCtx &ctx) {
	AuthzRequest &req = ctx.req;
	switch (ref.type) {
	case duckdb::TableReferenceType::BASE_TABLE: {
		const auto &bt = ref.Cast<duckdb::BaseTableRef>();
		if (bt.at_clause) {
			const auto &expr = bt.at_clause->ExpressionMutable();
			if (expr) WalkExpression(*expr, ctx);
			else Unsafe(ctx, "null AT clause expression");
		}
		// An unqualified name matching a CTE in scope is a reference to that
		// CTE, not to a table. Only bare names qualify -- an explicit
		// `main.c` still gates.
		const auto target = duckdb_compat::AstTarget(bt);
		if (target[0].empty() && target[1].empty() && ctx.IsCte(LowerAscii(target[2]))) {
			break;
		}
		if (IsReplacementScanName(target[0], target[1], target[2])) {
			Unsafe(ctx, "path-like replacement scan");
			break;
		}
		AddObject(req, target[0], target[1], target[2]);
		break;
	}
	case duckdb::TableReferenceType::JOIN: {
		const auto &jr = ref.Cast<duckdb::JoinRef>();
		if (jr.left) {
			WalkTableRef(*jr.left, ctx);
		}
		if (jr.right) {
			WalkTableRef(*jr.right, ctx);
		}
		if (jr.condition) WalkExpression(*jr.condition, ctx);
		break;
	}
	case duckdb::TableReferenceType::SUBQUERY: {
		const auto &sr = ref.Cast<duckdb::SubqueryRef>();
		if (sr.subquery && sr.subquery->node) {
			WalkQueryNode(*sr.subquery->node, ctx);
		} else Unsafe(ctx, "null subquery ref");
		break;
	}
	case duckdb::TableReferenceType::TABLE_FUNCTION: {
		// A table function (read_csv, read_parquet, glob, postgres_query, …).
		// Surface it as a `fn:<name>` gated object so default-deny covers it —
		// on the serving connection these reach secrets, remote endpoints, and
		// attached catalogs by path, which schema isolation never gated (F1).
		const auto &tf = ref.Cast<duckdb::TableFunctionRef>();
		std::string fn_name;
		if (tf.function && tf.function->GetExpressionClass() == duckdb::ExpressionClass::FUNCTION) {
			fn_name = duckdb_compat::FunctionName(tf.function->Cast<duckdb::FunctionExpression>());
		}
		if (fn_name.empty()) {
			// A table function we cannot name is one we cannot gate by rule —
			// fail closed rather than let it through unsurfaced.
			req.unsafe = true;
			req.error = "unnamed table function";
		} else {
			AddFunctionObject(req, fn_name);
			const auto lowered = LowerAscii(fn_name);
			if (lowered == "query" || lowered == "query_table") Unsafe(ctx, "dynamic SQL table function");
		}
		if (tf.function) WalkExpression(*tf.function, ctx);
		if (tf.subquery) {
			if (tf.subquery->node) WalkQueryNode(*tf.subquery->node, ctx);
			else Unsafe(ctx, "null table-function subquery");
		}
		break;
	}
	case duckdb::TableReferenceType::PIVOT: {
		// PIVOT/UNPIVOT wrap a source table ref — walk it so the pivoted
		// object is still gated.
		const auto &pr = ref.Cast<duckdb::PivotRef>();
		if (pr.source) {
			WalkTableRef(*pr.source, ctx);
		}
		WalkExpressions(pr.aggregates, ctx);
		for (const auto &pivot : pr.pivots) {
			WalkExpressions(pivot.pivot_expressions, ctx);
			if (pivot.subquery) WalkQueryNode(*pivot.subquery, ctx);
			for (const auto &entry : pivot.entries) if (entry.expr) WalkExpression(*entry.expr, ctx);
		}
		break;
	}
	case duckdb::TableReferenceType::EXPRESSION_LIST: {
		const auto &values = ref.Cast<duckdb::ExpressionListRef>();
		for (const auto &row : values.values) WalkExpressions(row, ctx);
		break;
	}
	case duckdb::TableReferenceType::SHOW_REF: {
		const auto &show = ref.Cast<duckdb::ShowRef>();
		if (show.query) WalkQueryNode(*show.query, ctx);
		else {
			const auto target = duckdb_compat::AstTarget(show);
			const auto &name = target[2];
			if (name == "\"variables\"") Unsafe(ctx, "SHOW VARIABLES exposes session variables");
			else if (name == "\"databases\"" || name == "\"schemas\"" || name == "\"tables\"" ||
			         name == "__show_tables_expanded") break;
			else if (name.empty()) Unsafe(ctx, "SHOW without inspectable target");
			else if (IsReplacementScanName(target[0], target[1], target[2]))
				Unsafe(ctx, "path-like SHOW target");
			else if (!(target[0].empty() && target[1].empty() && ctx.IsCte(LowerAscii(target[2]))))
				AddObject(req, target[0], target[1], target[2]);
		}
		break;
	}
	case duckdb::TableReferenceType::EMPTY_FROM:
	case duckdb::TableReferenceType::CTE:
	case duckdb::TableReferenceType::COLUMN_DATA:
	case duckdb::TableReferenceType::DELIM_GET:
	case duckdb::TableReferenceType::BOUND_TABLE_REF:
	case duckdb::TableReferenceType::INVALID:
		// Nothing to gate: literal VALUES lists, an empty FROM, a CTE
		// reference (its body is walked at the definition via cte_map), or an
		// already-bound ref — none is a policy-targetable object in v1.
		break;
	default:
		Unsafe(ctx, "unsupported table reference");
		break;
	}
}

void WalkCreate(const duckdb::CreateStatement &stmt, WalkCtx &ctx) {
	if (!stmt.info) { Unsafe(ctx, "null CREATE info"); return; }
	const auto &info = *stmt.info;
	switch (info.type) {
	case duckdb::CatalogType::TABLE_ENTRY: {
		const auto &table = static_cast<const duckdb::CreateTableInfo &>(info);
		const auto target = duckdb_compat::CreateTarget(table);
		AddObject(ctx.req, target[0], target[1], target[2]);
		if (table.query) {
			if (table.query->node) WalkQueryNode(*table.query->node, ctx);
			else Unsafe(ctx, "null CREATE TABLE query");
		}
		for (const auto &column : table.columns.Logical()) {
			if (column.Generated()) WalkExpression(column.GeneratedExpression(), ctx);
			else if (column.HasDefaultValue()) WalkExpression(column.DefaultValue(), ctx);
		}
		for (const auto &constraint : table.constraints) {
			if (!constraint) { Unsafe(ctx, "null CREATE TABLE constraint"); continue; }
			if (constraint->type == duckdb::ConstraintType::CHECK) {
				const auto &check = constraint->Cast<duckdb::CheckConstraint>();
				if (check.expression) WalkExpression(*check.expression, ctx);
				else Unsafe(ctx, "null CHECK expression");
			} else if (constraint->type != duckdb::ConstraintType::NOT_NULL &&
			           constraint->type != duckdb::ConstraintType::UNIQUE &&
			           constraint->type != duckdb::ConstraintType::FOREIGN_KEY) Unsafe(ctx, "unknown CREATE TABLE constraint");
		}
		duckdb_compat::VisitCreateTableExtras(table, [&](const auto &partition_keys, const auto &sort_keys,
		                                               const auto &options) {
			WalkExpressions(partition_keys, ctx);
			WalkExpressions(sort_keys, ctx);
			WalkNamedExpressions(options, ctx);
		});
		break;
	}
	case duckdb::CatalogType::VIEW_ENTRY: {
		const auto &view = static_cast<const duckdb::CreateViewInfo &>(info);
		const auto target = duckdb_compat::CreateTarget(view);
		AddObject(ctx.req, target[0], target[1], target[2]);
		if (view.query && view.query->node) WalkQueryNode(*view.query->node, ctx);
		else Unsafe(ctx, "null CREATE VIEW query");
		break;
	}
	case duckdb::CatalogType::TYPE_ENTRY: {
		const auto &type_info = static_cast<const duckdb::CreateTypeInfo &>(info);
		const auto target = duckdb_compat::CreateTarget(type_info);
		AddObject(ctx.req, target[0], target[1], target[2]);
		if (type_info.query) WalkStatement(*type_info.query, ctx);
		break;
	}
	case duckdb::CatalogType::MACRO_ENTRY:
	case duckdb::CatalogType::TABLE_MACRO_ENTRY: {
		const auto &macro = static_cast<const duckdb::CreateMacroInfo &>(info);
		const auto target = duckdb_compat::CreateTarget(macro);
		AddObject(ctx.req, target[0], target[1], target[2]);
		// A macro can execute later against a different catalog. Parse-only
		// inspection cannot safely bind its body here.
		Unsafe(ctx, "CREATE MACRO body requires catalog binding");
		break;
	}
	case duckdb::CatalogType::SCHEMA_ENTRY: {
		const auto &schema_info = static_cast<const duckdb::CreateSchemaInfo &>(info);
		const auto target = duckdb_compat::SchemaTarget(schema_info);
		if (!target[0].empty()) Unsafe(ctx, "catalog-qualified CREATE SCHEMA");
		if (target[1].empty()) Unsafe(ctx, "unnamed CREATE SCHEMA");
		else AddNamedObject(ctx.req, "schema:" + LowerAscii(target[1]));
		duckdb_compat::VisitCreateSchemaOptions(schema_info, [&](const auto &options) {
			WalkNamedExpressions(options, ctx);
		});
		break;
	}
	default:
		Unsafe(ctx, "unsupported CREATE body");
		break;
	}
}

void WalkDrop(const duckdb::DropStatement &stmt, WalkCtx &ctx) {
	if (!stmt.info) { Unsafe(ctx, "null DROP info"); return; }
	const auto &info = *stmt.info;
	if (info.type != duckdb::CatalogType::TABLE_ENTRY && info.type != duckdb::CatalogType::VIEW_ENTRY)
		Unsafe(ctx, "unsupported DROP entry type");
	const auto target = duckdb_compat::CreateTarget(info);
	if (target[2].empty()) Unsafe(ctx, "unnamed DROP target");
	else AddObject(ctx.req, target[0], target[1], target[2]);
}

void WalkAlter(const duckdb::AlterStatement &stmt, WalkCtx &ctx) {
	if (!stmt.info) { Unsafe(ctx, "null ALTER info"); return; }
	const auto &info = *stmt.info;
	const auto target = duckdb_compat::CreateTarget(info);
	if (target[2].empty()) Unsafe(ctx, "unnamed ALTER target");
	else AddObject(ctx.req, target[0], target[1], target[2]);
	if (info.type != duckdb::AlterType::ALTER_TABLE) { Unsafe(ctx, "unsupported ALTER kind"); return; }
	const auto &table = static_cast<const duckdb::AlterTableInfo &>(info);
	switch (table.alter_table_type) {
	case duckdb::AlterTableType::RENAME_COLUMN:
	case duckdb::AlterTableType::RENAME_TABLE:
	case duckdb::AlterTableType::REMOVE_COLUMN:
	case duckdb::AlterTableType::SET_NOT_NULL:
	case duckdb::AlterTableType::DROP_NOT_NULL:
		break;
	case duckdb::AlterTableType::ALTER_COLUMN_TYPE: {
		const auto &expr = static_cast<const duckdb::ChangeColumnTypeInfo &>(table).expression;
		if (expr) WalkExpression(*expr, ctx);
		else Unsafe(ctx, "null ALTER TYPE expression");
		break;
	}
	case duckdb::AlterTableType::SET_DEFAULT: {
		const auto &expr = static_cast<const duckdb::SetDefaultInfo &>(table).expression;
		if (expr) WalkExpression(*expr, ctx);
		break;
	}
	case duckdb::AlterTableType::ADD_COLUMN: {
		const auto &column = static_cast<const duckdb::AddColumnInfo &>(table).new_column;
		if (column.Generated()) WalkExpression(column.GeneratedExpression(), ctx);
		else if (column.HasDefaultValue()) WalkExpression(column.DefaultValue(), ctx);
		break;
	}
	default: Unsafe(ctx, "unsupported ALTER subtype"); break;
	}
}

Action ClassifyStatement(const duckdb::SQLStatement &s, WalkCtx &ctx) {
	switch (s.type) {
	case duckdb::StatementType::SELECT_STATEMENT:
	case duckdb::StatementType::EXPLAIN_STATEMENT:
	case duckdb::StatementType::RELATION_STATEMENT:
		return Action::Scan;
	case duckdb::StatementType::INSERT_STATEMENT:
		return Action::Insert;
	case duckdb::StatementType::UPDATE_STATEMENT:
		return Action::Update;
	case duckdb::StatementType::DELETE_STATEMENT:
		return Action::Delete;
	case duckdb::StatementType::MERGE_INTO_STATEMENT: {
		const auto &node = duckdb_compat::MergeNode(s.Cast<duckdb::MergeIntoStatement>());
		if (!MergeOnlyUpdates(node)) Unsafe(ctx, "MERGE has non-UPDATE action");
		return Action::Update;
	}
	case duckdb::StatementType::CREATE_STATEMENT:
	case duckdb::StatementType::DROP_STATEMENT:
	case duckdb::StatementType::ALTER_STATEMENT:
	case duckdb::StatementType::TRANSACTION_STATEMENT:
	case duckdb::StatementType::DETACH_STATEMENT:
		return Action::Ddl;
	case duckdb::StatementType::CREATE_FUNC_STATEMENT:
		Unsafe(ctx, "CREATE FUNCTION body is not inspectable");
		return Action::Ddl;
	case duckdb::StatementType::COPY_STATEMENT: {
		const auto &cs = s.Cast<duckdb::CopyStatement>();
		return (cs.info && cs.info->is_from) ? Action::CopyFrom : Action::CopyTo;
	}
	case duckdb::StatementType::ATTACH_STATEMENT:
		return Action::Attach;
	case duckdb::StatementType::PRAGMA_STATEMENT: {
		const auto &ps = s.Cast<duckdb::PragmaStatement>();
		if (!ps.info) { Unsafe(ctx, "null PRAGMA info"); return Action::Pragma; }
		const auto name = LowerAscii(duckdb_compat::Str(ps.info->name));
		if (name == "quack_serve" || name == "quack_stop" || name == "quack_restart") return Action::ServeAdmin;
		if (name.rfind("quack_oauth_", 0) == 0) Unsafe(ctx, "quack_oauth PRAGMA is not inspectable");
		if (!AllowedPragma(name)) Unsafe(ctx, "PRAGMA is not allowlisted");
		return Action::Pragma;
	}
	case duckdb::StatementType::SET_STATEMENT: {
		const auto &ss = static_cast<const duckdb::SetStatement &>(s);
		const auto name = LowerAscii(duckdb_compat::Str(ss.name));
		if (name.rfind("quack_oauth_", 0) == 0 || !AllowedSetting(name)) Unsafe(ctx, "SET/RESET is not allowlisted");
		if (ss.scope == duckdb::SetScope::GLOBAL) Unsafe(ctx, "GLOBAL SET/RESET changes shared state");
		if (ss.set_type != duckdb::SetType::SET) Unsafe(ctx, "RESET changes shared state");
		return Action::Pragma;
	}
	case duckdb::StatementType::LOAD_STATEMENT:
		Unsafe(ctx, "extension LOAD or INSTALL");
		return Action::Ddl;
	default:
		Unsafe(ctx, "unsupported statement type");
		return Action::Scan;
	}
}

void WalkStatement(const duckdb::SQLStatement &s, WalkCtx &ctx) {
	AuthzRequest &req = ctx.req;
	switch (s.type) {
	case duckdb::StatementType::SELECT_STATEMENT: {
		const auto &ss = s.Cast<duckdb::SelectStatement>();
		if (ss.node) {
			WalkQueryNode(*ss.node, ctx);
		}
		break;
	}
	case duckdb::StatementType::EXPLAIN_STATEMENT: {
		const auto &es = s.Cast<duckdb::ExplainStatement>();
		if (!es.stmt) Unsafe(ctx, "null EXPLAIN statement");
		else {
			if (es.explain_type == duckdb::ExplainType::EXPLAIN_ANALYZE) Unsafe(ctx, "EXPLAIN ANALYZE may execute SQL");
			// Apply the inner statement's classification checks (SET/PRAGMA/LOAD allowlists,
			// quack_oauth_* settings, GLOBAL scope): EXPLAIN must not launder a statement the
			// top-level path would reject. The request's action stays Scan.
			(void)ClassifyStatement(*es.stmt, ctx);
			WalkStatement(*es.stmt, ctx);
		}
		break;
	}
	case duckdb::StatementType::INSERT_STATEMENT: {
		const auto &is = s.Cast<duckdb::InsertStatement>();
		const auto &node = duckdb_compat::DmlNode(is);
		CteScope scope(ctx, node.cte_map);
		WalkInsert(node, ctx);
		break;
	}
	case duckdb::StatementType::UPDATE_STATEMENT: {
		const auto &us = s.Cast<duckdb::UpdateStatement>();
		const auto &node = duckdb_compat::DmlNode(us);
		CteScope scope(ctx, node.cte_map);
		WalkUpdate(node, ctx);
		break;
	}
	case duckdb::StatementType::DELETE_STATEMENT: {
		const auto &ds = s.Cast<duckdb::DeleteStatement>();
		const auto &node = duckdb_compat::DmlNode(ds);
		CteScope scope(ctx, node.cte_map);
		WalkDelete(node, ctx);
		break;
	}
	case duckdb::StatementType::MERGE_INTO_STATEMENT: {
		const auto &node = duckdb_compat::MergeNode(s.Cast<duckdb::MergeIntoStatement>());
		CteScope scope(ctx, node.cte_map);
		WalkMerge(node, ctx);
		break;
	}
	case duckdb::StatementType::COPY_STATEMENT: {
		const auto &cs = s.Cast<duckdb::CopyStatement>();
		if (cs.info) WalkCopyInfo(*cs.info, ctx);
		else Unsafe(ctx, "null COPY info");
		break;
	}
	case duckdb::StatementType::CREATE_STATEMENT:
		WalkCreate(s.Cast<duckdb::CreateStatement>(), ctx);
		break;
	case duckdb::StatementType::DROP_STATEMENT:
		WalkDrop(s.Cast<duckdb::DropStatement>(), ctx);
		break;
	case duckdb::StatementType::ALTER_STATEMENT:
		WalkAlter(s.Cast<duckdb::AlterStatement>(), ctx);
		break;
	case duckdb::StatementType::PRAGMA_STATEMENT: {
		const auto &ps = s.Cast<duckdb::PragmaStatement>();
		if (!ps.info) Unsafe(ctx, "null PRAGMA info");
		else {
			WalkExpressions(ps.info->parameters, ctx);
			WalkNamedExpressions(ps.info->named_parameters, ctx);
		}
		break;
	}
	case duckdb::StatementType::ATTACH_STATEMENT: {
		const auto &as = s.Cast<duckdb::AttachStatement>();
		if (!as.info) Unsafe(ctx, "null ATTACH info");
		else WalkNamedExpressions(as.info->parsed_options, ctx);
		break;
	}
	case duckdb::StatementType::DETACH_STATEMENT: {
		const auto &ds = s.Cast<duckdb::DetachStatement>();
		if (!ds.info) Unsafe(ctx, "null DETACH info");
		else {
			const auto name = LowerAscii(duckdb_compat::Str(ds.info->name));
			if (name.empty()) Unsafe(ctx, "unnamed DETACH target");
			else AddNamedObject(ctx.req, "catalog:" + name);
		}
		break;
	}
	case duckdb::StatementType::SET_STATEMENT: {
		const auto &base = s.Cast<duckdb::SetStatement>();
		if (base.set_type == duckdb::SetType::SET) {
			const auto &ss = static_cast<const duckdb::SetVariableStatement &>(base);
			if (!ss.value) Unsafe(ctx, "null SET value");
			else {
				WalkExpression(*ss.value, ctx);
				if (ss.value->GetExpressionClass() != duckdb::ExpressionClass::CONSTANT) Unsafe(ctx, "nonconstant SET value");
				if (LowerAscii(duckdb_compat::Str(base.name)) == "threads" && ss.value->ToString() != "4")
					Unsafe(ctx, "threads setting must be the approved value 4");
			}
		}
		break;
	}
	case duckdb::StatementType::LOAD_STATEMENT:
	case duckdb::StatementType::TRANSACTION_STATEMENT:
	case duckdb::StatementType::RELATION_STATEMENT:
		break;
	case duckdb::StatementType::CREATE_FUNC_STATEMENT:
		Unsafe(ctx, "CREATE FUNCTION body is not inspectable");
		break;
	default:
		Unsafe(ctx, "unsupported statement walk");
		break;
	}
}

} // namespace

AuthzRequest InspectSql(const std::string &query) {
	AuthzRequest req;
	if (query.empty()) {
		req.action = Action::Scan;
		return req;
	}
	duckdb::vector<duckdb::unique_ptr<duckdb::SQLStatement>> statements;
	try {
		// This parser has the built-in grammar only. Extension grammar that
		// cannot be parsed here fails closed below. If the execution parser
		// accepts a different built-in shape, add a regression case before
		// admitting it to the authorization path.
		statements = duckdb_compat::ParseBuiltin(query);
	} catch (const std::exception &e) {
		req.unsafe = true;
		req.error = e.what();
		return req;
	} catch (...) {
		req.unsafe = true;
		req.error = "parse_error";
		return req;
	}
	if (statements.empty()) {
		req.action = Action::Scan;
		return req;
	}
	// A single request can carry only one action. Mixed actions must be
	// rejected before the policy engine evaluates the combined object list.
	try {
		bool first = true;
		for (const auto &stmt : statements) {
			if (stmt) {
				// A CTE from one statement cannot shadow a later table.
				WalkCtx ctx {req, {}};
				const auto action = ClassifyStatement(*stmt, ctx);
				if (first) { req.action = action; first = false; }
				else if (action != req.action) Unsafe(ctx, "mixed statement actions");
				WalkStatement(*stmt, ctx);
			} else {
				req.unsafe = true;
				if (req.error.empty()) req.error = "null statement";
			}
		}
	} catch (const std::exception &e) {
		req.unsafe = true;
		req.error = e.what();
	} catch (...) {
		req.unsafe = true;
		req.error = "statement inspection error";
	}
	return req;
}

} // namespace quack_oauth
