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
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/group_by_node.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/statement/insert_statement.hpp"
#include "duckdb/parser/statement/update_statement.hpp"
#include "duckdb/parser/statement/delete_statement.hpp"
#include "duckdb/parser/statement/copy_statement.hpp"
#include "duckdb/parser/statement/pragma_statement.hpp"
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
#include "duckdb/logging/logger.hpp"

// DuckDB 1.5 restructured `SetOperationNode` from `left`/`right`
// unique_ptrs into a flat `children` vector. We probe a known 1.5-only
// macro from <duckdb/logging/logger.hpp> as the version sentinel
// (1.5 has `DUCKDB_LOG_WARNING`, 1.4 has `DUCKDB_LOG_WARN`).
#if defined(DUCKDB_LOG_WARNING)
#define QUACK_OAUTH_SETOP_HAS_CHILDREN 1
#else
#define QUACK_OAUTH_SETOP_HAS_CHILDREN 0
#endif

namespace quack_oauth {

namespace {

std::string LowerAscii(std::string_view s) {
	std::string out(s);
	std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
	return out;
}

// Match the `duckdb_*` family of metadata table functions + the well-
// known catalog schemas. Metadata reads don't need policy gating.
bool IsSystemObject(const std::string &qual) {
	static const std::string kSysPrefixes[] = {
	    "information_schema.", "pg_catalog.", "main.duckdb_", "system.information_schema.", "system.main.",
	};
	for (const auto &p : kSysPrefixes) {
		if (qual.rfind(p, 0) == 0) {
			return true;
		}
	}
	// Bare `duckdb_*` (no schema). We never insert these because
	// QualifiedName already prepends `main.`, but accept either form.
	if (qual.rfind("duckdb_", 0) == 0) {
		return true;
	}
	return false;
}

void AddObject(AuthzRequest &req, const std::string &catalog, const std::string &schema, const std::string &table) {
	if (table.empty()) {
		return;
	}
	// schema defaults to "main" if unset (DuckDB default).
	const auto sch = schema.empty() ? "main" : LowerAscii(schema);
	const auto tbl = LowerAscii(table);
	(void)catalog; // not enforced in v1 (cross-catalog policy can come later)
	auto qual = sch + "." + tbl;
	if (IsSystemObject(qual)) {
		return;
	}
	if (std::find(req.objects.begin(), req.objects.end(), qual) == req.objects.end()) {
		req.objects.push_back(std::move(qual));
	}
}

// The `duckdb_*` metadata table functions mirror `information_schema.*` /
// `pg_catalog.*`, which `IsSystemObject` already exempts. Gating only the
// function spelling would buy nothing -- `duckdb_tables()` and
// `information_schema.tables` expose the same rows -- while breaking the
// introspection every BI client issues. So exempt the family, minus the
// members that carry credential material and have no catalog-view twin:
// `duckdb_secrets` is the cross-join defeat F1 closed, and DuckDB settings
// have historically included keys such as `s3_secret_access_key`.
bool IsExemptFunction(const std::string &name) {
	static const std::string kNeverExempt[] = {"duckdb_secrets", "duckdb_settings"};
	if (name.rfind("duckdb_", 0) != 0) {
		return false;
	}
	for (const auto &n : kNeverExempt) {
		if (name == n) {
			return false;
		}
	}
	return true;
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

void WalkExpression(const duckdb::ParsedExpression &expr, WalkCtx &ctx) {
	AuthzRequest &req = ctx.req;
	if (expr.GetExpressionClass() == duckdb::ExpressionClass::COLUMN_REF) {
		const auto &cr = expr.Cast<duckdb::ColumnRefExpression>();
		if (!cr.column_names.empty()) {
			AddColumn(req, cr.column_names.back());
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
		if (sq.subquery && sq.subquery->node) {
			WalkQueryNode(*sq.subquery->node, ctx);
		}
	}
	duckdb::ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const duckdb::ParsedExpression &child) { WalkExpression(child, ctx); });
}

void WalkQueryNode(const duckdb::QueryNode &qn, WalkCtx &ctx) {
	AuthzRequest &req = ctx.req;
	switch (qn.type) {
	case duckdb::QueryNodeType::SELECT_NODE: {
		const auto &sn = qn.Cast<duckdb::SelectNode>();
		// Register CTE aliases before walking anything: a `FROM c` in this
		// node -- or in a nested subquery, where the CTE is still in scope --
		// must be recognised as the CTE, not as a table (see WalkCtx).
		for (const auto &kv : sn.cte_map.map) {
			const auto cte_name = LowerAscii(kv.first);
			if (!ctx.IsCte(cte_name)) {
				ctx.cte_names.push_back(cte_name);
			}
		}
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
		// CTE bodies are real objects -- walk them. The aliases were
		// registered above.
		for (const auto &kv : sn.cte_map.map) {
			if (kv.second && kv.second->query && kv.second->query->node) {
				WalkQueryNode(*kv.second->query->node, ctx);
			}
		}
		break;
	}
	case duckdb::QueryNodeType::SET_OPERATION_NODE: {
		// DuckDB 1.5 flattened the set-operation arms into a `children`
		// vector; 1.4 LTS still exposes them as separate `left` / `right`
		// unique_ptrs.
		const auto &son = qn.Cast<duckdb::SetOperationNode>();
#if QUACK_OAUTH_SETOP_HAS_CHILDREN
		for (const auto &child : son.children) {
			if (child) {
				WalkQueryNode(*child, ctx);
			}
		}
#else
		if (son.left) {
			WalkQueryNode(*son.left, ctx);
		}
		if (son.right) {
			WalkQueryNode(*son.right, ctx);
		}
#endif
		break;
	}
	case duckdb::QueryNodeType::CTE_NODE: {
		// DuckDB 1.4.x parses a WITH clause into a CTENode wrapping the rest
		// of the query, rather than attaching it to a SelectNode's cte_map
		// the way 1.5.x does. Without this case the whole select half went
		// unwalked on the LTS line -- every statement containing a WITH
		// collected zero objects, which is not a fail-closed state: a
		// zero-object request skips every rule that carries an
		// object_pattern (see policy.cpp), so an object-scoped deny could be
		// laundered through a CTE. Handle both shapes on both versions.
		const auto &cn = qn.Cast<duckdb::CTENode>();
		const auto cte_name = LowerAscii(cn.ctename);
		if (!cte_name.empty() && !ctx.IsCte(cte_name)) {
			ctx.cte_names.push_back(cte_name);
		}
		if (cn.query) {
			WalkQueryNode(*cn.query, ctx);
		}
		if (cn.child) {
			WalkQueryNode(*cn.child, ctx);
		}
		break;
	}
	case duckdb::QueryNodeType::RECURSIVE_CTE_NODE: {
		const auto &rn = qn.Cast<duckdb::RecursiveCTENode>();
		const auto cte_name = LowerAscii(rn.ctename);
		if (!cte_name.empty() && !ctx.IsCte(cte_name)) {
			ctx.cte_names.push_back(cte_name);
		}
		if (rn.left) {
			WalkQueryNode(*rn.left, ctx);
		}
		if (rn.right) {
			WalkQueryNode(*rn.right, ctx);
		}
		break;
	}
	default:
		// BOUND_SUBQUERY_NODE and friends: nothing parse-level to walk.
		break;
	}
}

void WalkTableRef(const duckdb::TableRef &ref, WalkCtx &ctx) {
	AuthzRequest &req = ctx.req;
	switch (ref.type) {
	case duckdb::TableReferenceType::BASE_TABLE: {
		const auto &bt = ref.Cast<duckdb::BaseTableRef>();
		// An unqualified name matching a CTE in scope is a reference to that
		// CTE, not to a table. Only bare names qualify -- an explicit
		// `main.c` still gates.
		if (bt.catalog_name.empty() && bt.schema_name.empty() && ctx.IsCte(LowerAscii(bt.table_name))) {
			break;
		}
		AddObject(req, bt.catalog_name, bt.schema_name, bt.table_name);
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
		break;
	}
	case duckdb::TableReferenceType::SUBQUERY: {
		const auto &sr = ref.Cast<duckdb::SubqueryRef>();
		if (sr.subquery && sr.subquery->node) {
			WalkQueryNode(*sr.subquery->node, ctx);
		}
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
			fn_name = tf.function->Cast<duckdb::FunctionExpression>().function_name;
		}
		if (fn_name.empty()) {
			// A table function we cannot name is one we cannot gate by rule —
			// fail closed rather than let it through unsurfaced.
			req.unsafe = true;
			req.error = "unnamed table function";
		} else {
			AddFunctionObject(req, fn_name);
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
		break;
	}
	case duckdb::TableReferenceType::EXPRESSION_LIST:
	case duckdb::TableReferenceType::EMPTY_FROM:
	case duckdb::TableReferenceType::CTE:
	case duckdb::TableReferenceType::SHOW_REF:
	case duckdb::TableReferenceType::COLUMN_DATA:
	case duckdb::TableReferenceType::DELIM_GET:
	case duckdb::TableReferenceType::BOUND_TABLE_REF:
	case duckdb::TableReferenceType::INVALID:
		// Nothing to gate: literal VALUES lists, an empty FROM, a CTE
		// reference (its body is walked at the definition via cte_map), or an
		// already-bound ref — none is a policy-targetable object in v1.
		break;
	}
}

Action ClassifyStatement(const duckdb::SQLStatement &s) {
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
	case duckdb::StatementType::CREATE_STATEMENT:
	case duckdb::StatementType::DROP_STATEMENT:
	case duckdb::StatementType::ALTER_STATEMENT:
	case duckdb::StatementType::TRANSACTION_STATEMENT:
	case duckdb::StatementType::CREATE_FUNC_STATEMENT:
	case duckdb::StatementType::DETACH_STATEMENT:
		return Action::Ddl;
	case duckdb::StatementType::COPY_STATEMENT: {
		const auto &cs = s.Cast<duckdb::CopyStatement>();
		return (cs.info && cs.info->is_from) ? Action::CopyFrom : Action::CopyTo;
	}
	case duckdb::StatementType::ATTACH_STATEMENT:
		return Action::Attach;
	case duckdb::StatementType::PRAGMA_STATEMENT: {
		const auto &ps = s.Cast<duckdb::PragmaStatement>();
		if (ps.info) {
			const auto name = LowerAscii(ps.info->name);
			if (name == "quack_serve" || name == "quack_stop" || name == "quack_restart") {
				return Action::ServeAdmin;
			}
		}
		return Action::Pragma;
	}
	case duckdb::StatementType::SET_STATEMENT:
	case duckdb::StatementType::VARIABLE_SET_STATEMENT:
	case duckdb::StatementType::LOAD_STATEMENT:
		// SET / LOAD aren't data-bearing; classify as Pragma so a
		// rule with actions=['Pragma'] gates them.
		return Action::Pragma;
	default:
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
		// Walk the inner statement's objects/columns.
		// EXPLAIN wraps a child statement we'd want to gate the same way.
		// Skipped for v1: most operators allow EXPLAIN broadly. Keep an
		// EXPLAIN result classified as Scan but with no objects -- the
		// rule writer can deny ['Scan'] unconditionally if needed.
		break;
	}
	case duckdb::StatementType::INSERT_STATEMENT: {
		const auto &is = s.Cast<duckdb::InsertStatement>();
		AddObject(req, is.catalog, is.schema, is.table);
		if (is.select_statement && is.select_statement->node) {
			WalkQueryNode(*is.select_statement->node, ctx);
		}
		if (is.table_ref) {
			WalkTableRef(*is.table_ref, ctx);
		}
		break;
	}
	case duckdb::StatementType::UPDATE_STATEMENT: {
		const auto &us = s.Cast<duckdb::UpdateStatement>();
		if (us.table) {
			WalkTableRef(*us.table, ctx);
		}
		if (us.from_table) {
			WalkTableRef(*us.from_table, ctx);
		}
		break;
	}
	case duckdb::StatementType::DELETE_STATEMENT: {
		const auto &ds = s.Cast<duckdb::DeleteStatement>();
		if (ds.table) {
			WalkTableRef(*ds.table, ctx);
		}
		for (const auto &uref : ds.using_clauses) {
			if (uref) {
				WalkTableRef(*uref, ctx);
			}
		}
		break;
	}
	case duckdb::StatementType::COPY_STATEMENT: {
		const auto &cs = s.Cast<duckdb::CopyStatement>();
		if (cs.info) {
			AddObject(req, cs.info->catalog, cs.info->schema, cs.info->table);
			if (cs.info->select_statement) {
				WalkQueryNode(*cs.info->select_statement, ctx);
			}
		}
		break;
	}
	default:
		// ATTACH / DETACH / PRAGMA / SET / LOAD / DDL: no
		// policy-relevant objects beyond the action.
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
	duckdb::Parser parser;
	try {
		parser.ParseQuery(query);
	} catch (const std::exception &e) {
		req.unsafe = true;
		req.error = e.what();
		return req;
	} catch (...) {
		req.unsafe = true;
		req.error = "parse_error";
		return req;
	}
	if (parser.statements.empty()) {
		req.action = Action::Scan;
		return req;
	}
	// Classify on the first statement; collect objects/columns from all.
	req.action = ClassifyStatement(*parser.statements.front());
	for (const auto &stmt : parser.statements) {
		if (stmt) {
			// Fresh CTE scope per statement: `WITH t AS (…) SELECT * FROM t;
			// SELECT * FROM t;` must still gate the second `t`, which is a
			// real table.
			WalkCtx ctx {req, {}};
			WalkStatement(*stmt, ctx);
		}
	}
	return req;
}

} // namespace quack_oauth
