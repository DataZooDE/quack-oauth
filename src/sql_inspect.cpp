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
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/statement/insert_statement.hpp"
#include "duckdb/parser/statement/update_statement.hpp"
#include "duckdb/parser/statement/delete_statement.hpp"
#include "duckdb/parser/statement/copy_statement.hpp"
#include "duckdb/parser/statement/pragma_statement.hpp"
#include "duckdb/parser/query_node.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/query_node/set_operation_node.hpp"
#include "duckdb/parser/expression/columnref_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parsed_data/copy_info.hpp"
#include "duckdb/parser/parsed_data/pragma_info.hpp"
#include "duckdb/common/exception.hpp"

namespace quack_oauth {

namespace {

std::string LowerAscii(std::string_view s) {
	std::string out(s);
	std::transform(out.begin(), out.end(), out.begin(),
	               [](unsigned char c) { return std::tolower(c); });
	return out;
}

// Match the `duckdb_*` family of metadata table functions + the well-
// known catalog schemas. Metadata reads don't need policy gating.
bool IsSystemObject(const std::string &qual) {
	static const std::string kSysPrefixes[] = {
	    "information_schema.", "pg_catalog.", "main.duckdb_",
	    "system.information_schema.", "system.main.",
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

void AddObject(AuthzRequest &req, const std::string &catalog, const std::string &schema,
               const std::string &table) {
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

void AddColumn(AuthzRequest &req, const std::string &col) {
	if (col.empty()) {
		return;
	}
	const auto c = LowerAscii(col);
	if (std::find(req.columns.begin(), req.columns.end(), c) == req.columns.end()) {
		req.columns.push_back(c);
	}
}

void WalkTableRef(const duckdb::TableRef &ref, AuthzRequest &req);

void WalkExpression(const duckdb::ParsedExpression &expr, AuthzRequest &req) {
	if (expr.GetExpressionClass() == duckdb::ExpressionClass::COLUMN_REF) {
		const auto &cr = expr.Cast<duckdb::ColumnRefExpression>();
		if (!cr.column_names.empty()) {
			AddColumn(req, cr.column_names.back());
		}
	} else if (expr.GetExpressionClass() == duckdb::ExpressionClass::STAR) {
		AddColumn(req, "*");
	}
	duckdb::ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const duckdb::ParsedExpression &child) { WalkExpression(child, req); });
}

void WalkQueryNode(const duckdb::QueryNode &qn, AuthzRequest &req) {
	switch (qn.type) {
	case duckdb::QueryNodeType::SELECT_NODE: {
		const auto &sn = qn.Cast<duckdb::SelectNode>();
		if (sn.from_table) {
			WalkTableRef(*sn.from_table, req);
		}
		for (const auto &expr : sn.select_list) {
			if (expr) {
				WalkExpression(*expr, req);
			}
		}
		// CTE definitions
		for (const auto &kv : sn.cte_map.map) {
			if (kv.second && kv.second->query && kv.second->query->node) {
				WalkQueryNode(*kv.second->query->node, req);
			}
		}
		break;
	}
	case duckdb::QueryNodeType::SET_OPERATION_NODE: {
		// In current DuckDB the set-operation node stores its arms as
		// a `children` vector; the legacy `left` / `right` accessors
		// were removed.
		const auto &son = qn.Cast<duckdb::SetOperationNode>();
		for (const auto &child : son.children) {
			if (child) {
				WalkQueryNode(*child, req);
			}
		}
		break;
	}
	default:
		// CTE_NODE / RECURSIVE_CTE_NODE / BOUND_SUBQUERY_NODE: walk
		// children if present. We don't unwrap exhaustively; the
		// parent SelectStatement already covers the typical shapes.
		break;
	}
}

void WalkTableRef(const duckdb::TableRef &ref, AuthzRequest &req) {
	switch (ref.type) {
	case duckdb::TableReferenceType::BASE_TABLE: {
		const auto &bt = ref.Cast<duckdb::BaseTableRef>();
		AddObject(req, bt.catalog_name, bt.schema_name, bt.table_name);
		break;
	}
	case duckdb::TableReferenceType::JOIN: {
		const auto &jr = ref.Cast<duckdb::JoinRef>();
		if (jr.left) {
			WalkTableRef(*jr.left, req);
		}
		if (jr.right) {
			WalkTableRef(*jr.right, req);
		}
		break;
	}
	case duckdb::TableReferenceType::SUBQUERY: {
		const auto &sr = ref.Cast<duckdb::SubqueryRef>();
		if (sr.subquery && sr.subquery->node) {
			WalkQueryNode(*sr.subquery->node, req);
		}
		break;
	}
	case duckdb::TableReferenceType::TABLE_FUNCTION:
	case duckdb::TableReferenceType::EXPRESSION_LIST:
	case duckdb::TableReferenceType::EMPTY_FROM:
	case duckdb::TableReferenceType::PIVOT:
	case duckdb::TableReferenceType::CTE:
	case duckdb::TableReferenceType::SHOW_REF:
	case duckdb::TableReferenceType::COLUMN_DATA:
	case duckdb::TableReferenceType::DELIM_GET:
	case duckdb::TableReferenceType::BOUND_TABLE_REF:
	case duckdb::TableReferenceType::INVALID:
		// Nothing to gate: either non-base or already-bound, neither
		// of which we surface as a policy-targetable object in v1.
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

void WalkStatement(const duckdb::SQLStatement &s, AuthzRequest &req) {
	switch (s.type) {
	case duckdb::StatementType::SELECT_STATEMENT: {
		const auto &ss = s.Cast<duckdb::SelectStatement>();
		if (ss.node) {
			WalkQueryNode(*ss.node, req);
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
			WalkQueryNode(*is.select_statement->node, req);
		}
		if (is.table_ref) {
			WalkTableRef(*is.table_ref, req);
		}
		break;
	}
	case duckdb::StatementType::UPDATE_STATEMENT: {
		const auto &us = s.Cast<duckdb::UpdateStatement>();
		if (us.table) {
			WalkTableRef(*us.table, req);
		}
		if (us.from_table) {
			WalkTableRef(*us.from_table, req);
		}
		break;
	}
	case duckdb::StatementType::DELETE_STATEMENT: {
		const auto &ds = s.Cast<duckdb::DeleteStatement>();
		if (ds.table) {
			WalkTableRef(*ds.table, req);
		}
		for (const auto &uref : ds.using_clauses) {
			if (uref) {
				WalkTableRef(*uref, req);
			}
		}
		break;
	}
	case duckdb::StatementType::COPY_STATEMENT: {
		const auto &cs = s.Cast<duckdb::CopyStatement>();
		if (cs.info) {
			AddObject(req, cs.info->catalog, cs.info->schema, cs.info->table);
			if (cs.info->select_statement) {
				WalkQueryNode(*cs.info->select_statement, req);
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
			WalkStatement(*stmt, req);
		}
	}
	return req;
}

} // namespace quack_oauth
