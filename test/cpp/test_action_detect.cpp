#include <catch2/catch_test_macros.hpp>

#include "action_detect.hpp"
#include "authz.hpp"

using quack_oauth::Action;
using quack_oauth::DetectAction;

TEST_CASE("DetectAction: SELECT and friends → Scan", "[action-detect]") {
	CHECK(DetectAction("SELECT 1") == Action::Scan);
	CHECK(DetectAction("select * from t") == Action::Scan);
	CHECK(DetectAction("WITH cte AS (SELECT 1) SELECT * FROM cte") == Action::Scan);
	CHECK(DetectAction("SHOW TABLES") == Action::Scan);
	CHECK(DetectAction("DESCRIBE t") == Action::Scan);
	CHECK(DetectAction("VALUES (1)") == Action::Scan);
}

TEST_CASE("DetectAction: ATTACH", "[action-detect]") {
	CHECK(DetectAction("ATTACH 'quack:rs.example.com' AS r") == Action::Attach);
	CHECK(DetectAction("  attach 'foo'") == Action::Attach);
}

TEST_CASE("DetectAction: COPY direction is detected from TO / FROM", "[action-detect][copy]") {
	CHECK(DetectAction("COPY t TO 'file.csv'") == Action::CopyTo);
	CHECK(DetectAction("COPY t FROM 'file.csv'") == Action::CopyFrom);
	CHECK(DetectAction("copy (select 1) to 'out.csv' (format csv)") == Action::CopyTo);
	// Unrecognised COPY shape -- conservative Scan fallback.
	CHECK(DetectAction("COPY") == Action::Scan);
}

TEST_CASE("DetectAction: PRAGMA quack_* → ServeAdmin", "[action-detect][admin]") {
	CHECK(DetectAction("PRAGMA quack_serve('rs.example.com', 'token')") == Action::ServeAdmin);
	CHECK(DetectAction("pragma quack_stop") == Action::ServeAdmin);
	// Non-admin pragmas are scans.
	CHECK(DetectAction("PRAGMA version") == Action::Scan);
}

TEST_CASE("DetectAction: leading comments + whitespace are skipped", "[action-detect]") {
	CHECK(DetectAction("\n\t  SELECT 1") == Action::Scan);
	CHECK(DetectAction("-- a comment\nSELECT 1") == Action::Scan);
	CHECK(DetectAction("/* block */ ATTACH 'x' AS y") == Action::Attach);
	CHECK(DetectAction("-- c1\n-- c2\n  COPY t FROM 'x'") == Action::CopyFrom);
}

TEST_CASE("DetectAction: unknown / write statements map to Scan", "[action-detect]") {
	// These are write statements at the SQL level, but our authz only
	// distinguishes the 5 quack-level actions. They route to Scan;
	// the default policy still denies them via missing write scope when
	// it matters. A future schema extension to the policy table could
	// carve write further.
	CHECK(DetectAction("INSERT INTO t VALUES (1)") == Action::Scan);
	CHECK(DetectAction("UPDATE t SET x = 1") == Action::Scan);
	CHECK(DetectAction("DELETE FROM t") == Action::Scan);
	CHECK(DetectAction("CREATE TABLE t (i INT)") == Action::Scan);
	CHECK(DetectAction("DROP TABLE t") == Action::Scan);
	CHECK(DetectAction("") == Action::Scan);
	CHECK(DetectAction("   ") == Action::Scan);
}
