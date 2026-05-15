#pragma once

#include <string_view>

#include "authz.hpp"

namespace quack_oauth {

// Heuristically classify a quack `query_string` into one of the five Actions
// the policy gates on (R-S-7). Conservative default: anything we don't
// recognise maps to `Scan`, the read-only action.
//
// Detection is keyword-based on the first SQL statement:
//   ATTACH ...        → Attach
//   COPY ... TO ...   → CopyTo
//   COPY ... FROM ... → CopyFrom
//   PRAGMA quack_*    → ServeAdmin   (administrative knobs on quack itself)
//   SELECT / WITH / SHOW / DESCRIBE / ... → Scan
//   anything else     → Scan         (fail-safe to the most restrictive
//                                     non-write action)
//
// Leading whitespace + `--` line comments and `/* ... */` block comments
// are stripped before keyword matching.
Action DetectAction(std::string_view query_string);

} // namespace quack_oauth
