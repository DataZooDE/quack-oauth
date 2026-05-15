// DuckDB-coupled tracing sink. Empty in slice S-0 -- the Logger wiring
// lands when the first actual call site needs it (slice S-2 or later).
//
// This file exists so the build system can split pure-logic (`tracing_redact.cpp`,
// Catch2-testable) from DuckDB-coupled tracing without a special-case in
// CMakeLists.txt. See docs/IMPLEMENTATION.md section 2.3.
