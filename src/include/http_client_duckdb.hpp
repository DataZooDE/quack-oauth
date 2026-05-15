#pragma once

#include "http_client.hpp"

namespace duckdb {

// Concrete `IHttpClient` for the native extension target, backed by
// `duckdb/third_party/httplib` (the `duckdb_httplib_openssl` namespace).
//
// This class is intentionally NOT part of `PURE_SOURCES` -- it has DuckDB
// and OpenSSL transitive includes, so it is not compiled into the Catch2
// unit-test binary. The Catch2 layer exercises `Validator` via the
// `FakeHttpClient` test double in `test/cpp/test_validator.cpp`.
class DuckdbHttpClient : public quack_oauth::IHttpClient {
public:
	DuckdbHttpClient() = default;
	~DuckdbHttpClient() override = default;

	std::optional<Response> Get(std::string_view url) override;
	std::optional<Response> Post(const PostRequest &req) override;
};

} // namespace duckdb
