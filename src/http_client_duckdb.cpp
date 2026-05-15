#include "http_client_duckdb.hpp"

#include <chrono>
#include <string>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

namespace duckdb {

namespace {

// Minimal URL splitter: scheme, host, port, path-and-query. We don't need a
// full RFC 3986 parser -- JWKS / introspection URLs are well-known shapes.
struct UrlParts {
	std::string scheme;
	std::string host;
	int port = -1;
	std::string path; // includes the leading '/' and any query string
};

bool ParseUrl(std::string_view url, UrlParts &out) {
	const auto scheme_end = url.find("://");
	if (scheme_end == std::string_view::npos) {
		return false;
	}
	out.scheme = std::string(url.substr(0, scheme_end));
	const auto rest_off = scheme_end + 3;
	const auto path_off = url.find('/', rest_off);

	const auto host_part = (path_off == std::string_view::npos)
	                           ? url.substr(rest_off)
	                           : url.substr(rest_off, path_off - rest_off);
	out.path = (path_off == std::string_view::npos)
	               ? std::string("/")
	               : std::string(url.substr(path_off));

	const auto colon = host_part.rfind(':');
	if (colon == std::string_view::npos) {
		out.host = std::string(host_part);
		out.port = (out.scheme == "https") ? 443 : 80;
	} else {
		out.host = std::string(host_part.substr(0, colon));
		try {
			out.port = std::stoi(std::string(host_part.substr(colon + 1)));
		} catch (...) {
			return false;
		}
	}
	return !out.host.empty();
}

template <typename Client>
std::optional<quack_oauth::IHttpClient::Response>
DoGet(Client &client, const std::string &path) {
	client.set_connection_timeout(std::chrono::seconds(5));
	client.set_read_timeout(std::chrono::seconds(10));
	auto result = client.Get(path.c_str());
	if (!result) {
		return std::nullopt;
	}
	quack_oauth::IHttpClient::Response out;
	out.status_code = result->status;
	out.body = std::move(result->body);
	return out;
}

template <typename Client>
std::optional<quack_oauth::IHttpClient::Response>
DoPost(Client &client, const std::string &path,
       const quack_oauth::IHttpClient::PostRequest &req) {
	client.set_connection_timeout(std::chrono::seconds(5));
	client.set_read_timeout(std::chrono::seconds(10));
	if (!req.basic_user.empty()) {
		client.set_basic_auth(req.basic_user, req.basic_pass);
	}
	auto result =
	    client.Post(path.c_str(), req.body, req.content_type.c_str());
	if (!result) {
		return std::nullopt;
	}
	quack_oauth::IHttpClient::Response out;
	out.status_code = result->status;
	out.body = std::move(result->body);
	return out;
}

} // namespace

std::optional<quack_oauth::IHttpClient::Response>
DuckdbHttpClient::Get(std::string_view url) {
	UrlParts u;
	if (!ParseUrl(url, u)) {
		return std::nullopt;
	}
	if (u.scheme == "https") {
		duckdb_httplib_openssl::SSLClient client(u.host, u.port);
		client.enable_server_certificate_verification(true);
		return DoGet(client, u.path);
	}
	if (u.scheme == "http") {
		duckdb_httplib_openssl::Client client(u.host, u.port);
		return DoGet(client, u.path);
	}
	return std::nullopt;
}

std::optional<quack_oauth::IHttpClient::Response>
DuckdbHttpClient::Post(const quack_oauth::IHttpClient::PostRequest &req) {
	UrlParts u;
	if (!ParseUrl(req.url, u)) {
		return std::nullopt;
	}
	if (u.scheme == "https") {
		duckdb_httplib_openssl::SSLClient client(u.host, u.port);
		client.enable_server_certificate_verification(true);
		return DoPost(client, u.path, req);
	}
	if (u.scheme == "http") {
		duckdb_httplib_openssl::Client client(u.host, u.port);
		return DoPost(client, u.path, req);
	}
	return std::nullopt;
}

} // namespace duckdb
