#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <jwt-cpp/traits/kazuho-picojson/defaults.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "http_client.hpp"
#include "jwks_cache.hpp"
#include "jwt_verify.hpp"
#include "validator.hpp"

using quack_oauth::IHttpClient;
using quack_oauth::Jwk;
using quack_oauth::JwksCache;
using quack_oauth::ValidateContext;
using quack_oauth::ValidateToken;
using quack_oauth::VerifyOptions;
using quack_oauth::VerifyResult;

namespace {

using TraitsT = jwt::traits::kazuho_picojson;

std::string B64UrlNoPad(const std::string &raw) {
	auto s = jwt::base::encode<jwt::alphabet::base64url>(raw);
	// See test_jwt_verify.cpp -- jwt-cpp's encoder uses "%3d" for padding.
	while (s.size() >= 3 && s.substr(s.size() - 3) == "%3d") {
		s.resize(s.size() - 3);
	}
	while (!s.empty() && s.back() == '=') {
		s.pop_back();
	}
	return s;
}

struct TestKey {
	std::string priv_pem;
	Jwk jwk;
};

const TestKey &GetValidatorKey() {
	static const TestKey k = [] {
		EVP_PKEY *pkey = EVP_RSA_gen(2048);
		REQUIRE(pkey != nullptr);

		BIO *priv_bio = BIO_new(BIO_s_mem());
		PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
		char *priv_data = nullptr;
		const long priv_len = BIO_get_mem_data(priv_bio, &priv_data);
		std::string priv_pem(priv_data, static_cast<std::size_t>(priv_len));
		BIO_free(priv_bio);

		BIGNUM *n_bn = nullptr;
		BIGNUM *e_bn = nullptr;
		EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n_bn);
		EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e_bn);

		auto bn_to_b64url = [](const BIGNUM *bn) {
			std::vector<unsigned char> buf(static_cast<std::size_t>(BN_num_bytes(bn)));
			BN_bn2bin(bn, buf.data());
			return B64UrlNoPad(std::string(buf.begin(), buf.end()));
		};

		Jwk jwk;
		jwk.kid = "validator-key-1";
		jwk.kty = "RSA";
		jwk.alg = "RS256";
		jwk.use = "sig";
		jwk.n = bn_to_b64url(n_bn);
		jwk.e = bn_to_b64url(e_bn);

		BN_free(n_bn);
		BN_free(e_bn);
		EVP_PKEY_free(pkey);

		return TestKey {std::move(priv_pem), std::move(jwk)};
	}();
	return k;
}

std::string Sign(const TestKey &k, std::int64_t exp_s, std::int64_t iat_s) {
	return jwt::create<TraitsT>()
	    .set_type("JWT")
	    .set_key_id(k.jwk.kid)
	    .set_issuer("https://idp.test")
	    .set_subject("alice")
	    .set_audience("api://quack")
	    .set_issued_at(std::chrono::system_clock::time_point(std::chrono::seconds(iat_s)))
	    .set_expires_at(std::chrono::system_clock::time_point(std::chrono::seconds(exp_s)))
	    .sign(jwt::algorithm::rs256("", k.priv_pem, "", ""));
}

std::string JwksWith(const Jwk &j) {
	// Hand-rolled JSON to avoid pulling picojson into the test.
	auto quote = [](const std::string &s) {
		return std::string("\"") + s + "\"";
	};
	std::string body = "{\"keys\":[{";
	body += quote("kid") + ":" + quote(j.kid) + ",";
	body += quote("kty") + ":" + quote(j.kty) + ",";
	body += quote("alg") + ":" + quote(j.alg) + ",";
	body += quote("use") + ":" + quote(j.use) + ",";
	body += quote("n") + ":" + quote(j.n) + ",";
	body += quote("e") + ":" + quote(j.e);
	body += "}]}";
	return body;
}

VerifyOptions BaseOpts(std::int64_t now_s = 1700000000) {
	VerifyOptions opts;
	opts.expected_issuer = "https://idp.test";
	opts.expected_audience = "api://quack";
	opts.clock_skew_s = 60;
	opts.now_s = now_s;
	opts.allowed_algorithms = {"RS256", "RS384", "RS512"};
	return opts;
}

class FakeHttpClient : public IHttpClient {
public:
	int call_count = 0;
	std::optional<Response> next_response;
	std::optional<std::string> last_url;

	std::optional<Response> Get(std::string_view url) override {
		++call_count;
		last_url = std::string(url);
		return next_response;
	}
};

} // namespace

TEST_CASE("Validator: cache hit short-circuits the HTTP fetch", "[validator][cache-hit]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);
	cache.OnFetchSuccess(k.jwk, 1700000000);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(k, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: cache miss triggers a fetch, populates, then verifies", "[validator][cache-miss]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(k.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(k, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
	CHECK(http.last_url.value_or("") == "https://idp.test/jwks");
	CHECK(cache.Size() == 1);
}

TEST_CASE("Validator: rate-limited cache returns UnknownKid without fetching", "[validator][rate-limit]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);
	cache.OnFetchMiss(k.jwk.kid, 1700000000);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(k, 1700003600, 1700000000);
	// 10s after the recorded miss -- inside the 30s rate-limit window.
	CHECK(ValidateToken(token, BaseOpts(1700000010), ctx) == VerifyResult::UnknownKid);
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: HTTP failure surfaces as JwksFetchFailed", "[validator][http-fail]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);

	FakeHttpClient http;
	http.next_response = std::nullopt; // network error -- no response at all
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(k, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::JwksFetchFailed);
	CHECK(cache.Size() == 0);
}

TEST_CASE("Validator: HTTP non-200 surfaces as JwksFetchFailed", "[validator][http-fail]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {503, "service unavailable"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(k, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::JwksFetchFailed);
}

TEST_CASE("Validator: kid absent from JWKS response records a miss", "[validator][unknown-kid]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);

	// Build a JWKS doc that contains a DIFFERENT key, not the one the token
	// is signed with.
	Jwk other = k.jwk;
	other.kid = "different-kid";

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(other)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(k, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::UnknownKid);

	// A subsequent call within the rate-limit window short-circuits.
	http.next_response.reset();
	CHECK(ValidateToken(token, BaseOpts(1700000010), ctx) == VerifyResult::UnknownKid);
	CHECK(http.call_count == 1); // no second fetch
}

TEST_CASE("Validator: forbidden algorithm rejected before any cache access", "[validator][alg]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// HS256 token; the validator MUST reject before touching cache or HTTP.
	const auto token = jwt::create<TraitsT>()
	                       .set_type("JWT")
	                       .set_key_id(k.jwk.kid)
	                       .set_issuer("https://idp.test")
	                       .set_audience("api://quack")
	                       .set_expires_at(std::chrono::system_clock::time_point(std::chrono::seconds(1700003600)))
	                       .sign(jwt::algorithm::hs256 {"shared-secret"});
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::DisallowedAlgorithm);
	CHECK(http.call_count == 0);
	CHECK(cache.Size() == 0);
}

TEST_CASE("Validator: malformed token rejected before any cache access", "[validator][malformed]") {
	JwksCache cache(30);
	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	CHECK(ValidateToken("not-a-jwt", BaseOpts(), ctx) == VerifyResult::Malformed);
	CHECK(http.call_count == 0);
}
