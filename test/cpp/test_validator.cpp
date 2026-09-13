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
#include "decision_cache.hpp"
#include "jwks_cache.hpp"
#include "jwt_parse.hpp"
#include "jwt_verify.hpp"
#include "validator.hpp"

using quack_oauth::DecisionCache;
using quack_oauth::IHttpClient;
using quack_oauth::IntrospectContext;
using quack_oauth::Jwk;
using quack_oauth::JwksCache;
using quack_oauth::JwksLookupStatus;
using quack_oauth::kReasonRefreshBudgetThrottled;
using quack_oauth::kReasonRefreshFetchFailed;
using quack_oauth::kReasonRefreshKidAbsent;
using quack_oauth::kReasonRefreshKidEvicted;
using quack_oauth::kReasonRefreshNoRotation;
using quack_oauth::kReasonRefreshParseFailed;
using quack_oauth::kReasonRefreshRevoked;
using quack_oauth::kReasonRefreshRotated;
using quack_oauth::kReasonRefreshSuperseded;
using quack_oauth::kReasonRefreshThrottled;
using quack_oauth::ParseJwt;
using quack_oauth::Principal;
using quack_oauth::RefreshEvent;
using quack_oauth::TokeninfoContext;
using quack_oauth::ValidateContext;
using quack_oauth::ValidateToken;
using quack_oauth::ValidateTokenViaIntrospection;
using quack_oauth::ValidateTokenViaTokeninfo;
using quack_oauth::VerifyOptions;
using quack_oauth::VerifyResult;

namespace {

constexpr const char *kTestJwksUri = "https://idp.test/jwks";

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

TestKey GenerateValidatorKey(const std::string &kid, unsigned int bits = 2048) {
	EVP_PKEY *pkey = EVP_RSA_gen(bits);
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
	jwk.kid = kid;
	jwk.kty = "RSA";
	jwk.alg = "RS256";
	jwk.use = "sig";
	jwk.n = bn_to_b64url(n_bn);
	jwk.e = bn_to_b64url(e_bn);

	BN_free(n_bn);
	BN_free(e_bn);
	EVP_PKEY_free(pkey);

	return TestKey {std::move(priv_pem), std::move(jwk)};
}

const TestKey &GetValidatorKey() {
	static const TestKey k = GenerateValidatorKey("validator-key-1");
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

std::string SignWithCustomKid(const TestKey &k, const std::string &kid, std::int64_t exp_s, std::int64_t iat_s) {
	return jwt::create<TraitsT>()
	    .set_type("JWT")
	    .set_key_id(kid)
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
	int post_call_count = 0;
	std::function<void()> on_get;

	std::optional<Response> Get(std::string_view url) override {
		++call_count;
		last_url = std::string(url);
		if (on_get) {
			on_get();
		}
		return next_response;
	}

	std::optional<Response> Post(const PostRequest &) override {
		++post_call_count;
		return std::nullopt;
	}
};

} // namespace

TEST_CASE("Validator: cache hit short-circuits the HTTP fetch", "[validator][cache-hit]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);
	cache.OnFetchSuccess(k.jwk.kid, {k.jwk}, 1700000000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(k, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: invalid signature refreshes a reused kid and retries once", "[validator][rotation]") {
	const auto &old_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(old_key.jwk.kid);
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1699999900, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(rotated_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(rotated_key, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: cached-key refresh failure keeps the last-good key and rate-limits retries",
          "[validator][rotation][rate-limit]") {
	const auto &old_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(old_key.jwk.kid);
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1699999900, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = std::nullopt;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto rotated_token = Sign(rotated_key, 1700003600, 1700000000);
	CHECK(ValidateToken(rotated_token, BaseOpts(), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	CHECK(ValidateToken(rotated_token, BaseOpts(1700000010), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	const auto old_token = Sign(old_key, 1700003600, 1700000000);
	CHECK(ValidateToken(old_token, BaseOpts(1700000010), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: malformed JWKS on refresh preserves last-good key and validates old tokens",
          "[validator][rotation][poison]") {
	const auto &old_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(old_key.jwk.kid);
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1699999900, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {
	    200, R"({"keys":[{"kid":")" + old_key.jwk.kid +
	             R"(","kty":"RSA","use":"sig","alg":"RS256","n":"bad_garbage_rsa_n","e":"AQAB"}]})"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto rotated_token = Sign(rotated_key, 1700003600, 1700000000);
	CHECK(ValidateToken(rotated_token, BaseOpts(), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	const auto old_token = Sign(old_key, 1700003600, 1700000000);
	CHECK(ValidateToken(old_token, BaseOpts(1700000010), ctx) == VerifyResult::Ok);
}

TEST_CASE("Validator: duplicate kid in refreshed JWKS tests candidate keys until one verifies",
          "[validator][rotation][duplicate-kid]") {
	const auto &old_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(old_key.jwk.kid);
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1699999900, kTestJwksUri);

	std::string jwks_body = std::string(R"({"keys":[)") + R"({"kid":")" + rotated_key.jwk.kid +
	                        R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + rotated_key.jwk.n + R"(","e":")" +
	                        rotated_key.jwk.e + R"("},)" + R"({"kid":")" + old_key.jwk.kid +
	                        R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + old_key.jwk.n + R"(","e":")" +
	                        old_key.jwk.e + R"("}]})";

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, std::move(jwks_body)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto rotated_token = Sign(rotated_key, 1700003600, 1700000000);
	CHECK(ValidateToken(rotated_token, BaseOpts(), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: hit-refresh additively ingests sibling keys into cache", "[validator][rotation][sibling]") {
	const auto &old_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(old_key.jwk.kid);
	const auto sibling_key = GenerateValidatorKey("unverified-sibling");
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1699999900, kTestJwksUri);

	std::string jwks_body = std::string(R"({"keys":[)") + R"({"kid":")" + rotated_key.jwk.kid +
	                        R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + rotated_key.jwk.n + R"(","e":")" +
	                        rotated_key.jwk.e + R"("},)" + R"({"kid":")" + sibling_key.jwk.kid +
	                        R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + sibling_key.jwk.n + R"(","e":")" +
	                        sibling_key.jwk.e + R"("}]})";

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, std::move(jwks_body)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto rotated_token = Sign(rotated_key, 1700003600, 1700000000);
	CHECK(ValidateToken(rotated_token, BaseOpts(), ctx) == VerifyResult::Ok);

	// The sibling key is ingested additively into the cache (F1, F5).
	CHECK(cache.Lookup("unverified-sibling", 1700000000, kTestJwksUri).status == JwksLookupStatus::Hit);
}

TEST_CASE("Validator: rotated key with claim check failure updates cache and returns true claim error",
          "[validator][rotation][claims]") {
	const auto &old_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(old_key.jwk.kid);
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1699999900, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(rotated_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Token was signed with rotated_key, but expired at t=1699999000 (now is 1700000000, skew is 60s).
	const auto expired_token = Sign(rotated_key, 1699999000, 1699990000);

	// The validator must recognize that rotated_key cryptographically signed the token,
	// commit the rotated key to the cache, and return VerifyResult::Expired (NOT InvalidSignature!).
	CHECK(ValidateToken(expired_token, BaseOpts(1700000000), ctx) == VerifyResult::Expired);
	CHECK(http.call_count == 1);

	// Cache must now hold the rotated key!
	const auto lookup = cache.Lookup(old_key.jwk.kid, 1700000000, kTestJwksUri);
	REQUIRE(lookup.status == JwksLookupStatus::Hit);
	CHECK(lookup.keys.front().n == rotated_key.jwk.n);
}

TEST_CASE("Validator: cache miss with duplicate kid in JWKS tests candidate keys until one verifies",
          "[validator][cache-miss][duplicate-kid]") {
	const auto &valid_key = GetValidatorKey();
	const auto invalid_key = GenerateValidatorKey(valid_key.jwk.kid);
	JwksCache cache(30);

	// JWKS body has the valid key FIRST, and a stale/invalid key with the same kid LAST.
	std::string jwks_body = std::string(R"({"keys":[)") + R"({"kid":")" + valid_key.jwk.kid +
	                        R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + valid_key.jwk.n + R"(","e":")" +
	                        valid_key.jwk.e + R"("},)" + R"({"kid":")" + invalid_key.jwk.kid +
	                        R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + invalid_key.jwk.n + R"(","e":")" +
	                        invalid_key.jwk.e + R"("}]})";

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, std::move(jwks_body)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(valid_key, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);

	// Under multi-key cache entries, both candidates are cached and the valid key is present.
	const auto lookup = cache.Lookup(valid_key.jwk.kid, 1700000000, kTestJwksUri);
	REQUIRE(lookup.status == JwksLookupStatus::Hit);
	REQUIRE(lookup.keys.size() == 2);
	bool has_valid = false;
	for (const auto &k : lookup.keys) {
		if (k.n == valid_key.jwk.n) {
			has_valid = true;
		}
	}
	CHECK(has_valid);
}

TEST_CASE("Validator: forged token signature failure triggers refresh once and rate-limits subsequent forged tokens",
          "[validator][rotation][rate-limit][security]") {
	const auto &valid_key = GetValidatorKey();
	const auto attacker_key = GenerateValidatorKey("unrelated-kid");
	JwksCache cache(30);
	cache.OnFetchSuccess(valid_key.jwk.kid, {valid_key.jwk}, 1699999900, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(valid_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Attacker presents a token with kid="validator-key-1" signed with attacker's private key.
	TestKey forged_key {attacker_key.priv_pem, valid_key.jwk};
	const auto forged_token = Sign(forged_key, 1700003600, 1700000000);

	// First attempt at t=1700000000 triggers an HTTP refresh attempt, but signature is still invalid.
	CHECK(ValidateToken(forged_token, BaseOpts(1700000000), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	// Subsequent attempts within the 30s window must be rate-limited (no HTTP fetch).
	CHECK(ValidateToken(forged_token, BaseOpts(1700000010), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	CHECK(ValidateToken(forged_token, BaseOpts(1700000029), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	// After 30s, the next forged token is allowed one new refresh attempt.
	http.next_response = IHttpClient::Response {200, JwksWith(valid_key.jwk)};
	CHECK(ValidateToken(forged_token, BaseOpts(1700000031), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 2);

	// Legitimate token signed with valid_key must still succeed.
	const auto valid_token = Sign(valid_key, 1700003600, 1700000000);
	CHECK(ValidateToken(valid_token, BaseOpts(1700000031), ctx) == VerifyResult::Ok);
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

TEST_CASE("Validator: rate-limited cache returns JwksThrottled without fetching (F8)", "[validator][rate-limit]") {
	const auto &k = GetValidatorKey();
	JwksCache cache(30);
	cache.OnFetchMiss(k.jwk.kid, 1700000000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(k, 1700003600, 1700000000);
	// 10s after the recorded miss -- inside the 30s rate-limit window.
	CHECK(ValidateToken(token, BaseOpts(1700000010), ctx) == VerifyResult::JwksThrottled);
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
	CHECK(ValidateToken(token, BaseOpts(1700000010), ctx) == VerifyResult::JwksThrottled);
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

TEST_CASE("Validator: tokeninfo cache hit returns cached Principal", "[validator][tokeninfo][cache-hit]") {
	DecisionCache cache(64, 30);
	const auto key = DecisionCache::KeyOf("opaque-token");
	Principal cached;
	cached.subject = "cached-sub";
	cached.issuer = "https://accounts.google.com";
	cached.scopes = {"scope-a"};
	cached.exp = 1700003600;
	cache.Store(key, cached, 1700000000);

	FakeHttpClient http;
	TokeninfoContext ctx {http, cache, "https://oauth2.googleapis.com/tokeninfo", ""};

	Principal out;
	CHECK(ValidateTokenViaTokeninfo("opaque-token", BaseOpts(), ctx, &out) == VerifyResult::Ok);
	CHECK(http.post_call_count == 0);
	CHECK(out.subject == "cached-sub");
	CHECK(out.issuer == "https://accounts.google.com");
	REQUIRE(out.scopes.size() == 1);
	CHECK(out.scopes[0] == "scope-a");
}

TEST_CASE("Validator: introspection cache hit returns cached Principal", "[validator][introspect][cache-hit]") {
	DecisionCache cache(64, 30);
	const auto key = DecisionCache::KeyOf("opaque-token");
	Principal cached;
	cached.subject = "cached-sub";
	cached.issuer = "https://idp.test";
	cached.scopes = {"quack:read"};
	cached.exp = 1700003600;
	cache.Store(key, cached, 1700000000);

	FakeHttpClient http;
	IntrospectContext ctx {http, cache, "https://idp.test/introspect", "client", "secret", "https://idp.test", ""};

	Principal out;
	CHECK(ValidateTokenViaIntrospection("opaque-token", BaseOpts(), ctx, &out) == VerifyResult::Ok);
	CHECK(http.post_call_count == 0);
	CHECK(out.subject == "cached-sub");
	CHECK(out.issuer == "https://idp.test");
	REQUIRE(out.scopes.size() == 1);
	CHECK(out.scopes[0] == "quack:read");
}

TEST_CASE("Validator: forged token during real rotation commits new key from IdP and does not starve recovery",
          "[validator][rotation][starvation][security]") {
	const auto &old_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(old_key.jwk.kid);
	const auto attacker_key = GenerateValidatorKey("attacker-key");

	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1699999900, kTestJwksUri);

	// IdP serves the new rotated key
	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(rotated_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Attacker presents a forged token for old_key.jwk.kid at t=1700000000
	TestKey forged_key {attacker_key.priv_pem, old_key.jwk};
	const auto forged_token = Sign(forged_key, 1700003600, 1700000000);

	// The forged token must fail verification (InvalidSignature)
	CHECK(ValidateToken(forged_token, BaseOpts(1700000000), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	// Crucially, the fresh TLS-fetched key material for old_key.jwk.kid from the IdP MUST be committed!
	// So a legitimate client presenting a token signed with rotated_key at t+1 (1700000001) must succeed!
	const auto legit_token = Sign(rotated_key, 1700003600, 1700000001);
	CHECK(ValidateToken(legit_token, BaseOpts(1700000001), ctx) == VerifyResult::Ok);
	// No additional HTTP call needed because rotated_key was committed!
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: candidates with use=enc or mismatched alg are ignored",
          "[validator][candidates][filtering][security]") {
	const auto &valid_key = GetValidatorKey();
	JwksCache cache(30);

	// JWKS has an 'enc' key with the same kid FIRST, then the 'sig' key
	std::string jwks_body = std::string(R"({"keys":[)") + R"({"kid":")" + valid_key.jwk.kid +
	                        R"(","kty":"RSA","use":"enc","alg":"RS256","n":")" + valid_key.jwk.n + R"(","e":")" +
	                        valid_key.jwk.e + R"("},)" + R"({"kid":")" + valid_key.jwk.kid +
	                        R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + valid_key.jwk.n + R"(","e":")" +
	                        valid_key.jwk.e + R"("}]})";

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, std::move(jwks_body)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(valid_key, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::Ok);

	// The cached key must have use="sig"
	const auto lookup = cache.Lookup(valid_key.jwk.kid, 1700000000, kTestJwksUri);
	REQUIRE(lookup.status == JwksLookupStatus::Hit);
	CHECK(lookup.keys.front().use == "sig");
}

TEST_CASE("Validator: cached malformed key triggers refresh and recovers",
          "[validator][rotation][malformed-recovery]") {
	const auto &valid_key = GetValidatorKey();
	JwksCache cache(30);

	// Poison the cache with a malformed RSA key for valid_key.jwk.kid
	Jwk malformed_jwk;
	malformed_jwk.kid = valid_key.jwk.kid;
	malformed_jwk.kty = "RSA";
	malformed_jwk.n = "bad-garbage-rsa-modulus";
	malformed_jwk.e = "AQAB";
	cache.OnFetchSuccess(malformed_jwk.kid, {malformed_jwk}, 1699999900, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(valid_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(valid_key, 1700003600, 1700000000);
	// Verification must detect the unusable cached key, trigger a refresh, and succeed!
	CHECK(ValidateToken(token, BaseOpts(1700000000), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
	CHECK(cache.Lookup(valid_key.jwk.kid, 1700000000, kTestJwksUri).keys.front().n == valid_key.jwk.n);
}

TEST_CASE("Validator: cache miss when no candidate verifies does not negative-cache published kid",
          "[validator][cache-miss][security]") {
	const auto &valid_key = GetValidatorKey();
	JwksCache cache(30);

	const auto bad_key = GenerateValidatorKey(valid_key.jwk.kid);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(bad_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(valid_key, 1700003600, 1700000000);
	CHECK(ValidateToken(token, BaseOpts(), ctx) == VerifyResult::InvalidSignature);

	// The published key must be ingested as a Hit, not negative-cached as Miss/RateLimited (F3).
	CHECK(cache.Lookup(valid_key.jwk.kid, 1700000000, kTestJwksUri).status == JwksLookupStatus::Hit);
}

TEST_CASE("Validator: RefreshEvent receives kid and reason on refresh events", "[validator][audit][jwks-refresh]") {
	const auto &initial_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(initial_key.jwk.kid);
	JwksCache cache(30);
	cache.OnFetchSuccess(initial_key.jwk.kid, {initial_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// 1. Success on rotated key
	http.next_response = IHttpClient::Response {200, JwksWith(rotated_key.jwk)};
	const auto token1 = Sign(rotated_key, 2000, 1030);
	RefreshEvent ev1;
	CHECK(ValidateToken(token1, BaseOpts(1030), ctx, &ev1) == VerifyResult::Ok);
	CHECK(ev1.kid == initial_key.jwk.kid);
	CHECK(ev1.reason == kReasonRefreshRotated);

	// 2. Throttled within rate-limit window
	const auto attacker_key = GenerateValidatorKey(initial_key.jwk.kid);
	const auto token2 = Sign(attacker_key, 2000, 1040); // fails against both cached keys
	RefreshEvent ev2;
	CHECK(ValidateToken(token2, BaseOpts(1040), ctx, &ev2) == VerifyResult::InvalidSignature);
	CHECK(ev2.kid == initial_key.jwk.kid);
	CHECK(ev2.reason == kReasonRefreshThrottled);

	// 3. Fetch failed (e.g. 500)
	http.next_response = IHttpClient::Response {500, "internal error"};
	RefreshEvent ev3;
	CHECK(ValidateToken(token2, BaseOpts(1080), ctx, &ev3) == VerifyResult::InvalidSignature);
	CHECK(ev3.kid == initial_key.jwk.kid);
	CHECK(ev3.reason == kReasonRefreshFetchFailed);

	// 4. Parse failed (e.g. invalid json)
	http.next_response = IHttpClient::Response {200, "not-json"};
	RefreshEvent ev4;
	CHECK(ValidateToken(token2, BaseOpts(1120), ctx, &ev4) == VerifyResult::InvalidSignature);
	CHECK(ev4.kid == initial_key.jwk.kid);
	CHECK(ev4.reason == kReasonRefreshParseFailed);

	// 5. Kid absent in fresh JWKS
	Jwk other_key = rotated_key.jwk;
	other_key.kid = "some-other-kid";
	http.next_response = IHttpClient::Response {200, JwksWith(other_key)};
	RefreshEvent ev5;
	CHECK(ValidateToken(token2, BaseOpts(1160), ctx, &ev5) == VerifyResult::InvalidSignature);
	CHECK(ev5.kid == initial_key.jwk.kid);
	CHECK(ev5.reason == kReasonRefreshKidAbsent);
}

TEST_CASE("Validator: multi-key entry verifies tokens for both keys under same kid without HTTP calls",
          "[validator][multi-key]") {
	const auto k1 = GenerateValidatorKey("common-kid");
	const auto k2 = GenerateValidatorKey("common-kid");
	JwksCache cache(30);
	cache.OnFetchSuccess("common-kid", {k1.jwk, k2.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token1 = Sign(k1, 2000, 1010);
	const auto token2 = Sign(k2, 2000, 1010);

	CHECK(ValidateToken(token1, BaseOpts(1010), ctx) == VerifyResult::Ok);
	CHECK(ValidateToken(token2, BaseOpts(1010), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: refresh_no_rotation emitted when fresh JWKS contains only already-cached keys",
          "[validator][no-rotation]") {
	const auto key = GenerateValidatorKey("k1");
	JwksCache cache(30);
	cache.OnFetchSuccess(key.jwk.kid, {key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Forged token: fails signature
	const auto forged_key = GenerateValidatorKey("k1");
	const auto forged_token = Sign(forged_key, 2000, 1050);

	RefreshEvent ev;
	CHECK(ValidateToken(forged_token, BaseOpts(1050), ctx, &ev) == VerifyResult::InvalidSignature);
	CHECK(ev.reason == kReasonRefreshNoRotation);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: 100 distinct unknown kids in one batch trigger exactly 1 HTTP GET", "[validator][budget]") {
	JwksCache cache(30);
	const auto real_key = GenerateValidatorKey("real-key");

	FakeHttpClient http;
	// IdP publishes only real-key
	http.next_response = IHttpClient::Response {200, JwksWith(real_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	for (int i = 0; i < 100; ++i) {
		const auto bogus_key = GenerateValidatorKey("unknown-" + std::to_string(i));
		const auto bogus_token = Sign(bogus_key, 2000, 1000);
		CHECK(ValidateToken(bogus_token, BaseOpts(1000), ctx) == VerifyResult::UnknownKid);
	}

	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: cold miss where kid is published in JWKS returns InvalidSignature and does not negative-cache",
          "[validator][cold-miss]") {
	JwksCache cache(30);
	const auto legit_key = GenerateValidatorKey("my-kid");
	const auto forged_key = GenerateValidatorKey("my-kid");

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(legit_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Attacker sends forged token for "my-kid" while cache is cold
	const auto forged_token = Sign(forged_key, 2000, 1000);
	CHECK(ValidateToken(forged_token, BaseOpts(1000), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	// Legitimate token for "my-kid" arrives at t+1; must NOT be negative-cached!
	http.next_response.reset();
	const auto legit_token = Sign(legit_key, 2000, 1001);
	CHECK(ValidateToken(legit_token, BaseOpts(1001), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1); // 0 additional HTTP calls
}

TEST_CASE("Validator: key removed from IdP JWKS is revoked upon successful 200 refresh",
          "[validator][revocation][security][f1]") {
	const auto old_key = GenerateValidatorKey("rot-key");
	const auto new_key = GenerateValidatorKey("rot-key");
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP has rotated and now publishes ONLY new_key for rot-key
	http.next_response = IHttpClient::Response {200, JwksWith(new_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// New token validates and triggers refresh committing new_key
	const auto new_token = Sign(new_key, 2000, 1050);
	CHECK(ValidateToken(new_token, BaseOpts(1050), ctx) == VerifyResult::Ok);

	// Old key must be REVOKED now; old tokens must fail signature!
	const auto old_token = Sign(old_key, 2000, 1051);
	CHECK(ValidateToken(old_token, BaseOpts(1051), ctx) == VerifyResult::InvalidSignature);
}

TEST_CASE("Validator: global fetch budget bounds failed fetches (100 unknown kids against failing IdP triggers at most "
          "1 GET)",
          "[validator][budget][f2]") {
	JwksCache cache(30);
	FakeHttpClient http;
	http.next_response = std::nullopt; // IdP is down / network failure
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	for (int i = 0; i < 100; ++i) {
		const auto key = GenerateValidatorKey("unknown-" + std::to_string(i));
		const auto token = Sign(key, 2000, 1000);
		const auto expected = (i == 0) ? VerifyResult::JwksFetchFailed : VerifyResult::JwksThrottled;
		CHECK(ValidateToken(token, BaseOpts(1000), ctx) == expected);
	}
	CHECK(http.call_count <= 1);
}

TEST_CASE("Validator: TryRefreshRotatedKid obeys global fetch budget across distinct cached kids",
          "[validator][budget][f3]") {
	JwksCache cache(30);
	std::vector<TestKey> keys;
	for (int i = 0; i < 5; ++i) {
		keys.push_back(GenerateValidatorKey("kid-" + std::to_string(i)));
		cache.OnFetchSuccess(keys.back().jwk.kid, {keys.back().jwk}, 1000, kTestJwksUri);
	}

	FakeHttpClient http;
	// Fresh JWKS that returns something
	http.next_response = IHttpClient::Response {200, JwksWith(keys[0].jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Present forged tokens for all 5 cached kids at now_s = 1050
	for (int i = 0; i < 5; ++i) {
		const auto forged_key = GenerateValidatorKey("kid-" + std::to_string(i));
		const auto token = Sign(forged_key, 2000, 1050);
		CHECK(ValidateToken(token, BaseOpts(1050), ctx) == VerifyResult::InvalidSignature);
	}

	// At most 1 HTTP GET across all 5 cached kids within the rate limit window
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: budget-blocked cold miss does not negative-cache and recovers after window",
          "[validator][cold-miss][f4]") {
	JwksCache cache(30);
	const auto key1 = GenerateValidatorKey("kid-1");
	const auto key2 = GenerateValidatorKey("kid-2");

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {500, "internal error"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// t=1000: failed fetch for kid-1
	const auto token1 = Sign(key1, 2000, 1000);
	CHECK(ValidateToken(token1, BaseOpts(1000), ctx) == VerifyResult::JwksFetchFailed);
	CHECK(http.call_count == 1);

	// t=1001: IdP publishes kid-2, but client requests kid-2 within 2s global budget window.
	// Global budget blocks fetch and returns JwksThrottled (F-G).
	http.next_response = IHttpClient::Response {200, JwksWith(key2.jwk)};
	const auto token2 = Sign(key2, 2000, 1001);
	CHECK(ValidateToken(token2, BaseOpts(1001), ctx) == VerifyResult::JwksThrottled);
	CHECK(http.call_count == 1); // 0 additional fetches

	// kid-2 must NOT have been negative-cached!
	CHECK(cache.Lookup("kid-2", 1001, kTestJwksUri).status != JwksLookupStatus::RateLimited);

	// t=1005: global budget window (2s) has passed; request for kid-2 now fetches successfully!
	CHECK(ValidateToken(token2, BaseOpts(1005), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 2);
}

TEST_CASE("Validator: hit path alg filter skips refresh during cooldown and refreshes after (F9)",
          "[validator][alg-filter][f9]") {
	JwksCache cache(30);
	auto key = GenerateValidatorKey("kid-alg");
	key.jwk.alg = "RS512"; // Key in cache is pinned to RS512
	cache.OnFetchSuccess(key.jwk.kid, {key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP JWKS still only has the RS512 key
	http.next_response = IHttpClient::Response {200, JwksWith(key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Token is signed with RS256; arrives at t=1010 (inside kid's 30s cooldown)
	const auto token = Sign(key, 2000, 1010);
	CHECK(ValidateToken(token, BaseOpts(1010), ctx) == VerifyResult::NoMatchingKey);
	CHECK(http.call_count == 0);

	// Arrives at t=1050 (after kid's 30s cooldown): attempts refresh, still no matching key
	CHECK(ValidateToken(token, BaseOpts(1050), ctx) == VerifyResult::NoMatchingKey);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: sub-2048 RSA key returns UnsupportedKeyType and does not trigger refresh loop",
          "[validator][rsa-size][f7]") {
	JwksCache cache(30);
	const auto sub_key = GenerateValidatorKey("sub-2048-kid", 1024);
	cache.OnFetchSuccess(sub_key.jwk.kid, {sub_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(sub_key, 2000, 1010);
	CHECK(ValidateToken(token, BaseOpts(1010), ctx) == VerifyResult::UnsupportedKeyType);
	CHECK(http.call_count == 0); // Must NOT trigger refresh!

	// Second attempt in same or next window also does not trigger refresh
	CHECK(ValidateToken(token, BaseOpts(1050), ctx) == VerifyResult::UnsupportedKeyType);
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: F-A 200 fetch lacking target kid ingests document without new-kid lockout", "[validator][f-a]") {
	JwksCache cache(30);
	const auto old_key = GenerateValidatorKey("kid-old");
	const auto new_key = GenerateValidatorKey("kid-new");
	cache.OnFetchSuccess(old_key.jwk.kid, {old_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP now publishes only kid-new!
	http.next_response = IHttpClient::Response {200, JwksWith(new_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Present a forged token for kid-old at t=1050
	const auto forged_old = GenerateValidatorKey("kid-old");
	const auto token_old = Sign(forged_old, 2000, 1050);
	CHECK(ValidateToken(token_old, BaseOpts(1050), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	// Now present a valid token for kid-new at t=1053 (after global budget window)
	const auto token_new = Sign(new_key, 2000, 1053);
	// kid-new must be present in cache from the previous fetch! No second HTTP fetch needed.
	CHECK(ValidateToken(token_new, BaseOpts(1053), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: F-B Removal-only revocation prunes removed key on 200 OK refresh", "[validator][f-b]") {
	JwksCache cache(30);
	const auto key_a = GenerateValidatorKey("shared-kid");
	const auto key_b = GenerateValidatorKey("shared-kid");
	// Cache initially has both key A and key B under shared-kid
	cache.OnFetchSuccess("shared-kid", {key_a.jwk, key_b.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP has removed key_b, publishes only key_a
	http.next_response = IHttpClient::Response {200, JwksWith(key_a.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Present a forged token to trigger refresh at t=1050
	const auto forged = GenerateValidatorKey("shared-kid");
	const auto forged_token = Sign(forged, 2000, 1050);
	CHECK(ValidateToken(forged_token, BaseOpts(1050), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 1);

	// Token signed with removed key_b must now be REJECTED!
	const auto token_b = Sign(key_b, 2000, 1050);
	CHECK(ValidateToken(token_b, BaseOpts(1050), ctx) == VerifyResult::InvalidSignature);

	// Token signed with key_a still verifies OK
	const auto token_a = Sign(key_a, 2000, 1050);
	CHECK(ValidateToken(token_a, BaseOpts(1050), ctx) == VerifyResult::Ok);
}

TEST_CASE("Validator: F-C TryReserveRefresh does not burn per-kid window when global budget is blocked",
          "[validator][f-c]") {
	JwksCache cache(30);
	const auto key = GenerateValidatorKey("kid-1");
	cache.OnFetchSuccess(key.jwk.kid, {key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Saturate global budget by recording a fetch attempt at t=1030
	cache.RecordJwksFetch(1030);

	// Present forged token for kid-1 at t=1031 (global budget closed).
	// Global budget check must reject BEFORE reserving kid-1's 30s window.
	const auto forged = GenerateValidatorKey("kid-1");
	const auto token_bad = Sign(forged, 2000, 1031);
	CHECK(ValidateToken(token_bad, BaseOpts(1031), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 0);

	// At t=1033 (global window of 2s has passed, but per-kid 30s window from 1031 has NOT passed).
	// If kid-1 was erroneously reserved at 1031, it would be blocked until 1061.
	// Because it was NOT reserved at 1031, it can refresh now!
	const auto rotated_key = GenerateValidatorKey("kid-1");
	http.next_response = IHttpClient::Response {200, JwksWith(rotated_key.jwk)};
	const auto token_rotated = Sign(rotated_key, 2000, 1033);
	CHECK(ValidateToken(token_rotated, BaseOpts(1033), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: F-F Global fetch budget decoupled from min_refresh_s", "[validator][f-f]") {
	JwksCache cache(300); // 5-minute per-kid min_refresh_s
	const auto key1 = GenerateValidatorKey("kid-1");
	const auto key2 = GenerateValidatorKey("kid-2");

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(key1.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// t=1000: cold miss for kid-1 fetches JWKS
	const auto token1 = Sign(key1, 2000, 1000);
	CHECK(ValidateToken(token1, BaseOpts(1000), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);

	// t=1003: 3 seconds later (> 2s global budget, but way < 300s per-kid setting).
	// Cold miss for kid-2 must be permitted to fetch!
	http.next_response = IHttpClient::Response {200, JwksWith(key2.jwk)};
	const auto token2 = Sign(key2, 2000, 1003);
	CHECK(ValidateToken(token2, BaseOpts(1003), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 2);
}

TEST_CASE("Validator: F-G Budget-blocked cold miss returns JwksThrottled", "[validator][f-g]") {
	JwksCache cache(30);
	const auto key2 = GenerateValidatorKey("kid-2");

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Satiate global budget by recording a fetch attempt at t=1000 without successful document
	cache.RecordJwksFetch(1000);

	// t=1001: 1 second later (< 2s global budget), cold miss for kid-2 without fresh document
	const auto token2 = Sign(key2, 2000, 1001);
	CHECK(ValidateToken(token2, BaseOpts(1001), ctx) == VerifyResult::JwksThrottled);
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: F-K Sub-2048 key in cache does not mask valid 2048-bit key rotation", "[validator][f-k]") {
	JwksCache cache(30);
	const auto weak_key = GenerateValidatorKey("kid-k", 1024);
	const auto valid_key = GenerateValidatorKey("kid-k", 2048);
	// Cache holds both weak key and rotated valid key
	cache.OnFetchSuccess("kid-k", {weak_key.jwk, valid_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Token signed with the valid 2048-bit key must verify OK, not return UnsupportedKeyType!
	const auto token_valid = Sign(valid_key, 2000, 1010);
	CHECK(ValidateToken(token_valid, BaseOpts(1010), ctx) == VerifyResult::Ok);
}

TEST_CASE("Validator: F-O ParseJwt rejects kid > 256 bytes or control characters as malformed", "[validator][f-o]") {
	const auto key = GenerateValidatorKey("k");
	// Normal token verifies
	const auto valid_token = Sign(key, 2000, 1000);
	CHECK(ParseJwt(valid_token).has_value());

	// Token with kid containing control character '\n'
	const auto bad_ctrl_token = SignWithCustomKid(key, "bad\nkid", 2000, 1000);
	CHECK_FALSE(ParseJwt(bad_ctrl_token).has_value());

	// Token with kid > 256 chars
	std::string long_kid(257, 'a');
	const auto long_kid_token = SignWithCustomKid(key, long_kid, 2000, 1000);
	CHECK_FALSE(ParseJwt(long_kid_token).has_value());
}

TEST_CASE(
    "Validator: candidate returning UnsupportedKeyType does not mask InvalidSignature and allows rotation recovery",
    "[validator][weak-key][rotation-recovery]") {
	JwksCache cache(30);
	const auto weak_key = GenerateValidatorKey("mixed-kid", 1024);
	const auto stale_key = GenerateValidatorKey("mixed-kid", 2048);
	const auto rotated_key = GenerateValidatorKey("mixed-kid", 2048);

	// Cache contains BOTH weak_key (1024-bit) and stale_key (2048-bit) under "mixed-kid"
	cache.OnFetchSuccess("mixed-kid", {weak_key.jwk, stale_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(rotated_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Client presents token signed with fresh rotated_key at t=1050
	const auto token = Sign(rotated_key, 2000, 1050);
	// Must NOT return UnsupportedKeyType; must recognize InvalidSignature against stale_key,
	// trigger TryRefreshRotatedKid, and verify Ok with 1 HTTP GET!
	CHECK(ValidateToken(token, BaseOpts(1050), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: cold-miss ingest filters unusable keys through ScreenUsableKeys",
          "[validator][cold-miss][screening]") {
	JwksCache cache(30);
	const auto weak_key = GenerateValidatorKey("cold-weak", 1024);
	const auto valid_key = GenerateValidatorKey("cold-valid", 2048);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {
	    200, std::string(R"({"keys":[)") + R"({"kid":")" + weak_key.jwk.kid +
	             R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + weak_key.jwk.n + R"(","e":")" + weak_key.jwk.e +
	             R"("},)" + R"({"kid":")" + valid_key.jwk.kid + R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" +
	             valid_key.jwk.n + R"(","e":")" + valid_key.jwk.e + R"("}]})"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token_valid = Sign(valid_key, 2000, 1000);
	CHECK(ValidateToken(token_valid, BaseOpts(1000), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);

	// The weak key for "cold-weak" must have been screened out by ScreenUsableKeys during ingest,
	// rather than resident in the cache as an unusable key.
	const auto lookup = cache.Lookup("cold-weak", 1000, kTestJwksUri);
	CHECK(lookup.keys.empty());
}

TEST_CASE("Validator: TryRefreshRotatedKid commits target kid before sibling ingest under LRU pressure",
          "[validator][lru][ordering]") {
	JwksCache cache(30, /*max_entries=*/2);
	const auto target_old = GenerateValidatorKey("target-kid");
	const auto target_new = GenerateValidatorKey("target-kid");
	const auto old_other = GenerateValidatorKey("old-other");
	const auto sib1 = GenerateValidatorKey("sib1");

	// Populate cache: target_old first, then old_other (target_old is at back of LRU)
	cache.OnFetchSuccess(target_old.jwk.kid, {target_old.jwk}, 990, kTestJwksUri);
	cache.OnFetchSuccess(old_other.jwk.kid, {old_other.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	http.next_response =
	    IHttpClient::Response {200, std::string(R"({"keys":[)") + R"({"kid":")" + target_new.jwk.kid +
	                                    R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + target_new.jwk.n +
	                                    R"(","e":")" + target_new.jwk.e + R"("},)" + R"({"kid":")" + sib1.jwk.kid +
	                                    R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + sib1.jwk.n + R"(","e":")" +
	                                    sib1.jwk.e + R"("}]})"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(target_new, 2000, 1050);
	CHECK(ValidateToken(token, BaseOpts(1050), ctx) == VerifyResult::Ok);

	const auto lookup = cache.Lookup("target-kid", 1050, kTestJwksUri);
	REQUIRE(lookup.status == JwksLookupStatus::Hit);
	REQUIRE(!lookup.keys.empty());
	CHECK(lookup.keys.front().n == target_new.jwk.n);
}

TEST_CASE("Validator: failed fetch for kid A does not mislabel budget-blocked cold miss for kid B as JwksFetchFailed",
          "[validator][budget][isolated-error]") {
	JwksCache cache(30);
	FakeHttpClient http;
	http.next_response = IHttpClient::Response {500, "server error"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto key_a = GenerateValidatorKey("kid-a");
	const auto token_a = Sign(key_a, 2000, 1000);
	CHECK(ValidateToken(token_a, BaseOpts(1000), ctx) == VerifyResult::JwksFetchFailed);

	const auto key_b = GenerateValidatorKey("kid-b");
	const auto token_b = Sign(key_b, 2000, 1001);
	CHECK(ValidateToken(token_b, BaseOpts(1001), ctx) == VerifyResult::JwksThrottled);
}

TEST_CASE("Validator: concurrent cache update invalidating reservation causes stale refresh to reject uncommitted key",
          "[validator][rotation][concurrent-revocation]") {
	const auto initial_key = GenerateValidatorKey("target-kid");
	const auto concurrent_key = GenerateValidatorKey("target-kid");
	const auto stale_key = GenerateValidatorKey("target-kid");

	JwksCache cache(30);
	cache.OnFetchSuccess("target-kid", {initial_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(stale_key.jwk)};
	// When http.Get is invoked (while reservation is active), simulate concurrent thread T2
	// updating the cache with concurrent_key at t=1040, which invalidates target-kid's reservation.
	http.on_get = [&]() {
		cache.OnFetchSuccess("target-kid", {concurrent_key.jwk}, 1040, kTestJwksUri);
	};

	ValidateContext ctx {http, cache, "https://idp.test/jwks"};
	RefreshEvent refresh;
	const auto token = Sign(stale_key, 2000, 1050);
	const auto res = ValidateToken(token, BaseOpts(1050), ctx, &refresh);

	// The stale refresh's commit is refused (refresh_superseded).
	// Crucially, the token signed by stale_key MUST NOT be accepted against uncommitted keys!
	CHECK(res == VerifyResult::InvalidSignature);
	CHECK(refresh.reason == kReasonRefreshSuperseded);
}

TEST_CASE("Validator: reserved refresh against 200 JWKS missing target kid evicts cached entry after 2 consecutive "
          "refreshes (F2)",
          "[validator][revocation][kid-absent-evict]") {
	const auto target_key = GenerateValidatorKey("revoked-kid");
	const auto other_key = GenerateValidatorKey("other-kid");

	JwksCache cache(30);
	cache.OnFetchSuccess("revoked-kid", {target_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// 200 OK containing only other-kid; revoked-kid has been deleted by the IdP!
	http.next_response = IHttpClient::Response {200, JwksWith(other_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	RefreshEvent refresh;
	// Token with expired or modified signature triggers hit-refresh
	const auto bad_token = SignWithCustomKid(other_key, "revoked-kid", 2000, 1050);
	const auto res = ValidateToken(bad_token, BaseOpts(1050), ctx, &refresh);

	CHECK(res == VerifyResult::InvalidSignature);
	CHECK(refresh.reason == kReasonRefreshKidAbsent);

	// First absent response does NOT evict immediately; corroboration requires 2 (F2)
	const auto lookup1 = cache.Lookup("revoked-kid", 1050, kTestJwksUri);
	CHECK(lookup1.status == JwksLookupStatus::Hit);

	// Second absent refresh at t=1090 corroborates absence and evicts
	http.next_response = IHttpClient::Response {200, JwksWith(other_key.jwk)};
	const auto res2 = ValidateToken(bad_token, BaseOpts(1090), ctx, &refresh);
	CHECK(res2 == VerifyResult::InvalidSignature);
	CHECK(refresh.reason == kReasonRefreshKidEvicted);

	const auto lookup2 = cache.Lookup("revoked-kid", 1090, kTestJwksUri);
	CHECK(lookup2.status == JwksLookupStatus::Miss);
}

TEST_CASE("Validator: cold miss for random kid cannot mutate unrelated recently-refreshed cached kid",
          "[validator][cold-miss][unrelated-isolation]") {
	const auto stable_v1 = GenerateValidatorKey("stable-kid");
	const auto stable_v2 = GenerateValidatorKey("stable-kid");
	const auto random_key = GenerateValidatorKey("random-kid");

	JwksCache cache(30);
	cache.OnFetchSuccess("stable-kid", {stable_v1.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP publishes both random-kid and a modified stable-kid v2
	http.next_response =
	    IHttpClient::Response {200, std::string(R"({"keys":[)") + R"({"kid":")" + random_key.jwk.kid +
	                                    R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + random_key.jwk.n +
	                                    R"(","e":")" + random_key.jwk.e + R"("},)" + R"({"kid":")" + stable_v2.jwk.kid +
	                                    R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + stable_v2.jwk.n +
	                                    R"(","e":")" + stable_v2.jwk.e + R"("}]})"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Unauthenticated request with random-kid arrives at t=1005 (only 5s after stable-kid was cached; min_refresh_s is
	// 30)
	const auto random_token = Sign(random_key, 2000, 1005);
	CHECK(ValidateToken(random_token, BaseOpts(1005), ctx) == VerifyResult::Ok);

	// stable-kid was NOT due for refresh (< 30s elapsed); cold miss must NOT have mutated its cached keys!
	const auto lookup = cache.Lookup("stable-kid", 1005, kTestJwksUri);
	REQUIRE(lookup.status == JwksLookupStatus::Hit);
	REQUIRE(!lookup.keys.empty());
	CHECK(lookup.keys.front().n == stable_v1.jwk.n);
}

TEST_CASE(
    "Validator: cold miss for unknown kid within 2s of successful fetch returns UnknownKid without negative cache (F1)",
    "[validator][budget][cold-miss][f1]") {
	const auto known_key = GenerateValidatorKey("known-kid");
	const auto unknown_key = GenerateValidatorKey("unknown-kid");

	JwksCache cache(30);
	FakeHttpClient http;
	// IdP publishes known-kid
	http.next_response = IHttpClient::Response {200, std::string(R"({"keys":[)") + R"({"kid":")" + known_key.jwk.kid +
	                                                     R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" +
	                                                     known_key.jwk.n + R"(","e":")" + known_key.jwk.e + R"("}]})"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Request 1 at t=1000 with known-kid fetches JWKS successfully and validates OK
	const auto known_token = Sign(known_key, 2000, 1000);
	CHECK(ValidateToken(known_token, BaseOpts(1000), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);

	// Request 2 at t=1001 (1s later, within the 2s budget window) with unknown-kid arrives.
	// Fresh document exists; unknown-kid returns UnknownKid without fetching.
	const auto unknown_token = Sign(unknown_key, 2000, 1001);
	CHECK(ValidateToken(unknown_token, BaseOpts(1001), ctx) == VerifyResult::UnknownKid);
	CHECK(http.call_count == 1);

	// unknown-kid MUST NOT be negative-cached, so after the 2s budget window passes,
	// a subsequent request will be allowed to hit the network rather than being blocked for 30s.
	CHECK(cache.Lookup("unknown-kid", 1001, kTestJwksUri).status != JwksLookupStatus::RateLimited);
}

TEST_CASE("Validator: key removal on refresh emits refresh_revoked audit reason",
          "[validator][rotation][revocation][f8]") {
	const auto key1 = GenerateValidatorKey("dual-kid");
	const auto key2 = GenerateValidatorKey("dual-kid");

	JwksCache cache(30);
	// Cache initially has both key1 and key2
	cache.OnFetchSuccess("dual-kid", {key1.jwk, key2.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP revoked key2, so document now only has key1
	http.next_response = IHttpClient::Response {200, std::string(R"({"keys":[)") + R"({"kid":")" + key1.jwk.kid +
	                                                     R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" +
	                                                     key1.jwk.n + R"(","e":")" + key1.jwk.e + R"("}]})"};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	RefreshEvent refresh;
	// Presenting a token signed by a third key at t=1035 triggers refresh
	const auto key3 = GenerateValidatorKey("dual-kid");
	const auto token = Sign(key3, 2000, 1035);
	const auto res = ValidateToken(token, BaseOpts(1035), ctx, &refresh);
	CHECK(res == VerifyResult::InvalidSignature);
	CHECK(refresh.kid == "dual-kid");
	CHECK(refresh.reason == kReasonRefreshRevoked);
}

TEST_CASE("Validator: 5 keys under one kid prioritizes verifying key and keeps verifying (F8)",
          "[validator][rotation][trimming][f8]") {
	std::vector<TestKey> keys;
	for (int i = 0; i < 5; ++i) {
		keys.push_back(GenerateValidatorKey("multi-kid"));
	}

	JwksCache cache(30);
	// Initially cache keys 0..3
	cache.OnFetchSuccess("multi-kid", {keys[0].jwk, keys[1].jwk, keys[2].jwk, keys[3].jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP publishes all 5 keys in order 0, 1, 2, 3, 4
	std::string jwks_json = R"({"keys":[)";
	for (int i = 0; i < 5; ++i) {
		if (i > 0) {
			jwks_json += ",";
		}
		jwks_json += R"({"kid":")" + keys[i].jwk.kid + R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" +
		             keys[i].jwk.n + R"(","e":")" + keys[i].jwk.e + R"("})";
	}
	jwks_json += "]}";
	http.next_response = IHttpClient::Response {200, jwks_json};

	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Present token signed by key #5 (index 4) at t=1035 (triggers refresh)
	const auto token1 = Sign(keys[4], 2000, 1035);
	CHECK(ValidateToken(token1, BaseOpts(1035), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);

	// Consecutive verification for key #5 must also succeed directly from cache
	const auto token2 = Sign(keys[4], 2000, 1036);
	CHECK(ValidateToken(token2, BaseOpts(1036), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: cold miss during fresh document window does not starve budget and returns UnknownKid (F1)",
          "[validator][cold-miss][starvation][f1]") {
	JwksCache cache(30);
	const auto &known_key = GetValidatorKey();
	// IdP fetch succeeds at t=1000
	cache.RecordJwksFetch(1000);
	cache.OnPassiveFetchSuccess(known_key.jwk.kid, {known_key.jwk}, 1000);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// At t=1001, token arrives with unknown kid
	const auto stranger_key = GenerateValidatorKey("stranger-kid");
	const auto token = Sign(stranger_key, 2000, 1001);

	RefreshEvent refresh;
	const auto res = ValidateToken(token, BaseOpts(1001), ctx, &refresh);
	CHECK(res == VerifyResult::UnknownKid);
	// No network request attempted because fresh document exists
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: single transient absent response does not evict cached key; second consecutive absent response "
          "evicts (F2)",
          "[validator][corroborated-eviction][f2]") {
	const auto valid_key = GenerateValidatorKey("corroborated-kid");
	const auto other_key = GenerateValidatorKey("other-kid");
	const auto attacker_key = GenerateValidatorKey("corroborated-kid");

	JwksCache cache(30);
	cache.OnFetchSuccess("corroborated-kid", {valid_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP serves document omitting corroborated-kid
	std::string jwks_omitted = R"({"keys":[{"kid":")" + other_key.jwk.kid +
	                           R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + other_key.jwk.n + R"(","e":")" +
	                           other_key.jwk.e + R"("}]})";
	http.next_response = IHttpClient::Response {200, jwks_omitted};

	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Attacker / invalid signature triggers refresh at t=1035
	TestKey forged {attacker_key.priv_pem, valid_key.jwk};
	const auto invalid_token = Sign(forged, 2000, 1035);
	RefreshEvent refresh1;
	const auto res1 = ValidateToken(invalid_token, BaseOpts(1035), ctx, &refresh1);
	CHECK(res1 == VerifyResult::InvalidSignature);
	CHECK(refresh1.reason == kReasonRefreshKidAbsent);
	CHECK(http.call_count == 1);

	// First absent observation: key must NOT be evicted! Legitimate token must still verify at t=1036!
	const auto legit_token = Sign(valid_key, 2000, 1036);
	CHECK(ValidateToken(legit_token, BaseOpts(1036), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);

	// Second absent observation at t=1070: another invalid token triggers refresh
	http.next_response = IHttpClient::Response {200, jwks_omitted};
	RefreshEvent refresh2;
	const auto res2 = ValidateToken(invalid_token, BaseOpts(1070), ctx, &refresh2);
	CHECK(res2 == VerifyResult::InvalidSignature);
	CHECK(refresh2.reason == kReasonRefreshKidEvicted);
	CHECK(http.call_count == 2);

	// Now key MUST be evicted after two consecutive corroborations
	const auto res3 = ValidateToken(legit_token, BaseOpts(1071), ctx);
	// Fresh document exists from t=1070 fetch; unknown kid returns UnknownKid
	CHECK(res3 == VerifyResult::UnknownKid);
}

TEST_CASE("Validator: multi-tenant caches partitioned by jwks_uri do not cross-talk (F3)",
          "[validator][multi-tenant][f3]") {
	const auto key_a = GenerateValidatorKey("shared-kid");
	const auto key_b = GenerateValidatorKey("shared-kid");

	JwksCache cache(30);
	FakeHttpClient http;

	ValidateContext ctx_a {http, cache, "https://tenant-a.com/jwks"};
	ValidateContext ctx_b {http, cache, "https://tenant-b.com/jwks"};

	// Seed tenant A with key_a
	cache.OnFetchSuccess("shared-kid", {key_a.jwk}, 1000, "https://tenant-a.com/jwks");

	// Tenant A verifies token signed with key_a
	const auto token_a = Sign(key_a, 2000, 1000);
	CHECK(ValidateToken(token_a, BaseOpts(1000), ctx_a) == VerifyResult::Ok);
	CHECK(http.call_count == 0);

	// Tenant B does NOT see tenant A's key (cold miss)
	std::string jwks_b = R"({"keys":[{"kid":"shared-kid","kty":"RSA","use":"sig","alg":"RS256","n":")" + key_b.jwk.n +
	                     R"(","e":")" + key_b.jwk.e + R"("}]})";
	http.next_response = IHttpClient::Response {200, jwks_b};

	const auto token_b = Sign(key_b, 2000, 1001);
	CHECK(ValidateToken(token_b, BaseOpts(1001), ctx_b) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: screening failure for published kid returns UnsupportedKeyType / UnusableKey without negative "
          "caching (F7)",
          "[validator][screening][unusable-key][f7]") {
	JwksCache cache(30);
	FakeHttpClient http;
	// EC P-521 is unsupported (only P-256 and P-384 supported)
	std::string p521_jwks = R"({"keys":[{"kid":"p521-kid","kty":"EC","crv":"P-521","use":"sig","x":"abc","y":"def"}]})";
	http.next_response = IHttpClient::Response {200, p521_jwks};

	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto key = GenerateValidatorKey("p521-kid");
	const auto token = Sign(key, 2000, 1000);

	const auto res = ValidateToken(token, BaseOpts(1000), ctx);
	CHECK(res == VerifyResult::UnusableKey);

	// Must NOT be placed in negative cache (lookup is Miss, not RateLimited)
	const auto lookup = cache.Lookup("p521-kid", 1001, "https://idp.test/jwks");
	CHECK(lookup.status == JwksLookupStatus::Miss);
}

TEST_CASE("Validator: per-kid rate-limited lookup returns JwksThrottled (F8)",
          "[validator][rate-limited][throttled][f8]") {
	JwksCache cache(30);
	cache.OnFetchMiss("unknown-kid", 1000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto key = GenerateValidatorKey("unknown-kid");
	const auto token = Sign(key, 2000, 1005);

	RefreshEvent refresh;
	const auto res = ValidateToken(token, BaseOpts(1005), ctx, &refresh);
	CHECK(res == VerifyResult::JwksThrottled);
	CHECK(refresh.reason == kReasonRefreshThrottled);
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: token with alg mismatch against cached kid returns NoMatchingKey without HTTP call (F9)",
          "[validator][alg-mismatch][no-matching-key][f9]") {
	const auto key = GenerateValidatorKey("rsa-kid");

	JwksCache cache(30);
	cache.OnFetchSuccess("rsa-kid", {key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Create token with alg="RS384" but kid="rsa-kid" (cached key is RSA RS256)
	const auto token = jwt::create<TraitsT>()
	                       .set_type("JWT")
	                       .set_key_id("rsa-kid")
	                       .set_issuer("https://idp.test")
	                       .set_subject("alice")
	                       .set_audience("api://quack")
	                       .set_issued_at(std::chrono::system_clock::time_point(std::chrono::seconds(1000)))
	                       .set_expires_at(std::chrono::system_clock::time_point(std::chrono::seconds(2000)))
	                       .sign(jwt::algorithm::rs384("", key.priv_pem, "", ""));

	VerifyOptions opts = BaseOpts(1000);
	opts.allowed_algorithms = {"RS256", "RS384"};

	const auto res = ValidateToken(token, opts, ctx);
	CHECK(res == VerifyResult::NoMatchingKey);
	CHECK(http.call_count == 0);
}

TEST_CASE("Validator: multi-candidate superseded commit refuses token and reports refresh_superseded",
          "[validator][rotation][concurrent-revocation-multi]") {
	const auto initial_key = GenerateValidatorKey("target-kid");
	const auto concurrent_key = GenerateValidatorKey("target-kid");
	const auto stale_key_1 = GenerateValidatorKey("target-kid");
	const auto stale_key_2 = GenerateValidatorKey("target-kid");

	JwksCache cache(30);
	cache.OnFetchSuccess("target-kid", {initial_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// JWKS returns 2 keys for target-kid
	http.next_response = IHttpClient::Response {
	    200, std::string(R"({"keys":[)") + R"({"kid":"target-kid","kty":"RSA","use":"sig","alg":"RS256","n":")" +
	             stale_key_1.jwk.n + R"(","e":")" + stale_key_1.jwk.e + R"("},)" +
	             R"({"kid":"target-kid","kty":"RSA","use":"sig","alg":"RS256","n":")" + stale_key_2.jwk.n +
	             R"(","e":")" + stale_key_2.jwk.e + R"("}]})"};

	http.on_get = [&]() {
		cache.OnFetchSuccess("target-kid", {concurrent_key.jwk}, 1040, kTestJwksUri);
	};

	ValidateContext ctx {http, cache, "https://idp.test/jwks"};
	RefreshEvent refresh;
	const auto token = Sign(stale_key_2, 2000, 1050);
	const auto res = ValidateToken(token, BaseOpts(1050), ctx, &refresh);

	CHECK(res == VerifyResult::InvalidSignature);
	CHECK(refresh.reason == kReasonRefreshSuperseded);
}

TEST_CASE("Validator: alg mismatch on cached key triggers refresh and succeeds if document has matching key",
          "[validator][rotation][alg-mismatch-refresh]") {
	const auto old_key = GenerateValidatorKey("target-kid");
	const auto new_key = GenerateValidatorKey("target-kid");

	JwksCache cache(30);
	// Cached key has RS256
	cache.OnFetchSuccess("target-kid", {old_key.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	// IdP publishes updated key with RS384
	auto updated_jwk = new_key.jwk;
	updated_jwk.alg = "RS384";
	http.next_response = IHttpClient::Response {200, JwksWith(updated_jwk)};

	ValidateContext ctx {http, cache, "https://idp.test/jwks"};
	const auto token = jwt::create<TraitsT>()
	                       .set_type("JWT")
	                       .set_key_id("target-kid")
	                       .set_issuer("https://idp.test")
	                       .set_subject("alice")
	                       .set_audience("api://quack")
	                       .set_issued_at(std::chrono::system_clock::time_point(std::chrono::seconds(1050)))
	                       .set_expires_at(std::chrono::system_clock::time_point(std::chrono::seconds(2000)))
	                       .sign(jwt::algorithm::rs384("", new_key.priv_pem, "", ""));

	VerifyOptions opts = BaseOpts(1050);
	opts.allowed_algorithms = {"RS256", "RS384"};

	const auto res = ValidateToken(token, opts, ctx);
	CHECK(res == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}

TEST_CASE("Validator: 5 candidate keys preserves signature-matching key for expired token",
          "[validator][rotation][prioritize-expired]") {
	const auto k1 = GenerateValidatorKey("target-kid");
	const auto k2 = GenerateValidatorKey("target-kid");
	const auto k3 = GenerateValidatorKey("target-kid");
	const auto k4 = GenerateValidatorKey("target-kid");
	const auto k5 = GenerateValidatorKey("target-kid");

	JwksCache cache(30);
	cache.OnFetchSuccess("target-kid", {k1.jwk}, 1000, kTestJwksUri);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {
	    200, std::string(R"({"keys":[)") + R"({"kid":"target-kid","kty":"RSA","use":"sig","alg":"RS256","n":")" +
	             k1.jwk.n + R"(","e":")" + k1.jwk.e + R"("},)" +
	             R"({"kid":"target-kid","kty":"RSA","use":"sig","alg":"RS256","n":")" + k2.jwk.n + R"(","e":")" +
	             k2.jwk.e + R"("},)" + R"({"kid":"target-kid","kty":"RSA","use":"sig","alg":"RS256","n":")" + k3.jwk.n +
	             R"(","e":")" + k3.jwk.e + R"("},)" +
	             R"({"kid":"target-kid","kty":"RSA","use":"sig","alg":"RS256","n":")" + k4.jwk.n + R"(","e":")" +
	             k4.jwk.e + R"("},)" + R"({"kid":"target-kid","kty":"RSA","use":"sig","alg":"RS256","n":")" + k5.jwk.n +
	             R"(","e":")" + k5.jwk.e + R"("}]})"};

	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Token signed by k5 is expired (exp=900, now=1050)
	const auto expired_token = Sign(k5, 900, 800);
	const auto res = ValidateToken(expired_token, BaseOpts(1050), ctx);

	// Must be recognized as Expired, NOT InvalidSignature (which would happen if k5 was trimmed)
	CHECK(res == VerifyResult::Expired);

	// And k5 is now cached, so a subsequent valid token with k5 passes with 0 HTTP calls
	const auto valid_token = Sign(k5, 2000, 1051);
	CHECK(ValidateToken(valid_token, BaseOpts(1051), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
}
