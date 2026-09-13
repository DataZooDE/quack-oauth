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
#include "jwt_verify.hpp"
#include "validator.hpp"

using quack_oauth::DecisionCache;
using quack_oauth::IHttpClient;
using quack_oauth::IntrospectContext;
using quack_oauth::Jwk;
using quack_oauth::JwksCache;
using quack_oauth::JwksLookupStatus;
using quack_oauth::Principal;
using quack_oauth::TokeninfoContext;
using quack_oauth::ValidateContext;
using quack_oauth::ValidateToken;
using quack_oauth::ValidateTokenViaIntrospection;
using quack_oauth::ValidateTokenViaTokeninfo;
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

	std::optional<Response> Get(std::string_view url) override {
		++call_count;
		last_url = std::string(url);
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
	cache.OnFetchSuccess(k.jwk, 1700000000);

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
	cache.OnFetchSuccess(old_key.jwk, 1699999900);

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
	cache.OnFetchSuccess(old_key.jwk, 1699999900);

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
	cache.OnFetchSuccess(old_key.jwk, 1699999900);

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
	cache.OnFetchSuccess(old_key.jwk, 1699999900);

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
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk, 1699999900);

	std::string jwks_body =
	    std::string(R"({"keys":[)") + R"({"kid":")" + rotated_key.jwk.kid +
	    R"(","kty":"RSA","use":"sig","alg":"RS256","n":")" + rotated_key.jwk.n + R"(","e":")" + rotated_key.jwk.e +
	    R"("},)" + R"({"kid":"unverified-sibling","kty":"RSA","use":"sig","alg":"RS256","n":"sibling-n","e":"AQAB"})" +
	    R"(]})";

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, std::move(jwks_body)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto rotated_token = Sign(rotated_key, 1700003600, 1700000000);
	CHECK(ValidateToken(rotated_token, BaseOpts(), ctx) == VerifyResult::Ok);

	// The sibling key is ingested additively into the cache (F1, F5).
	CHECK(cache.Lookup("unverified-sibling", 1700000000).status == JwksLookupStatus::Hit);
}

TEST_CASE("Validator: rotated key with claim check failure updates cache and returns true claim error",
          "[validator][rotation][claims]") {
	const auto &old_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(old_key.jwk.kid);
	JwksCache cache(30);
	cache.OnFetchSuccess(old_key.jwk, 1699999900);

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
	const auto lookup = cache.Lookup(old_key.jwk.kid, 1700000000);
	REQUIRE(lookup.status == JwksLookupStatus::Hit);
	CHECK(lookup.jwk->n == rotated_key.jwk.n);
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
	const auto lookup = cache.Lookup(valid_key.jwk.kid, 1700000000);
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
	cache.OnFetchSuccess(valid_key.jwk, 1699999900);

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
	cache.OnFetchSuccess(old_key.jwk, 1699999900);

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
	const auto lookup = cache.Lookup(valid_key.jwk.kid, 1700000000);
	REQUIRE(lookup.status == JwksLookupStatus::Hit);
	CHECK(lookup.jwk->use == "sig");
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
	cache.OnFetchSuccess(malformed_jwk, 1699999900);

	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(valid_key.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(valid_key, 1700003600, 1700000000);
	// Verification must detect the unusable cached key, trigger a refresh, and succeed!
	CHECK(ValidateToken(token, BaseOpts(1700000000), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);
	CHECK(cache.Lookup(valid_key.jwk.kid, 1700000000).jwk->n == valid_key.jwk.n);
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
	CHECK(cache.Lookup(valid_key.jwk.kid, 1700000000).status == JwksLookupStatus::Hit);
}

TEST_CASE("Validator: on_refresh callback receives kid, reason, and token on refresh events",
          "[validator][audit][jwks-refresh]") {
	const auto &initial_key = GetValidatorKey();
	const auto rotated_key = GenerateValidatorKey(initial_key.jwk.kid);
	JwksCache cache(30);
	cache.OnFetchSuccess(initial_key.jwk, 1000);

	struct RefreshCall {
		std::string kid;
		std::string reason;
		std::string token;
	};
	std::vector<RefreshCall> calls;

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks",
	                     [&](const std::string &kid, const std::string &reason, std::string_view token) {
		                     calls.push_back({kid, reason, std::string(token)});
	                     }};

	// 1. Success on rotated key
	http.next_response = IHttpClient::Response {200, JwksWith(rotated_key.jwk)};
	const auto token1 = Sign(rotated_key, 2000, 1030);
	CHECK(ValidateToken(token1, BaseOpts(1030), ctx) == VerifyResult::Ok);
	REQUIRE(calls.size() == 1);
	CHECK(calls[0].kid == initial_key.jwk.kid);
	CHECK(calls[0].reason == "rotated_key_refreshed");
	CHECK(calls[0].token == token1);

	// 2. Throttled within rate-limit window
	calls.clear();
	const auto attacker_key = GenerateValidatorKey(initial_key.jwk.kid);
	const auto token2 = Sign(attacker_key, 2000, 1040); // fails against both cached keys
	CHECK(ValidateToken(token2, BaseOpts(1040), ctx) == VerifyResult::InvalidSignature);
	REQUIRE(calls.size() == 1);
	CHECK(calls[0].reason == "refresh_throttled");

	// 3. Fetch failed (e.g. 500)
	calls.clear();
	http.next_response = IHttpClient::Response {500, "internal error"};
	CHECK(ValidateToken(token2, BaseOpts(1080), ctx) == VerifyResult::InvalidSignature);
	REQUIRE(calls.size() == 1);
	CHECK(calls[0].reason == "refresh_fetch_failed");

	// 4. Parse failed (e.g. invalid json)
	calls.clear();
	http.next_response = IHttpClient::Response {200, "not-json"};
	CHECK(ValidateToken(token2, BaseOpts(1120), ctx) == VerifyResult::InvalidSignature);
	REQUIRE(calls.size() == 1);
	CHECK(calls[0].reason == "refresh_parse_failed");

	// 5. Kid absent in fresh JWKS
	calls.clear();
	Jwk other_key = rotated_key.jwk;
	other_key.kid = "some-other-kid";
	http.next_response = IHttpClient::Response {200, JwksWith(other_key)};
	CHECK(ValidateToken(token2, BaseOpts(1160), ctx) == VerifyResult::InvalidSignature);
	REQUIRE(calls.size() == 1);
	CHECK(calls[0].reason == "refresh_kid_absent");
}

TEST_CASE("Validator: multi-key entry verifies tokens for both keys under same kid without HTTP calls",
          "[validator][multi-key]") {
	const auto k1 = GenerateValidatorKey("common-kid");
	const auto k2 = GenerateValidatorKey("common-kid");
	JwksCache cache(30);
	cache.OnFetchSuccess(k1.jwk, 1000);
	cache.OnFetchSuccess(k2.jwk, 1000);

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
	cache.OnFetchSuccess(key.jwk, 1000);

	std::string emitted_reason;
	FakeHttpClient http;
	http.next_response = IHttpClient::Response {200, JwksWith(key.jwk)};
	ValidateContext ctx {
	    http, cache, "https://idp.test/jwks",
	    [&](const std::string &, const std::string &reason, std::string_view) { emitted_reason = reason; }};

	// Forged token: fails signature
	const auto forged_key = GenerateValidatorKey("k1");
	const auto forged_token = Sign(forged_key, 2000, 1050);

	CHECK(ValidateToken(forged_token, BaseOpts(1050), ctx) == VerifyResult::InvalidSignature);
	CHECK(emitted_reason == "refresh_no_rotation");
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
	cache.OnFetchSuccess(old_key.jwk, 1000);

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
		CHECK(ValidateToken(token, BaseOpts(1000), ctx) == VerifyResult::JwksFetchFailed);
	}
	CHECK(http.call_count <= 1);
}

TEST_CASE("Validator: TryRefreshRotatedKid obeys global fetch budget across distinct cached kids",
          "[validator][budget][f3]") {
	JwksCache cache(30);
	std::vector<TestKey> keys;
	for (int i = 0; i < 5; ++i) {
		keys.push_back(GenerateValidatorKey("kid-" + std::to_string(i)));
		cache.OnFetchSuccess(keys.back().jwk, 1000);
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
	http.next_response = IHttpClient::Response {200, JwksWith(key1.jwk)};
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// t=1000: successful fetch for kid-1
	const auto token1 = Sign(key1, 2000, 1000);
	CHECK(ValidateToken(token1, BaseOpts(1000), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 1);

	// t=1005: IdP publishes kid-2, but client requests kid-2 within 30s window.
	// Global budget blocks fetch.
	http.next_response = IHttpClient::Response {200, JwksWith(key2.jwk)};
	const auto token2 = Sign(key2, 2000, 1005);
	CHECK(ValidateToken(token2, BaseOpts(1005), ctx) == VerifyResult::UnknownKid);
	CHECK(http.call_count == 1); // 0 additional fetches

	// kid-2 must NOT have been negative-cached!
	CHECK(cache.Lookup("kid-2", 1005).status != JwksLookupStatus::RateLimited);

	// t=1035: rate limit window has passed; request for kid-2 now fetches successfully!
	CHECK(ValidateToken(token2, BaseOpts(1035), ctx) == VerifyResult::Ok);
	CHECK(http.call_count == 2);
}

TEST_CASE("Validator: hit path alg/use filter rejects mismatched alg without fallback", "[validator][alg-filter][f5]") {
	JwksCache cache(30);
	auto key = GenerateValidatorKey("kid-alg");
	key.jwk.alg = "RS512"; // Key is pinned to RS512
	cache.OnFetchSuccess(key.jwk, 1000);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	// Token is signed with RS256
	const auto token = Sign(key, 2000, 1000);
	CHECK(ValidateToken(token, BaseOpts(1000), ctx) == VerifyResult::InvalidSignature);
	CHECK(http.call_count == 0); // No refresh attempted
}

TEST_CASE("Validator: sub-2048 RSA key returns UnsupportedKeyType and does not trigger refresh loop",
          "[validator][rsa-size][f7]") {
	JwksCache cache(30);
	const auto sub_key = GenerateValidatorKey("sub-2048-kid", 1024);
	cache.OnFetchSuccess(sub_key.jwk, 1000);

	FakeHttpClient http;
	ValidateContext ctx {http, cache, "https://idp.test/jwks"};

	const auto token = Sign(sub_key, 2000, 1010);
	CHECK(ValidateToken(token, BaseOpts(1010), ctx) == VerifyResult::UnsupportedKeyType);
	CHECK(http.call_count == 0); // Must NOT trigger refresh!

	// Second attempt in same or next window also does not trigger refresh
	CHECK(ValidateToken(token, BaseOpts(1050), ctx) == VerifyResult::UnsupportedKeyType);
	CHECK(http.call_count == 0);
}
