#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <jwt-cpp/traits/kazuho-picojson/defaults.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "jwks_cache.hpp"
#include "jwt_verify.hpp"

using quack_oauth::Jwk;
using quack_oauth::JwkRsaToPem;
using quack_oauth::VerifyJwt;
using quack_oauth::VerifyOptions;
using quack_oauth::VerifyResult;

namespace {

using TraitsT = jwt::traits::kazuho_picojson;

std::string B64UrlNoPad(const std::string &raw) {
	auto s = jwt::base::encode<jwt::alphabet::base64url>(raw);
	// jwt-cpp's base64url alphabet uses "%3d" (URL-percent-encoded `=`) as
	// its padding marker -- it's designed for URL-encoded query strings.
	// JWS/JWK use unpadded base64url, so strip both "%3d" and plain "=".
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

// Generates a fresh RSA-2048 keypair once per process and reuses it across
// tests. Determinism within a run is sufficient -- we are testing our parser
// against jwt-cpp's signer, not against a fixed wire format.
const TestKey &GetTestKey() {
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
		jwk.kid = "test-key-1";
		jwk.kty = "RSA";
		jwk.alg = "RS256";
		jwk.use = "sig";
		jwk.n = bn_to_b64url(n_bn);
		jwk.e = bn_to_b64url(e_bn);

		BN_free(n_bn);
		BN_free(e_bn);
		EVP_PKEY_free(pkey);

		return TestKey{std::move(priv_pem), std::move(jwk)};
	}();
	return k;
}

std::string SignRs256(const TestKey &k, std::int64_t exp_s, std::int64_t iat_s,
                      const std::string &iss, const std::string &aud,
                      std::int64_t nbf_s = 0) {
	auto builder = jwt::create<TraitsT>()
	                   .set_type("JWT")
	                   .set_key_id(k.jwk.kid)
	                   .set_issuer(iss)
	                   .set_subject("alice")
	                   .set_audience(aud)
	                   .set_issued_at(std::chrono::system_clock::time_point(
	                       std::chrono::seconds(iat_s)))
	                   .set_expires_at(std::chrono::system_clock::time_point(
	                       std::chrono::seconds(exp_s)));
	if (nbf_s > 0) {
		builder.set_not_before(std::chrono::system_clock::time_point(
		    std::chrono::seconds(nbf_s)));
	}
	return builder.sign(jwt::algorithm::rs256("", k.priv_pem, "", ""));
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

} // namespace

TEST_CASE("VerifyJwt: happy path on a freshly-signed RS256 token",
          "[jwt][verify]") {
	const auto &k = GetTestKey();
	const auto token = SignRs256(k, 1700003600, 1700000000, "https://idp.test",
	                             "api://quack");
	CHECK(VerifyJwt(token, k.jwk, BaseOpts()) == VerifyResult::Ok);
}

TEST_CASE("VerifyJwt: expired token is rejected", "[jwt][verify][exp]") {
	const auto &k = GetTestKey();
	const auto token = SignRs256(k, 1699000000, 1698990000, "https://idp.test",
	                             "api://quack");
	CHECK(VerifyJwt(token, k.jwk, BaseOpts(1700000000)) == VerifyResult::Expired);
}

TEST_CASE("VerifyJwt: clock skew gives a token leeway past exp",
          "[jwt][verify][exp]") {
	const auto &k = GetTestKey();
	// Token exp = now - 30s; clock skew = 60s -> still Ok.
	const auto token = SignRs256(k, 1699999970, 1699996400, "https://idp.test",
	                             "api://quack");
	CHECK(VerifyJwt(token, k.jwk, BaseOpts(1700000000)) == VerifyResult::Ok);
}

TEST_CASE("VerifyJwt: not-yet-valid token is rejected", "[jwt][verify][nbf]") {
	const auto &k = GetTestKey();
	const auto token = SignRs256(k, 1700003600, 1700000000, "https://idp.test",
	                             "api://quack", /*nbf*/ 1700000200);
	CHECK(VerifyJwt(token, k.jwk, BaseOpts(1700000000)) ==
	      VerifyResult::NotYetValid);
}

TEST_CASE("VerifyJwt: wrong issuer", "[jwt][verify][iss]") {
	const auto &k = GetTestKey();
	const auto token = SignRs256(k, 1700003600, 1700000000, "https://other.idp",
	                             "api://quack");
	CHECK(VerifyJwt(token, k.jwk, BaseOpts()) == VerifyResult::WrongIssuer);
}

TEST_CASE("VerifyJwt: wrong audience", "[jwt][verify][aud]") {
	const auto &k = GetTestKey();
	const auto token = SignRs256(k, 1700003600, 1700000000, "https://idp.test",
	                             "api://other");
	CHECK(VerifyJwt(token, k.jwk, BaseOpts()) == VerifyResult::WrongAudience);
}

TEST_CASE("VerifyJwt: invalid signature is rejected", "[jwt][verify][sig]") {
	const auto &k = GetTestKey();
	auto token = SignRs256(k, 1700003600, 1700000000, "https://idp.test",
	                       "api://quack");
	// Mangle a *middle* character of the signature segment -- flipping the
	// last char only modifies base64url's trailing padding bits, leaving
	// the actual signature bytes unchanged for unpadded RSA-2048 signatures.
	const auto last_dot = token.rfind('.');
	REQUIRE(last_dot != std::string::npos);
	REQUIRE(last_dot + 32 < token.size());
	for (std::size_t i = last_dot + 16; i < last_dot + 24; ++i) {
		token[i] = (token[i] == 'A') ? 'B' : 'A';
	}
	CHECK(VerifyJwt(token, k.jwk, BaseOpts()) == VerifyResult::InvalidSignature);
}

TEST_CASE("VerifyJwt: alg=none is rejected per R-S-3",
          "[jwt][verify][alg]") {
	// Manually built. Header: {"alg":"none","typ":"JWT","kid":"test-key-1"}.
	// Payload: {"iss":"https://idp.test","aud":"api://quack","exp":1700003600}.
	const std::string token =
	    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoidGVzdC1rZXktMSJ9."
	    "eyJpc3MiOiJodHRwczovL2lkcC50ZXN0IiwiYXVkIjoiYXBpOi8vcXVhY2siLCJleHAiOjE3MDAwMDM2MDB9."
	    "";
	const auto &k = GetTestKey();
	CHECK(VerifyJwt(token, k.jwk, BaseOpts()) ==
	      VerifyResult::DisallowedAlgorithm);
}

TEST_CASE("VerifyJwt: HS256 (symmetric) is rejected per R-S-3",
          "[jwt][verify][alg]") {
	const auto token = jwt::create<TraitsT>()
	                       .set_type("JWT")
	                       .set_key_id("test-key-1")
	                       .set_issuer("https://idp.test")
	                       .set_audience("api://quack")
	                       .set_expires_at(std::chrono::system_clock::time_point(
	                           std::chrono::seconds(1700003600)))
	                       .sign(jwt::algorithm::hs256{"shared-secret"});
	const auto &k = GetTestKey();
	CHECK(VerifyJwt(token, k.jwk, BaseOpts()) ==
	      VerifyResult::DisallowedAlgorithm);
}

TEST_CASE("VerifyJwt: malformed token", "[jwt][verify][error]") {
	const auto &k = GetTestKey();
	CHECK(VerifyJwt("", k.jwk, BaseOpts()) == VerifyResult::Malformed);
	CHECK(VerifyJwt("not-a-jwt", k.jwk, BaseOpts()) == VerifyResult::Malformed);
}

TEST_CASE("VerifyJwt: unsupported key type", "[jwt][verify][key]") {
	const auto &k = GetTestKey();
	const auto token = SignRs256(k, 1700003600, 1700000000, "https://idp.test",
	                             "api://quack");
	Jwk ec = k.jwk;
	ec.kty = "EC"; // S-7a only supports RSA
	CHECK(VerifyJwt(token, ec, BaseOpts()) == VerifyResult::UnsupportedKeyType);
}

TEST_CASE("JwkRsaToPem: known key roundtrips to a PEM SubjectPublicKeyInfo",
          "[jwk][pem]") {
	const auto &k = GetTestKey();
	const auto pem = JwkRsaToPem(k.jwk);
	REQUIRE(pem.has_value());
	CHECK(pem->find("BEGIN PUBLIC KEY") != std::string::npos);
	CHECK(pem->find("END PUBLIC KEY") != std::string::npos);
}

TEST_CASE("JwkRsaToPem: missing n or e returns nullopt", "[jwk][pem][error]") {
	Jwk j;
	j.kid = "x";
	j.kty = "RSA";
	CHECK_FALSE(JwkRsaToPem(j).has_value());
}
