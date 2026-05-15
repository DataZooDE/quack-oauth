#include "jwt_verify.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <jwt-cpp/traits/kazuho-picojson/defaults.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>

namespace quack_oauth {

namespace {

using TraitsT = jwt::traits::kazuho_picojson;

// ---- OpenSSL RAII helpers --------------------------------------------------

struct BnDelete {
	void operator()(BIGNUM *p) const noexcept { BN_free(p); }
};
using BnPtr = std::unique_ptr<BIGNUM, BnDelete>;

struct EvpPkeyDelete {
	void operator()(EVP_PKEY *p) const noexcept { EVP_PKEY_free(p); }
};
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDelete>;

struct EvpPkeyCtxDelete {
	void operator()(EVP_PKEY_CTX *p) const noexcept { EVP_PKEY_CTX_free(p); }
};
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDelete>;

struct ParamBldDelete {
	void operator()(OSSL_PARAM_BLD *p) const noexcept { OSSL_PARAM_BLD_free(p); }
};
using ParamBldPtr = std::unique_ptr<OSSL_PARAM_BLD, ParamBldDelete>;

struct ParamDelete {
	void operator()(OSSL_PARAM *p) const noexcept { OSSL_PARAM_free(p); }
};
using ParamPtr = std::unique_ptr<OSSL_PARAM, ParamDelete>;

struct BioDelete {
	void operator()(BIO *p) const noexcept { BIO_free(p); }
};
using BioPtr = std::unique_ptr<BIO, BioDelete>;

// ---- Base64URL -------------------------------------------------------------
//
// jwt-cpp ships a base64url alphabet but its `fill()` returns `"%3d"`
// (URL-percent-encoded `=`) -- it's designed for URL-encoded query strings,
// not the unpadded base64url that JWS/JWK use. So we roll our own decoder
// over standard base64url: alphabet A-Z, a-z, 0-9, -, _; no padding; `=`
// trailing chars (if any) are tolerated and skipped.

std::optional<std::string> Base64UrlDecode(const std::string &in) {
	if (in.empty()) {
		return std::nullopt;
	}
	auto value_of = [](unsigned char c) -> int {
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= 'a' && c <= 'z') return c - 'a' + 26;
		if (c >= '0' && c <= '9') return c - '0' + 52;
		if (c == '-') return 62;
		if (c == '_') return 63;
		return -1;
	};
	std::string out;
	out.reserve(in.size() * 3 / 4 + 3);
	unsigned int buffer = 0;
	int bits = 0;
	for (unsigned char c : in) {
		if (c == '=') {
			break;
		}
		const int v = value_of(c);
		if (v < 0) {
			return std::nullopt;
		}
		buffer = (buffer << 6) | static_cast<unsigned int>(v);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
		}
	}
	return out;
}

// ---- JWK -> PEM ------------------------------------------------------------

std::optional<std::string> RsaPublicKeyToPem(const std::vector<unsigned char> &n_bin,
                                            const std::vector<unsigned char> &e_bin) {
	BnPtr n_bn(BN_bin2bn(n_bin.data(), static_cast<int>(n_bin.size()), nullptr));
	BnPtr e_bn(BN_bin2bn(e_bin.data(), static_cast<int>(e_bin.size()), nullptr));
	if (!n_bn || !e_bn) {
		return std::nullopt;
	}

	ParamBldPtr bld(OSSL_PARAM_BLD_new());
	if (!bld || !OSSL_PARAM_BLD_push_BN(bld.get(), "n", n_bn.get()) ||
	    !OSSL_PARAM_BLD_push_BN(bld.get(), "e", e_bn.get())) {
		return std::nullopt;
	}
	ParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));
	if (!params) {
		return std::nullopt;
	}

	EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
	if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
		return std::nullopt;
	}
	EVP_PKEY *raw = nullptr;
	if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
		return std::nullopt;
	}
	EvpPkeyPtr pkey(raw);

	BioPtr bio(BIO_new(BIO_s_mem()));
	if (!bio || PEM_write_bio_PUBKEY(bio.get(), pkey.get()) == 0) {
		return std::nullopt;
	}
	char *pem_data = nullptr;
	const long pem_len = BIO_get_mem_data(bio.get(), &pem_data);
	if (pem_len <= 0 || pem_data == nullptr) {
		return std::nullopt;
	}
	return std::string(pem_data, static_cast<std::size_t>(pem_len));
}

// ---- Algorithm gating ------------------------------------------------------

bool StartsWith(const std::string &s, const std::string &prefix) {
	return s.size() >= prefix.size() &&
	       std::equal(prefix.begin(), prefix.end(), s.begin());
}

bool IsForbiddenAlgorithm(const std::string &alg) {
	// R-S-3: `none` and symmetric (HS*) are forbidden regardless of allowlist.
	return alg.empty() || alg == "none" || StartsWith(alg, "HS");
}

const std::vector<std::string> &DefaultAllowedAlgorithms() {
	static const std::vector<std::string> kDefault = {"RS256", "RS384", "RS512"};
	return kDefault;
}

bool IsAllowed(const std::string &alg, const std::vector<std::string> &whitelist) {
	const auto &use = whitelist.empty() ? DefaultAllowedAlgorithms() : whitelist;
	return std::find(use.begin(), use.end(), alg) != use.end();
}

// ---- Clock & verifier wiring ----------------------------------------------

struct FixedClock {
	std::chrono::system_clock::time_point fixed;
	std::chrono::system_clock::time_point now() const { return fixed; }
};

VerifyResult MapVerificationError(const std::error_code &ec) {
	using E = jwt::error::token_verification_error;
	switch (static_cast<E>(ec.value())) {
	case E::token_expired:
		return VerifyResult::Expired;
	case E::audience_missmatch:
		return VerifyResult::WrongAudience;
	case E::wrong_algorithm:
		return VerifyResult::DisallowedAlgorithm;
	case E::claim_value_missmatch:
	case E::claim_type_missmatch:
	case E::missing_claim:
		// Configured-claim mismatches surface here. The only configured
		// non-time, non-audience claim is `iss` -- so if we land in this
		// branch, treat it as a wrong-issuer.
		return VerifyResult::WrongIssuer;
	default:
		return VerifyResult::InvalidSignature;
	}
}

std::int64_t ToUnixSeconds(const std::chrono::system_clock::time_point &tp) {
	return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch())
	    .count();
}

VerifyResult VerifyWithVerifier(const jwt::decoded_jwt<TraitsT> &decoded,
                                const std::string &pem, const std::string &alg,
                                const VerifyOptions &opts) {
	FixedClock clock{std::chrono::system_clock::time_point(
	    std::chrono::seconds(opts.now_s))};
	auto verifier = jwt::verify<FixedClock, TraitsT>(clock);

	if (alg == "RS256") {
		verifier.allow_algorithm(jwt::algorithm::rs256(pem, "", "", ""));
	} else if (alg == "RS384") {
		verifier.allow_algorithm(jwt::algorithm::rs384(pem, "", "", ""));
	} else if (alg == "RS512") {
		verifier.allow_algorithm(jwt::algorithm::rs512(pem, "", "", ""));
	} else {
		// Pre-checked, but defensive.
		return VerifyResult::DisallowedAlgorithm;
	}

	if (!opts.expected_issuer.empty()) {
		verifier.with_issuer(opts.expected_issuer);
	}
	if (!opts.expected_audience.empty()) {
		verifier.with_audience(opts.expected_audience);
	}
	verifier.leeway(static_cast<std::size_t>(opts.clock_skew_s));

	std::error_code ec;
	verifier.verify(decoded, ec);
	if (!ec) {
		return VerifyResult::Ok;
	}

	// jwt-cpp uses two distinct error_categories: signature_verification_error
	// (raw RSA/ECDSA failures) and token_verification_error (claim checks).
	// Both encode their values as ints, so we MUST dispatch on category --
	// `static_cast<token_verification_error>(ec.value())` for a signature
	// failure can collide with `token_expired` numerically.
	if (ec.category() == jwt::error::signature_verification_error_category()) {
		return VerifyResult::InvalidSignature;
	}

	// jwt-cpp 0.7.x maps every time-based failure (exp-past, nbf-future,
	// iat-future) to the same `token_expired` error code. Disambiguate
	// by re-examining the relevant claims against the injected clock.
	using E = jwt::error::token_verification_error;
	if (static_cast<E>(ec.value()) == E::token_expired) {
		if (decoded.has_not_before()) {
			const auto nbf = ToUnixSeconds(decoded.get_not_before());
			if (opts.now_s + opts.clock_skew_s < nbf) {
				return VerifyResult::NotYetValid;
			}
		}
		return VerifyResult::Expired;
	}
	return MapVerificationError(ec);
}

} // namespace

std::optional<std::string> JwkRsaToPem(const Jwk &jwk) {
	if (jwk.n.empty() || jwk.e.empty()) {
		return std::nullopt;
	}
	const auto n_decoded = Base64UrlDecode(jwk.n);
	const auto e_decoded = Base64UrlDecode(jwk.e);
	if (!n_decoded || !e_decoded) {
		return std::nullopt;
	}
	const std::vector<unsigned char> n_bin(n_decoded->begin(), n_decoded->end());
	const std::vector<unsigned char> e_bin(e_decoded->begin(), e_decoded->end());
	return RsaPublicKeyToPem(n_bin, e_bin);
}

VerifyResult VerifyJwt(std::string_view token, const Jwk &jwk,
                       const VerifyOptions &opts) {
	if (token.empty()) {
		return VerifyResult::Malformed;
	}

	std::optional<jwt::decoded_jwt<TraitsT>> decoded;
	try {
		decoded.emplace(jwt::decode<TraitsT>(std::string(token)));
	} catch (...) {
		return VerifyResult::Malformed;
	}

	const std::string alg =
	    decoded->has_algorithm() ? decoded->get_algorithm() : "";
	if (IsForbiddenAlgorithm(alg) || !IsAllowed(alg, opts.allowed_algorithms)) {
		return VerifyResult::DisallowedAlgorithm;
	}

	if (jwk.kty != "RSA") {
		return VerifyResult::UnsupportedKeyType;
	}

	const auto pem = JwkRsaToPem(jwk);
	if (!pem) {
		// Malformed JWK contents.
		return VerifyResult::Malformed;
	}

	return VerifyWithVerifier(*decoded, *pem, alg, opts);
}

} // namespace quack_oauth
