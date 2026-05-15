#include "tracing.hpp"

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>

#include <openssl/evp.h>

namespace quack_oauth {

namespace {

constexpr std::size_t kRedactedPrefixHexChars = 8;
constexpr std::size_t kRedactedPrefixBytes = kRedactedPrefixHexChars / 2;

void HexEncode(const std::uint8_t *bytes, std::size_t n, std::string &out) {
	static constexpr char kHex[] = "0123456789abcdef";
	out.resize(n * 2);
	for (std::size_t i = 0; i < n; ++i) {
		out[2 * i] = kHex[(bytes[i] >> 4) & 0x0F];
		out[2 * i + 1] = kHex[bytes[i] & 0x0F];
	}
}

bool EqualsAsciiCi(std::string_view a, std::string_view b) {
	if (a.size() != b.size()) {
		return false;
	}
	for (std::size_t i = 0; i < a.size(); ++i) {
		const auto ca = static_cast<unsigned char>(a[i]);
		const auto cb = static_cast<unsigned char>(b[i]);
		if (std::tolower(ca) != std::tolower(cb)) {
			return false;
		}
	}
	return true;
}

} // namespace

std::string RedactSensitive(std::string_view value) {
	if (value.empty()) {
		return {};
	}

	std::array<std::uint8_t, EVP_MAX_MD_SIZE> digest{};
	unsigned int digest_len = 0;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == nullptr) {
		return {};
	}

	std::string out;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
	    EVP_DigestUpdate(ctx, value.data(), value.size()) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) == 1 &&
	    digest_len >= kRedactedPrefixBytes) {
		HexEncode(digest.data(), kRedactedPrefixBytes, out);
	}
	EVP_MD_CTX_free(ctx);
	return out;
}

bool IsSensitiveField(std::string_view field_name) {
	// Keep this list in sync with docs/IMPLEMENTATION.md section 5.
	static constexpr std::string_view kSensitive[] = {
	    "token",  "access_token", "refresh_token", "id_token",
	    "client_secret", "password", "code",
	};
	for (const auto &candidate : kSensitive) {
		if (EqualsAsciiCi(field_name, candidate)) {
			return true;
		}
	}
	return false;
}

} // namespace quack_oauth
