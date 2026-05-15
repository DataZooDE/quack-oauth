#include "action_detect.hpp"

#include <cctype>
#include <string>

namespace quack_oauth {

// Strip leading whitespace + `--` line comments + `/* ... */` block comments.
// Returns the offset of the first "real" character.
static std::size_t SkipNoise(std::string_view s) {
	std::size_t i = 0;
	while (i < s.size()) {
		const char c = s[i];
		if (std::isspace(static_cast<unsigned char>(c))) {
			++i;
			continue;
		}
		if (c == '-' && i + 1 < s.size() && s[i + 1] == '-') {
			// Line comment until newline.
			while (i < s.size() && s[i] != '\n')
				++i;
			continue;
		}
		if (c == '/' && i + 1 < s.size() && s[i + 1] == '*') {
			i += 2;
			while (i + 1 < s.size() && !(s[i] == '*' && s[i + 1] == '/'))
				++i;
			if (i + 1 < s.size())
				i += 2;
			continue;
		}
		break;
	}
	return i;
}

// Extract the first ASCII keyword (uppercased) starting at offset `i`.
static std::string FirstKeyword(std::string_view s, std::size_t i) {
	std::string out;
	while (i < s.size()) {
		const auto c = static_cast<unsigned char>(s[i]);
		if (std::isalpha(c) || c == '_') {
			out.push_back(static_cast<char>(std::toupper(c)));
			++i;
		} else {
			break;
		}
	}
	return out;
}

// Walk the remaining text and return true if any of `keywords` appears as
// a whole-word token. Used to disambiguate `COPY ... TO ...` vs
// `COPY ... FROM ...`.
static bool ContainsKeyword(std::string_view s, std::size_t start, std::initializer_list<const char *> keywords) {
	std::string upper;
	upper.reserve(s.size() - start);
	for (std::size_t i = start; i < s.size(); ++i) {
		const auto c = static_cast<unsigned char>(s[i]);
		upper.push_back(static_cast<char>(std::isalpha(c) ? std::toupper(c) : c));
	}
	for (const char *kw : keywords) {
		// Match whole-word: require non-alnum on both sides.
		std::string needle = kw;
		std::size_t pos = 0;
		while ((pos = upper.find(needle, pos)) != std::string::npos) {
			const bool left_ok = pos == 0 || !std::isalnum(static_cast<unsigned char>(upper[pos - 1]));
			const bool right_ok = pos + needle.size() == upper.size() ||
			                      !std::isalnum(static_cast<unsigned char>(upper[pos + needle.size()]));
			if (left_ok && right_ok)
				return true;
			pos += needle.size();
		}
	}
	return false;
}

Action DetectAction(std::string_view query_string) {
	const auto start = SkipNoise(query_string);
	const auto kw = FirstKeyword(query_string, start);

	if (kw == "ATTACH") {
		return Action::Attach;
	}
	if (kw == "COPY") {
		// `COPY src TO dst` vs `COPY tbl FROM src`. We look at the FIRST
		// occurrence -- both keywords appear in some shapes, but only the
		// directional one matters for authz.
		if (ContainsKeyword(query_string, start + kw.size(), {"TO"})) {
			return Action::CopyTo;
		}
		if (ContainsKeyword(query_string, start + kw.size(), {"FROM"})) {
			return Action::CopyFrom;
		}
		return Action::Scan; // unrecognised COPY shape -- be conservative
	}
	if (kw == "PRAGMA") {
		// Administrative pragmas (start with `quack_`) are admin actions.
		if (ContainsKeyword(query_string, start + kw.size(), {"QUACK_SERVE", "QUACK_STOP", "QUACK_RESTART"})) {
			return Action::ServeAdmin;
		}
		return Action::Scan;
	}
	// SELECT / WITH / SHOW / DESCRIBE / VALUES / TABLE all read.
	// Anything else (UPDATE, INSERT, DELETE, CREATE, DROP, ALTER, etc.)
	// also routes to Scan -- the default policy denies them anyway through
	// the absence of a write-class scope. A future schema extension to the
	// policy table could carve finer-grained CREATE / DROP / INSERT actions.
	return Action::Scan;
}

} // namespace quack_oauth
