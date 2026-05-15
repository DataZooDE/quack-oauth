#include "picojson_helpers.hpp"

#include <sstream>

namespace quack_oauth {

std::string UrlEncode(std::string_view in) {
	std::ostringstream out;
	for (unsigned char c : in) {
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~') {
			out << static_cast<char>(c);
		} else {
			out << '%';
			static constexpr char kHex[] = "0123456789ABCDEF";
			out << kHex[(c >> 4) & 0x0F];
			out << kHex[c & 0x0F];
		}
	}
	return out.str();
}

const std::string *AsString(const picojson::object &obj, const std::string &key) {
	const auto it = obj.find(key);
	if (it == obj.end() || !it->second.is<std::string>()) {
		return nullptr;
	}
	return &it->second.get<std::string>();
}

std::int64_t AsIntFlexible(const picojson::object &obj, const std::string &key) {
	const auto it = obj.find(key);
	if (it == obj.end())
		return 0;
	if (it->second.is<std::int64_t>())
		return it->second.get<std::int64_t>();
	if (it->second.is<double>())
		return static_cast<std::int64_t>(it->second.get<double>());
	if (it->second.is<std::string>()) {
		const auto &s = it->second.get<std::string>();
		if (s.empty())
			return 0;
		try {
			return std::stoll(s);
		} catch (...) {
			return 0;
		}
	}
	return 0;
}

bool AsBoolFlexible(const picojson::object &obj, const std::string &key) {
	const auto it = obj.find(key);
	if (it == obj.end())
		return false;
	if (it->second.is<bool>())
		return it->second.get<bool>();
	if (it->second.is<std::string>()) {
		const auto &s = it->second.get<std::string>();
		return s == "true" || s == "True" || s == "TRUE";
	}
	return false;
}

} // namespace quack_oauth
