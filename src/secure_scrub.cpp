#include "secure_scrub.hpp"

#include <openssl/crypto.h>

namespace quack_oauth {

void SecureScrub(std::string &s) {
	if (!s.empty()) {
		// data() on a non-empty std::string returns a writable buffer
		// (since C++17). OPENSSL_cleanse is a write-barrier the compiler
		// can't optimise away.
		OPENSSL_cleanse(s.data(), s.size());
	}
	s.clear();
	s.shrink_to_fit();
}

} // namespace quack_oauth
