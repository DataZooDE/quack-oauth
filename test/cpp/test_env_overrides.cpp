#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <string>

#include "env_overrides.hpp"

namespace {

// Cross-platform env setter. POSIX has setenv/unsetenv; MSVC has _putenv_s.
void SetEnv(const char *name, const char *value) {
#ifdef _WIN32
	_putenv_s(name, value ? value : "");
#else
	if (value == nullptr) {
		unsetenv(name);
	} else {
		setenv(name, value, 1);
	}
#endif
}

struct EnvGuard {
	std::string name;
	bool was_set = false;
	std::string prior;
	EnvGuard(const char *n, const char *v) : name(n) {
		if (const char *prev = std::getenv(n); prev != nullptr) {
			was_set = true;
			prior = prev;
		}
		SetEnv(n, v);
	}
	~EnvGuard() {
		SetEnv(name.c_str(), was_set ? prior.c_str() : nullptr);
	}
};

} // namespace

TEST_CASE("EnvString: unset → empty", "[env]") {
	EnvGuard g("QUACK_OAUTH_TEST_UNSET", nullptr);
	CHECK(quack_oauth::EnvString("QUACK_OAUTH_TEST_UNSET").empty());
}

TEST_CASE("EnvString: set → value", "[env]") {
	EnvGuard g("QUACK_OAUTH_TEST_STRING", "hello world");
	CHECK(quack_oauth::EnvString("QUACK_OAUTH_TEST_STRING") == "hello world");
}

TEST_CASE("EnvString: empty value → empty string", "[env]") {
	EnvGuard g("QUACK_OAUTH_TEST_EMPTY", "");
	CHECK(quack_oauth::EnvString("QUACK_OAUTH_TEST_EMPTY").empty());
}

TEST_CASE("EnvBoolOrDefault: unset → fallback", "[env]") {
	EnvGuard g("QUACK_OAUTH_TEST_BOOL_UNSET", nullptr);
	CHECK(quack_oauth::EnvBoolOrDefault("QUACK_OAUTH_TEST_BOOL_UNSET", true) == true);
	CHECK(quack_oauth::EnvBoolOrDefault("QUACK_OAUTH_TEST_BOOL_UNSET", false) == false);
}

TEST_CASE("EnvBoolOrDefault: truthy variants → true", "[env]") {
	for (const auto *v : {"1", "true", "TRUE", "True", "yes", "Yes", "on", "ON"}) {
		EnvGuard g("QUACK_OAUTH_TEST_BOOL_TRUE", v);
		INFO("value = " << v);
		CHECK(quack_oauth::EnvBoolOrDefault("QUACK_OAUTH_TEST_BOOL_TRUE", false) == true);
	}
}

TEST_CASE("EnvBoolOrDefault: falsy variants → false", "[env]") {
	for (const auto *v : {"0", "false", "FALSE", "no", "off", ""}) {
		EnvGuard g("QUACK_OAUTH_TEST_BOOL_FALSE", v);
		INFO("value = " << v);
		// Note: "" goes through the unset path; we pass fallback=true so any
		// non-truthy value (including "") returns the fallback only when truly
		// unset; here we set it to empty so EnvString returns "" → fallback.
		CHECK(quack_oauth::EnvBoolOrDefault("QUACK_OAUTH_TEST_BOOL_FALSE", true) ==
		      (std::string(v).empty() ? true : false));
	}
}

TEST_CASE("EnvIntOrDefault: unset → fallback", "[env]") {
	EnvGuard g("QUACK_OAUTH_TEST_INT_UNSET", nullptr);
	CHECK(quack_oauth::EnvIntOrDefault("QUACK_OAUTH_TEST_INT_UNSET", 42) == 42);
}

TEST_CASE("EnvIntOrDefault: valid int → value", "[env]") {
	EnvGuard g("QUACK_OAUTH_TEST_INT_OK", "120");
	CHECK(quack_oauth::EnvIntOrDefault("QUACK_OAUTH_TEST_INT_OK", 30) == 120);
}

TEST_CASE("EnvIntOrDefault: garbage → fallback", "[env]") {
	for (const auto *v : {"not-a-number", "12abc", "abc12", ""}) {
		EnvGuard g("QUACK_OAUTH_TEST_INT_BAD", v);
		INFO("value = " << v);
		CHECK(quack_oauth::EnvIntOrDefault("QUACK_OAUTH_TEST_INT_BAD", 7) == 7);
	}
}

TEST_CASE("EnvIntOrDefault: negative + zero handled", "[env]") {
	{
		EnvGuard g("QUACK_OAUTH_TEST_INT_NEG", "-15");
		CHECK(quack_oauth::EnvIntOrDefault("QUACK_OAUTH_TEST_INT_NEG", 99) == -15);
	}
	{
		EnvGuard g("QUACK_OAUTH_TEST_INT_ZERO", "0");
		CHECK(quack_oauth::EnvIntOrDefault("QUACK_OAUTH_TEST_INT_ZERO", 99) == 0);
	}
}
