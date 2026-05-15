#include <catch2/catch_test_macros.hpp>

#include "plaintext_guard.hpp"

using quack_oauth::IsLoopbackHost;
using quack_oauth::HostFromQuackUri;

TEST_CASE("IsLoopbackHost: textbook loopback names", "[plaintext-guard]") {
	CHECK(IsLoopbackHost("127.0.0.1"));
	CHECK(IsLoopbackHost("localhost"));
	CHECK(IsLoopbackHost("LOCALHOST"));
	CHECK(IsLoopbackHost("::1"));
	CHECK(IsLoopbackHost("[::1]"));
}

TEST_CASE("IsLoopbackHost: 127.0.0.0/8 (all 127.x are loopback)", "[plaintext-guard]") {
	CHECK(IsLoopbackHost("127.0.0.2"));
	CHECK(IsLoopbackHost("127.10.20.30"));
	CHECK(IsLoopbackHost("127.255.255.255"));
}

TEST_CASE("IsLoopbackHost: public-bound is NOT loopback", "[plaintext-guard]") {
	// 0.0.0.0 binds to all interfaces -- public surface, NOT loopback.
	CHECK_FALSE(IsLoopbackHost("0.0.0.0"));
	CHECK_FALSE(IsLoopbackHost("::"));
	CHECK_FALSE(IsLoopbackHost("[::]"));
	// Real public IPs.
	CHECK_FALSE(IsLoopbackHost("1.2.3.4"));
	CHECK_FALSE(IsLoopbackHost("8.8.8.8"));
	CHECK_FALSE(IsLoopbackHost("192.168.1.1")); // private LAN -- also not loopback
	// DNS names.
	CHECK_FALSE(IsLoopbackHost("example.com"));
	CHECK_FALSE(IsLoopbackHost("rs.internal.corp"));
	// Empty / blank.
	CHECK_FALSE(IsLoopbackHost(""));
}

TEST_CASE("HostFromQuackUri: standard quack:host:port", "[plaintext-guard]") {
	CHECK(HostFromQuackUri("quack:127.0.0.1:9494") == "127.0.0.1");
	CHECK(HostFromQuackUri("quack:localhost:9494") == "localhost");
	CHECK(HostFromQuackUri("quack:0.0.0.0:9494") == "0.0.0.0");
	CHECK(HostFromQuackUri("quack:rs.example.com:443") == "rs.example.com");
}

TEST_CASE("HostFromQuackUri: optional port", "[plaintext-guard]") {
	CHECK(HostFromQuackUri("quack:127.0.0.1") == "127.0.0.1");
	CHECK(HostFromQuackUri("quack:example.com") == "example.com");
}

TEST_CASE("HostFromQuackUri: IPv6 bracket form", "[plaintext-guard]") {
	CHECK(HostFromQuackUri("quack:[::1]:9494") == "[::1]");
	CHECK(HostFromQuackUri("quack:[2001:db8::1]:9494") == "[2001:db8::1]");
}

TEST_CASE("HostFromQuackUri: tolerates quack:// variant", "[plaintext-guard]") {
	CHECK(HostFromQuackUri("quack://127.0.0.1:9494") == "127.0.0.1");
	CHECK(HostFromQuackUri("quack://localhost") == "localhost");
}

TEST_CASE("HostFromQuackUri: malformed → empty", "[plaintext-guard]") {
	CHECK(HostFromQuackUri("").empty());
	CHECK(HostFromQuackUri("not-a-uri").empty());
	CHECK(HostFromQuackUri("http://x.example/y").empty()); // wrong scheme
	CHECK(HostFromQuackUri("quack:").empty());             // no host
}
