#pragma once

#include <string>
#include <string_view>

namespace quack_oauth {

// R-N-4: pure-logic helpers for the plaintext-listener heuristic.
//
// `IsLoopbackHost(host)` returns true if the host part of a listen URI
// resolves to the loopback interface (and therefore is "TLS-safe" in the
// R-N-4 sense -- nobody outside the host can reach it). Recognised:
//   - "127.0.0.0/8" (textbook IPv4 loopback range)
//   - "::1" and "[::1]" (IPv6 loopback)
//   - "localhost" (any ASCII case)
// Explicitly NOT loopback: "0.0.0.0", "::" / "[::]" (bind-to-all-interfaces),
// private LAN IPs (e.g. "192.168.x.x"), DNS names other than localhost, and
// empty input.
bool IsLoopbackHost(std::string_view host);

// Extracts the host portion from a quack listen URI like `quack:host:port`,
// `quack://host:port`, or `quack:host`. Handles IPv6 bracket notation
// (`[::1]`). Returns empty string for unparseable inputs.
std::string HostFromQuackUri(std::string_view uri);

} // namespace quack_oauth
