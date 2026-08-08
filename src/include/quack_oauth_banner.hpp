#pragma once

#include "datazoo_banner_duckdb.hpp"

// Shared identity for the load banner and the issue-link error footer.
//
// External linkage on purpose: DATAZOO_GUARD takes the address as a non-type
// template argument, and every guarded translation unit should annotate errors
// against the same object rather than a per-TU copy.
//
// Defined in quack_oauth_extension.cpp.
extern const datazoo::BannerInfo QUACK_OAUTH_BANNER;
